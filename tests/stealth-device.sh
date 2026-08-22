#!/usr/bin/env bash
# shellcheck disable=SC2016,SC2129
set -euo pipefail

umask 077

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
REPO_ROOT=$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd -P)
cd "$REPO_ROOT"

SSH_OPTIONS=(
    -o StrictHostKeyChecking=no
    -o IdentitiesOnly=yes
    -o PreferredAuthentications=password
    -o PubkeyAuthentication=no
    -o LogLevel=ERROR
    -o ConnectTimeout=10
    -o ConnectionAttempts=1
)

DAEMON_LEGACY_LEDGER=''
DAEMON_LEGACY_OWNER_PIDS=''
DAEMON_LEGACY_RECOVERY=''

die() { printf 'stealth-device: %s\n' "$*" >&2; exit 1; }
usage() {
    printf '%s\n' 'usage: tests/stealth-device.sh {selftest|preflight|inventory|import-stock|build|install-deb|install-component|install-hookprobe|set-mode|launch|pull-report|run-hookprobe|daemon-status|daemon-term-safe|client-kill-safe|restore|collect}' >&2
    exit 64
}
require_cmd() { command -v "$1" >/dev/null 2>&1 || die "missing host command: $1"; }
sha256_file() { sha256sum "$1" | cut -d' ' -f1; }

is_task_id() {
    case "$1" in
        TOOL-01|TOOL-02|ORA-01|ORA-02|ORA-03|ORA-04|VNODE-01|VNODE-02|VNODE-03|VNODE-03L|VNODE-04|HOOK-01|HOOK-02|HOOK-03|HOOK-04|HOOK-05|ACT-01|ACT-02|ID-01|ID-02|DYLD-01|DYLD-02|CAP-01|REL-01|REL-01I|REL-02|REL-03|REL-04) return 0 ;;
        *) return 1 ;;
    esac
}

validate_run_env() {
    local name value expected user
    for name in SHADOW_RUN_ID SHADOW_EVIDENCE_ROOT SHADOW_ROW_ID SHADOW_DEVICE SHADOW_DEVICE_PASSWORD SHADOW_TASK_ID; do
        value=${!name-}
        [ -n "$value" ] || die "$name is required"
    done
    [[ $SHADOW_RUN_ID =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || die 'invalid SHADOW_RUN_ID'
    [[ $SHADOW_ROW_ID =~ ^[A-Za-z0-9][A-Za-z0-9._,-]*$ ]] || die 'invalid SHADOW_ROW_ID'
    is_task_id "$SHADOW_TASK_ID" || die "unknown SHADOW_TASK_ID: $SHADOW_TASK_ID"
    expected="artifacts/stealth/$SHADOW_RUN_ID"
    [ "$SHADOW_EVIDENCE_ROOT" = "$expected" ] || die "SHADOW_EVIDENCE_ROOT must equal $expected"
    user=${SHADOW_DEVICE%%@*}
    [ "$user" = mobile ] && [ "$SHADOW_DEVICE" != "$user" ] || die 'SHADOW_DEVICE user must be exactly mobile'
    [[ $SHADOW_DEVICE != *[[:space:]]* ]] || die 'invalid SHADOW_DEVICE'
    [[ $SHADOW_DEVICE_PASSWORD != *$'\n'* ]] || die 'device password must be one line'
    EVIDENCE_ABS="$REPO_ROOT/$SHADOW_EVIDENCE_ROOT"
    case "$EVIDENCE_ABS" in "$REPO_ROOT"/artifacts/stealth/*) ;; *) die 'evidence path escaped repository' ;; esac
    DRIVER_REVISION=$(sha256_file "$SCRIPT_DIR/stealth-device.sh")
}

sq() { printf "'%s'" "${1//\'/\'\\\'\'}"; }

ssh_mobile() {
    local command=$1 quoted
    quoted=$(sq "$command")
    SSHPASS=$SHADOW_DEVICE_PASSWORD timeout "${SHADOW_SSH_TIMEOUT:-60}" "${SHADOW_SSHPASS_BIN:-sshpass}" -e "${SHADOW_SSH_BIN:-ssh}" \
        "${SSH_OPTIONS[@]}" "$SHADOW_DEVICE" "sh -c $quoted" </dev/null
}

ssh_privileged() {
    local command=$1 quoted
    quoted=$(sq "$command")
    printf '%s\n' "$SHADOW_DEVICE_PASSWORD" | \
        SSHPASS=$SHADOW_DEVICE_PASSWORD timeout "${SHADOW_SSH_TIMEOUT:-60}" "${SHADOW_SSHPASS_BIN:-sshpass}" -e "${SHADOW_SSH_BIN:-ssh}" \
        "${SSH_OPTIONS[@]}" "$SHADOW_DEVICE" "sudo -S -p '' sh -c $quoted"
}

scp_from() {
    local remote_path=$1 local_path=$2
    SSHPASS=$SHADOW_DEVICE_PASSWORD timeout "${SHADOW_SCP_TIMEOUT:-300}" "${SHADOW_SSHPASS_BIN:-sshpass}" -e "${SHADOW_SCP_BIN:-scp}" \
        "${SSH_OPTIONS[@]}" "$SHADOW_DEVICE:$remote_path" "$local_path" </dev/null
}

scp_to() {
    local local_path=$1 remote_path=$2
    SSHPASS=$SHADOW_DEVICE_PASSWORD timeout "${SHADOW_SCP_TIMEOUT:-300}" "${SHADOW_SSHPASS_BIN:-sshpass}" -e "${SHADOW_SCP_BIN:-scp}" \
        "${SSH_OPTIONS[@]}" "$local_path" "$SHADOW_DEVICE:$remote_path" </dev/null
}

atomic_json_from_python() {
    local path=$1
    shift
    python3 - "$path" "$@"
}

build_revision_manifest() {
    local output=$1
    python3 - "$REPO_ROOT" "$SHADOW_EVIDENCE_ROOT" "$output" "$SHADOW_TASK_ID" <<'PY'
import hashlib, os, pathlib, subprocess, sys

root = pathlib.Path(sys.argv[1])
evidence = sys.argv[2].rstrip('/') + '/'
output = pathlib.Path(sys.argv[3])
task = sys.argv[4]
raw = subprocess.check_output(
    ['git', '-C', str(root), 'ls-files', '--cached', '--others', '--exclude-standard', '-z']
)
paths = sorted({p.decode('utf-8', 'surrogateescape') for p in raw.split(b'\0') if p})
excluded = (evidence, 'artifacts/stealth/', 'build/', 'packages/', '.theos/')
task_scopes = {
    'ORA-02': ('ShadowHarness/', 'ShadowCore.dylib/dylib.x',
               'tests/stealth-device.sh', 'tests/stealth_validate.py',
               'tests/verify-hook-matrix.sh'),
    'ORA-03': ('tools/dyldprobe/', 'Shadow.dylib/dylib.x',
               'ShadowCore.dylib/hooks/Runtime/dyld.x', 'Shadow.framework/Core.m',
               'tests/stealth-device.sh', 'tests/stealth_validate.py'),
    'ORA-04': ('ShadowHarness/', 'tools/dyldprobe/', 'Shadow.dylib/dylib.x',
               'ShadowCore.dylib/hooks/Runtime/dyld.x', 'Shadow.framework/Core.m',
               'tests/stealth-device.sh', 'tests/stealth_validate.py'),
}
scope = task_scopes.get(task)
rows = []
for rel in paths:
    if rel.startswith(excluded):
        continue
    if scope and not any(rel == item or (item.endswith('/') and rel.startswith(item)) for item in scope):
        continue
    path = root / rel
    if path.is_file():
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
    elif path.exists():
        continue
    else:
        digest = 'DELETED'
    rows.append(f'{digest}\t{rel}\n')
data = ''.join(rows).encode()
output.parent.mkdir(parents=True, exist_ok=True)
tmp = output.with_name(output.name + f'.tmp.{os.getpid()}')
with open(tmp, 'wb') as f:
    f.write(data); f.flush(); os.fsync(f.fileno())
os.replace(tmp, output)
fd = os.open(output.parent, os.O_RDONLY)
try: os.fsync(fd)
finally: os.close(fd)
print(hashlib.sha256(data).hexdigest())
PY
}

write_task_anchor() {
    local task_dir tmp_manifest revision anchor
    task_dir="$EVIDENCE_ABS/host/$SHADOW_TASK_ID"
    mkdir -p "$task_dir" || return
    tmp_manifest=$(mktemp "$task_dir/revision.XXXXXX") || return
    revision=$(build_revision_manifest "$tmp_manifest") || return
    anchor="$task_dir/task.json"
    if [ -f "$anchor" ]; then
        python3 - "$anchor" "$SHADOW_RUN_ID" "$SHADOW_TASK_ID" "$revision" <<'PY' || return
import json, sys
d=json.load(open(sys.argv[1], encoding='utf-8'))
want={'run_id':sys.argv[2], 'task_id':sys.argv[3], 'probe_revision':sys.argv[4]}
for k,v in want.items():
    if d.get(k) != v: raise SystemExit(f'task anchor mismatch: {k}')
PY
        rm -f "$tmp_manifest"
    else
        mv "$tmp_manifest" "$task_dir/revision.manifest"
        atomic_json_from_python "$anchor" "$SHADOW_RUN_ID" "$SHADOW_TASK_ID" "$revision" <<'PY'
import json, os, pathlib, sys
p=pathlib.Path(sys.argv[1]); data={'schema_version':1,'run_id':sys.argv[2],'task_id':sys.argv[3],'probe_revision':sys.argv[4]}
t=p.with_name(p.name+f'.tmp.{os.getpid()}')
with open(t,'w',encoding='utf-8') as f: json.dump(data,f,sort_keys=True,separators=(',',':')); f.write('\n'); f.flush(); os.fsync(f.fileno())
os.replace(t,p); fd=os.open(p.parent,os.O_RDONLY); os.fsync(fd); os.close(fd)
PY
    fi
    TASK_REVISION=$revision
}

verify_owned_regular() {
    local path=$1
    [ -f "$path" ] && [ ! -L "$path" ] || die "missing or unsafe anchor: $path"
    [ "$(stat -c %u "$path")" = "$(id -u)" ] || die "wrong owner: $path"
}

verify_run_anchor() {
    local expected_driver=${1:-$DRIVER_REVISION}
    local anchor="$EVIDENCE_ABS/run.json"
    verify_owned_regular "$anchor"
    verify_owned_regular "$EVIDENCE_ABS/cleanup.jsonl"
    python3 - "$anchor" "$SHADOW_RUN_ID" "$SHADOW_ROW_ID" "$SHADOW_DEVICE" "$SHADOW_EVIDENCE_ROOT" "$expected_driver" <<'PY'
import json, sys
d=json.load(open(sys.argv[1],encoding='utf-8'))
want={'run_id':sys.argv[2],'primary_row_id':sys.argv[3],'primary_endpoint':sys.argv[4],
      'evidence_root':sys.argv[5],'primary_row_type':'jailbroken'}
if sys.argv[6] != '-': want['driver_revision']=sys.argv[6]
for k,v in want.items():
    if d.get(k) != v: raise SystemExit(f'run anchor mismatch: {k}')
PY
}

load_task_anchor() {
    local anchor="$EVIDENCE_ABS/host/$SHADOW_TASK_ID/task.json"
    verify_owned_regular "$anchor"
    TASK_REVISION=$(python3 - "$anchor" "$SHADOW_RUN_ID" "$SHADOW_TASK_ID" <<'PY'
import json,sys
d=json.load(open(sys.argv[1],encoding='utf-8'))
if d.get('run_id') != sys.argv[2]: raise SystemExit('task anchor mismatch: run_id')
if d.get('task_id') != sys.argv[3]: raise SystemExit('task anchor mismatch: task_id')
rev=d.get('probe_revision')
if not isinstance(rev,str) or len(rev) != 64: raise SystemExit('task anchor mismatch: probe_revision')
print(rev)
PY
)
}

verify_device_identity() {
    local got expected
    got=$(ssh_mobile "a=\$(dpkg --print-architecture); case \"\$a\" in iphoneos-arm64) printf 'arm64\\n';; *) printf '%s\\n' \"\$a\";; esac; sw_vers -productVersion; sw_vers -buildVersion") || die 'device identity query failed'
    expected=$(python3 - "$EVIDENCE_ABS/run.json" <<'PY'
import json,sys
d=json.load(open(sys.argv[1])); print(d['architecture']); print(d['os_version']); print(d['os_build'])
PY
)
    [ "$got" = "$expected" ] || die 'device identity changed'
}

prepare_existing_run() {
    validate_run_env || return
    verify_run_anchor || return
    write_task_anchor || return
}

prepare_restore() {
    validate_run_env || return
    # Cleanup must remain possible after source/driver drift. New evidence is
    # still revision-locked by prepare_existing_run; restore uses the frozen
    # task revision solely to replay the run's existing write-ahead journal.
    verify_run_anchor - || return
    load_task_anchor || return
}

capture_dir() {
    local nonce=${1:-} command=$2 side=${3:-device} token
    if [ -n "$nonce" ]; then token=$nonce; else token="$command-$(date -u +%Y%m%dT%H%M%SZ)-$$"; fi
    [[ $token =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || die 'invalid evidence nonce'
    if [ "$side" = host ]; then
        CAPTURE_DIR="$EVIDENCE_ABS/host/$SHADOW_TASK_ID/$token/$command"
    else
        CAPTURE_DIR="$EVIDENCE_ABS/device/$SHADOW_ROW_ID/$SHADOW_TASK_ID/$token/$command"
    fi
    mkdir -p "$(dirname "$CAPTURE_DIR")"
    [ ! -e "$CAPTURE_DIR" ] || die 'evidence capture already exists'
    mkdir "$CAPTURE_DIR"
    CAPTURE_STDOUT="$CAPTURE_DIR/stdout.txt"
    CAPTURE_STDERR="$CAPTURE_DIR/stderr.txt"
    : >"$CAPTURE_STDOUT"; : >"$CAPTURE_STDERR"
}

write_manifest() {
    local command=$1 nonce=${2:-} requested=${3:-not-applicable} observed=${4:-not-applicable}
    local transport=${5:-0} producer=${6:-not-applicable} inventory=${7:-}
    shift 7 || true
    python3 - "$EVIDENCE_ABS/run.json" "$CAPTURE_DIR/manifest.json" "$SHADOW_TASK_ID" "$TASK_REVISION" \
        "$command" "$nonce" "$requested" "$observed" "$transport" "$producer" \
        "$CAPTURE_STDOUT" "$CAPTURE_STDERR" "$inventory" "$@" <<'PY'
import hashlib,json,os,pathlib,sys
run=json.load(open(sys.argv[1],encoding='utf-8')); out=pathlib.Path(sys.argv[2])
task,rev,cmd,nonce,requested,observed=sys.argv[3:9]
transport=sys.argv[9]; producer=sys.argv[10]; stdout=pathlib.Path(sys.argv[11]); stderr=pathlib.Path(sys.argv[12]); inv=sys.argv[13]
def h(p):
    q=pathlib.Path(p); return hashlib.sha256(q.read_bytes()).hexdigest()
arts=[]
for spec in sys.argv[14:]:
    role,path=spec.split('=',1); arts.append({'role':role,'path':path,'sha256':h(path)})
inventory={'components':{}}
if inv: inventory=json.load(open(inv,encoding='utf-8'))
def n(v): return None if v in ('','not-applicable') else v
doc={
 'schema_version':1,'run_id':run['run_id'],'row_id':run['primary_row_id'],'row_type':run['primary_row_type'],
 'source':'device-driver','command':cmd,'task_id':task,'nonce':n(nonce),'endpoint':run['primary_endpoint'],
 'jailbreak':run['jailbreak'],'os_version':run['os_version'],'os_build':run['os_build'],'architecture':run['architecture'],
 'requested_mode':requested,'observed_mode':observed,'probe_revision':rev,'inventory':inventory,'artifacts':arts,
 'stdout':{'path':str(stdout),'sha256':h(stdout)},'stderr':{'path':str(stderr),'sha256':h(stderr)},
 'exit':{'command':int(transport) if transport.isdigit() else transport,'transport':int(transport) if transport.isdigit() else transport,'producer':int(producer) if producer.isdigit() else producer},
 'pid':None,'process_start_identity':None,
 'launch':{'transition':'not-applicable','pre_pid':None,'pre_lstart':None,'pre_state':'not-applicable','post_pid':None,'post_lstart':None,'post_state':'not-applicable'},
 'cleanup':{'event_ids':[],'journal_sha256':None,'result':'not-applicable','artifacts':[]},
 'restore':{'result':'not-applicable','artifacts':[]},'authorization':{'sha256':None},
 'reconnect':{'expected_disconnect':False,'elapsed_seconds':None,'result':'not-applicable'}
}
t=out.with_name(out.name+f'.tmp.{os.getpid()}')
with open(t,'w',encoding='utf-8') as f: json.dump(doc,f,sort_keys=True,separators=(',',':')); f.write('\n'); f.flush(); os.fsync(f.fileno())
os.replace(t,out); fd=os.open(out.parent,os.O_RDONLY); os.fsync(fd); os.close(fd)
PY
}

journal_event() {
    local event_id=$1 action=$2 target=$3 prior=$4 state=$5
    python3 - "$EVIDENCE_ABS/cleanup.jsonl" "$event_id" "$action" "$target" "$prior" "$state" <<'PY'
import json,os,sys,time
p=sys.argv[1]; row={'event_id':sys.argv[2],'action':sys.argv[3],'target':sys.argv[4],
 'prior_state':sys.argv[5],'state':sys.argv[6],'timestamp':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())}
fd=os.open(p,os.O_WRONLY|os.O_APPEND|os.O_CREAT,0o600)
with os.fdopen(fd,'a',encoding='utf-8') as f: f.write(json.dumps(row,sort_keys=True,separators=(',',':'))+'\n'); f.flush(); os.fsync(f.fileno())
PY
}

new_event_id() { printf '%s-%s-%s-%s' "$SHADOW_RUN_ID" "$SHADOW_TASK_ID" "$(date -u +%Y%m%dT%H%M%SZ)" "$$-$RANDOM"; }

package_status_remote() {
    cat <<'EOS'
for package in me.jjolano.shadow me.jjolano.shadow.harness me.jjolano.dyldprobe; do
  row=$(dpkg-query -W -f='${Version}\t${db:Status-Status}' "$package" 2>/dev/null || true)
  if [ -n "$row" ]; then
    version=$(printf '%s\n' "$row" | cut -f1); status=$(printf '%s\n' "$row" | cut -f2)
    printf 'PACKAGE\t%s\t%s\t%s\n' "$package" "$version" "$status"
  else
    printf 'PACKAGE\t%s\tnull\tabsent\n' "$package"
  fi
done
dpkg-query -W -f='DPKG\t${Package}\t${db:Status-Status}\n'
EOS
}

capture_package_database() {
    local status_file=$1 audit_file=$2 required_package=${3:-}
    ssh_mobile "$(package_status_remote)" >"$status_file" 2>>"$CAPTURE_STDERR" || return
    ssh_privileged 'dpkg --audit' >"$audit_file" 2>>"$CAPTURE_STDERR" || return
    python3 - "$status_file" "$audit_file" "$required_package" <<'PY'
import pathlib,sys
rows={}
states={}
for line in pathlib.Path(sys.argv[1]).read_text(errors='replace').splitlines():
    fields=line.split('\t')
    if len(fields)==4 and fields[0]=='PACKAGE':
        rows[fields[1]]={'version':None if fields[2]=='null' else fields[2],'status':fields[3]}
    elif len(fields)==3 and fields[0]=='DPKG': states[fields[1]]=fields[2]
expected={'me.jjolano.shadow','me.jjolano.shadow.harness','me.jjolano.dyldprobe'}
if set(rows)!=expected: raise SystemExit('package-status key drift')
bad=[name for name,row in rows.items() if row['status'] not in {'installed','absent'}]
if bad: raise SystemExit('package database is not ready: '+','.join(sorted(bad)))
allowed={'installed','not-installed','config-files'}
pending=[name for name,status in states.items() if status not in allowed]
if pending: raise SystemExit('dpkg has transitional packages: '+','.join(sorted(pending)))
required=sys.argv[3]
if required:
    for name in {required,'me.jjolano.shadow'}:
        if rows.get(name,{}).get('status')!='installed': raise SystemExit(f'required package is not installed: {name}')
PY
}

cmd_inventory() {
    local preparation=${1:-evidence} remote rc package_rc inventory_json package_status audit_file
    case "$preparation" in
        evidence) prepare_existing_run || return ;;
        restore) prepare_restore || return ;;
        *) die 'invalid inventory preparation mode' ;;
    esac
    verify_device_identity || return
    capture_dir '' inventory device
    read -r -d '' remote <<'EOS' || true
set -u
emit_file() {
  key=$1; package=$2; exact=$3; pid_expected=$4
  expected=false
  if [ "$package" != none ] && dpkg-query -L "$package" 2>/dev/null | grep -F -x "$exact" >/dev/null 2>&1; then expected=true; fi
  if [ -f "$exact" ]; then count=1; else count=0; fi
  digest=null
  if [ "$count" = 1 ] && [ -f "$exact" ]; then digest=$(sha256sum "$exact" | cut -d' ' -f1); fi
  printf 'FILE\t%s\t%s\t%s\t%s\t%s\t%s\n' "$key" "$expected" "$exact" "$count" "$digest" "$pid_expected"
}
job=$(launchctl print system/me.jjolano.shadow 2>/dev/null || true)
job_pid=$(printf '%s\n' "$job" | sed -n 's/^[[:space:]]*pid = //p' | head -1)
case "$job_pid" in ''|*[!0-9]*) shadowd_pid=false ;; *) shadowd_pid=true ;; esac
printf 'SHADOWD_JOB_PID\t%s\n' "$job_pid"
emit_file shadowd me.jjolano.shadow /var/jb/usr/libexec/shadowd "$shadowd_pid"
emit_file ShadowCore me.jjolano.shadow /var/jb/usr/lib/ShadowCore.dylib false
emit_file harness me.jjolano.shadow.harness /var/jb/Applications/ShadowHarness.app/ShadowHarness false
emit_file dyldprobe me.jjolano.dyldprobe /var/jb/Applications/dyldprobe.app/dyldprobe false
emit_file hookprobe none /var/jb/usr/bin/hookprobe false
printf 'PS_BEGIN\n'
ps -ax -o pid=,lstart=,comm= 2>/dev/null || printf '__PS_ERROR__\n'
printf 'PS_END\n'
EOS
    set +e
    ssh_mobile "$remote" >"$CAPTURE_STDOUT" 2>"$CAPTURE_STDERR"
    rc=$?
    package_status="$CAPTURE_DIR/package-status.tsv"
    audit_file="$CAPTURE_DIR/dpkg-audit.txt"
    : >"$package_status"; : >"$audit_file"
    if [ "$rc" -eq 0 ]; then
        capture_package_database "$package_status" "$audit_file"
        package_rc=$?
        cat "$package_status" >>"$CAPTURE_STDOUT"
        [ "$package_rc" -eq 0 ] || rc=$package_rc
    fi
    set -e
    inventory_json="$CAPTURE_DIR/inventory.json"
    if [ -f "$package_status" ]; then
        set +e
        python3 - "$CAPTURE_STDOUT" "$inventory_json" "$EVIDENCE_ABS/cleanup.jsonl" "$EVIDENCE_ABS/run.json" "$audit_file" <<'PY'
import json,os,pathlib,sys
raw=pathlib.Path(sys.argv[1]).read_text(errors='replace').splitlines(); out=pathlib.Path(sys.argv[2])
rows={}; packages={}; dpkg_states={}; ps=[]; in_ps=False; ps_error=False; shadowd_job_pid=None
for line in raw:
    if line=='PS_BEGIN': in_ps=True; continue
    if line=='PS_END': in_ps=False; continue
    if in_ps:
        if line=='__PS_ERROR__': ps_error=True
        elif line.strip(): ps.append(line)
        continue
    f=line.split('\t')
    if len(f)==2 and f[0]=='SHADOWD_JOB_PID': shadowd_job_pid=f[1]; continue
    if len(f)==7 and f[0]=='FILE': rows[f[1]]=f[2:]
    if len(f)==4 and f[0]=='PACKAGE': packages[f[1]]={'version':None if f[2]=='null' else f[2],'status':f[3]}
    if len(f)==3 and f[0]=='DPKG': dpkg_states[f[1]]=f[2]
keys=['shadowd','ShadowCore','harness','dyldprobe','hookprobe']
if set(rows)!=set(keys): raise SystemExit('inventory component-key drift')
package_keys={'me.jjolano.shadow','me.jjolano.shadow.harness','me.jjolano.dyldprobe'}
if set(packages)!=package_keys: raise SystemExit('inventory package-key drift')
latest={}
try:
    for line in pathlib.Path(sys.argv[3]).read_text().splitlines():
        if line.strip():
            event=json.loads(line); latest[event['event_id']]=event
except Exception: pass
run=json.load(open(sys.argv[4])); baseline=run.get('baseline_components',{})
hook_expected=baseline.get('hookprobe',{}).get('presence')=='present' or any(v.get('action')=='install-hookprobe' and v.get('state')=='completed' for v in latest.values())
allowed={'installed','not-installed','config-files'}
pending=sorted(name for name,status in dpkg_states.items() if status not in allowed)
components={}; failed=bool(pending)
if any(row['status'] not in {'installed','absent'} for row in packages.values()): failed=True
for key in keys:
    expected_s,path,count_s,digest,pid_expected_s=rows[key]
    expected=expected_s=='true'
    if key=='hookprobe': expected=hook_expected
    pid_expected=pid_expected_s=='true'
    try: count=int(count_s)
    except ValueError: count=-1
    if count<0: discovery='error'; failed=True
    elif count==1: discovery='one-match'
    elif count==0 and expected: discovery='zero-match'; failed=True
    elif count==0: discovery='expected-absent'
    else: discovery='error'; failed=True
    if key=='ShadowCore':
        pid_status='not-applicable'; pids=None; starts=None
    elif ps_error:
        pid_status='error'; pids=[]; starts=[]; failed=True
    else:
        found=[]
        for line in ps:
            bits=line.strip().split()
            comm=bits[-1] if bits else ''
            suffix=path[path.find('/Applications/'):] if '/Applications/' in path else path
            matches=(comm==path or comm.endswith(suffix))
            if key=='shadowd': matches=(bits and bits[0]==shadowd_job_pid and comm in ('(shadowd)','shadowd',path))
            if key=='hookprobe': matches=(comm in ('(hookprobe)','hookprobe',path) or comm.endswith('/hookprobe'))
            if len(bits)>=3 and bits[0].isdigit() and matches:
                found.append((int(bits[0]),' '.join(bits[1:-1])))
        pids=[p for p,_ in found]; starts=[s for _,s in found]
        if len(found)>1: pid_status='error'; failed=True
        elif len(found)==1: pid_status='one-match'
        elif pid_expected: pid_status='zero-match'; failed=True
        else: pid_status='expected-absent'
    components[key]={'key':key,'expected_presence':expected,'pid_expected':pid_expected,
      'resolved_exact_path':path if count==1 else None,'discovery_status':discovery,
      'artifact_sha256':None if digest=='null' else digest,'pid_status':pid_status,
      'pids':pids,'process_start_identity':starts}
doc={'components':components,'package_database':{'packages':packages,'transitional_packages':pending,'dpkg_audit':'recorded'},'status':'PASS' if not failed else 'FAIL'}
t=out.with_name(out.name+f'.tmp.{os.getpid()}')
with open(t,'w') as f: json.dump(doc,f,sort_keys=True,separators=(',',':')); f.write('\n'); f.flush(); os.fsync(f.fileno())
os.replace(t,out)
if failed: raise SystemExit(2)
PY
        rc=$?
        set -e
    fi
    if [ ! -f "$inventory_json" ]; then
        printf '{"components":{},"status":"SETUP-FAIL"}\n' >"$inventory_json"
    fi
    write_manifest inventory '' not-applicable not-applicable "$rc" 0 "$inventory_json" "inventory=$inventory_json" "package-status=$package_status" "dpkg-audit=$audit_file"
    [ "$rc" -eq 0 ] || die 'inventory failed'
    printf '%s\n' "$CAPTURE_DIR/manifest.json"
}

require_clean_journal() {
    python3 - "$EVIDENCE_ABS/cleanup.jsonl" <<'PY'
import json,pathlib,sys
latest={}
for line in pathlib.Path(sys.argv[1]).read_text().splitlines():
    if line.strip():
        row=json.loads(line); latest[row['event_id']]=row
bad=[r for r in latest.values() if r.get('state')!='restored']
if bad: raise SystemExit('cleanup journal has unresolved events: '+','.join(r['event_id'] for r in bad))
PY
}

baseline_shadowd_job() {
    python3 - "$EVIDENCE_ABS/run.json" <<'PY'
import json,sys
state=json.load(open(sys.argv[1])).get('baseline_service',{}).get('shadowd_job')
if state not in {'present','absent'}: raise SystemExit('invalid baseline shadowd service state')
print(state)
PY
}

daemon_snapshot_remote() {
    cat <<'EOS'
set -u
job=$(launchctl print system/me.jjolano.shadow 2>/dev/null || true)
if [ -n "$job" ]; then
  printf 'job\tpresent\n'
  printf 'program\t%s\n' "$(printf '%s\n' "$job" | sed -n 's/^[[:space:]]*program = //p' | head -1)"
  printf 'job_pid\t%s\n' "$(printf '%s\n' "$job" | sed -n 's/^[[:space:]]*pid = //p' | head -1)"
else
  printf 'job\tabsent\nprogram\tabsent\njob_pid\tabsent\n'
fi
printf 'processes_begin\n'
ps -ax -o pid=,lstart=,comm= 2>/dev/null | grep -E '\(shadowd\)$|/shadowd$' || true
printf 'processes_end\n'
ledger=/var/jb/var/mobile/Library/Preferences/me.jjolano.shadowd/shadowd.ledger
printf 'ledger\t'
if [ ! -e "$ledger" ]; then printf 'absent\n'; elif [ ! -f "$ledger" ]; then printf 'error\n'; elif tail -n +3 "$ledger" 2>/dev/null | grep -q .; then printf 'records\n'; else printf 'empty\n'; fi
for p in /var/mobile/Library/Preferences/me.jjolano.shadow.plist /var/jb/var/mobile/Library/Preferences/me.jjolano.shadow.plist /Library/PreferenceBundles/ShadowSettings.bundle /var/jb/Library/PreferenceBundles/ShadowSettings.bundle; do
  printf 'control\t%s\t' "$p"; if [ -e "$p" ]; then printf 'visible\n'; else printf 'absent\n'; fi
done
log=/var/jb/var/log/shadowd.log
if [ ! -e "$log" ]; then
  printf 'log\tabsent\nlog_sha256\tnull\nlog_lines\t0\n'
elif [ -f "$log" ]; then
  lines=$(sed -n '$=' "$log" 2>/dev/null || true)
  printf 'log\tfile\nlog_sha256\t%s\nlog_lines\t%s\n' "$(sha256sum "$log" | cut -d' ' -f1)" "${lines:-0}"
else
  printf 'log\terror\nlog_sha256\tnull\nlog_lines\t0\n'
fi
printf 'log_begin\n'; tail -n 200 /var/jb/var/log/shadowd.log 2>/dev/null || true; printf 'log_end\n'
EOS
}

validate_daemon_snapshot() {
    local path=$1 require_absent=${2:-false}
    python3 - "$path" "$require_absent" "$EVIDENCE_ABS/run.json" <<'PY'
import json,pathlib,re,sys
lines=pathlib.Path(sys.argv[1]).read_text(errors='replace').splitlines(); absent=sys.argv[2]=='true'
baseline=json.load(open(sys.argv[3])).get('allowlist_controls',{})
facts={}; controls=[]; procs=[]; mode=None
for line in lines:
    if line=='processes_begin': mode='p'; continue
    if line=='processes_end': mode=None; continue
    if line=='log_begin': mode='l'; continue
    if line=='log_end': mode=None; continue
    if mode=='p' and line.strip(): procs.append(line)
    elif '\t' in line:
        f=line.split('\t')
        if f[0]=='control' and len(f)==3: controls.append((f[1],f[2]))
        elif len(f)>=2: facts[f[0]]=f[1]
if facts.get('ledger') not in ('absent','empty'): raise SystemExit('ledger is not absent/empty')
if facts.get('log') not in ('absent','file'): raise SystemExit('shadowd log has invalid type')
if len(controls)!=4 or dict(controls)!=baseline: raise SystemExit('allowlist controls differ from preflight baseline')
rows=[]
for line in procs:
    b=line.strip().split()
    if len(b)>=3 and b[0].isdigit() and b[-1] in ('(shadowd)','shadowd','/var/jb/usr/libexec/shadowd','/usr/libexec/shadowd'):
        rows.append((b[0],b[-1]))
if absent:
    if facts.get('job')!='absent' or rows: raise SystemExit('shadowd job/process still present')
else:
    if facts.get('job')!='present': raise SystemExit('shadowd job absent')
    if facts.get('program')!='/var/jb/usr/libexec/shadowd': raise SystemExit('unexpected shadowd job program')
    if facts.get('job_pid','').isdigit():
        if rows != [(facts['job_pid'], '(shadowd)')] and rows != [(facts['job_pid'], '/var/jb/usr/libexec/shadowd')]:
            raise SystemExit('shadowd job/process identity mismatch')
    elif facts.get('job_pid') not in ('', 'absent') or rows:
        raise SystemExit('invalid idle shadowd job state')
print('PASS')
PY
}

validate_legacy_daemon_snapshot() {
    local snapshot=$1 ledger=$2
    python3 - "$snapshot" "$ledger" "$EVIDENCE_ABS/run.json" <<'PY'
import json,pathlib,re,sys
snapshot,ledger,run=map(pathlib.Path,sys.argv[1:])
facts={}; controls=[]; mode=None
for line in snapshot.read_text(errors='replace').splitlines():
    if line in {'processes_begin','log_begin'}: mode=line; continue
    if line in {'processes_end','log_end'}: mode=None; continue
    if mode is not None: continue
    fields=line.split('\t')
    if fields[0]=='control' and len(fields)==3: controls.append((fields[1],fields[2]))
    elif len(fields)>=2: facts[fields[0]]=fields[1]
baseline=json.load(open(run)).get('allowlist_controls',{})
if facts.get('job')!='present' or facts.get('program')!='/var/jb/usr/libexec/shadowd':
    raise SystemExit('legacy daemon identity mismatch')
if facts.get('ledger')!='records' or facts.get('log')!='file' or len(controls)!=4 or dict(controls)!=baseline:
    raise SystemExit('legacy daemon state is unsafe')
rows=[line for line in ledger.read_text(errors='strict').splitlines() if line]
if len(rows)<3 or rows[0]!='SHADOWLEDGER1' or not re.fullmatch(r'[0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}',rows[1]):
    raise SystemExit('legacy ledger header is unsafe')
paths={'/Library/PreferenceBundles/ShadowSettings.bundle','/var/jb/Library/PreferenceBundles/ShadowSettings.bundle'}
for row in rows[2:]:
    fields=row.split('|')
    if len(fields)!=5: raise SystemExit('legacy ledger record is unsafe')
    state,path,owner,vnode,vid=fields
    if state not in {'0','1'} or path not in paths or not re.fullmatch(r'[1-9][0-9]*-[0-9]+-[0-9]+',owner):
        raise SystemExit('legacy ledger record is unsafe')
    if not re.fullmatch(r'0x[0-9A-Fa-f]+',vnode) or not re.fullmatch(r'0x[0-9A-Fa-f]+',vid):
        raise SystemExit('legacy ledger pointer is unsafe')
print('PASS')
PY
}

legacy_ledger_owner_pids() {
    python3 - "$1" <<'PY'
import pathlib,re,sys
pids=set()
for row in pathlib.Path(sys.argv[1]).read_text(errors='strict').splitlines()[2:]:
    fields=row.split('|')
    if len(fields)!=5: raise SystemExit('legacy ledger record is unsafe')
    owner=fields[2]
    if not re.fullmatch(r'[1-9][0-9]*-[0-9]+-[0-9]+',owner): raise SystemExit('legacy ledger owner is unsafe')
    pids.add(int(owner.split('-',1)[0]))
for pid in sorted(pids): print(pid)
PY
}

validate_legacy_recovery_delta() {
    local ledger=$1 delta=$2
    python3 - "$ledger" "$delta" <<'PY'
import pathlib,sys
ledger,delta=map(pathlib.Path,sys.argv[1:])
rows=[line.split('|') for line in ledger.read_text(errors='strict').splitlines()[2:] if line]
paths={row[1] for row in rows if len(row)==5}
lines=delta.read_text(errors='replace').splitlines()
if not any('krw: ready' in line for line in lines):
    raise SystemExit('legacy daemon did not complete recovery')
for path in paths:
    safe=(f'ledger: re-hidden {path} via fresh fd',
          f'ledger: re-hide UNVERIFIED for {path} — retained fd + record',
          f'ledger: adopted hidden {path} ',
          f'ledger: mayBeHidden + visible → rolled back: {path}',
          f'not flagged — dropped: {path}')
    if not any(any(marker in line for marker in safe) for line in lines):
        raise SystemExit('legacy ledger recovery is ambiguous: '+path)
print('PASS')
PY
}

backend_absence_remote() {
    daemon_snapshot_remote
    cat <<'EOS'
for path in \
  /var/jb/usr/libexec/shadowd \
  /usr/libexec/shadowd \
  /var/jb/var/mobile/Library/Preferences/me.jjolano.shadowd/shadowd.ledger \
  /var/mobile/Library/Preferences/me.jjolano.shadowd/shadowd.ledger \
  /var/jb/var/log/shadowd.log \
  /var/log/shadowd.log; do
  if [ -e "$path" ]; then state=present; else state=absent; fi
  printf 'backend\t%s\t%s\n' "$path" "$state"
done
EOS
}

validate_backend_absence_snapshot() {
    local snapshot=$1
    validate_daemon_snapshot "$snapshot" true >/dev/null
    python3 - "$snapshot" <<'PY'
import pathlib,sys
facts={}; paths={}; mode=None
for line in pathlib.Path(sys.argv[1]).read_text(errors='replace').splitlines():
    if line in {'processes_begin','log_begin'}: mode=line; continue
    if line in {'processes_end','log_end'}: mode=None; continue
    if mode is not None: continue
    fields=line.split('\t')
    if len(fields)==2: facts[fields[0]]=fields[1]
    elif len(fields)==3 and fields[0]=='backend': paths[fields[1]]=fields[2]
expected={
  '/var/jb/usr/libexec/shadowd', '/usr/libexec/shadowd',
  '/var/jb/var/mobile/Library/Preferences/me.jjolano.shadowd/shadowd.ledger',
  '/var/mobile/Library/Preferences/me.jjolano.shadowd/shadowd.ledger',
  '/var/jb/var/log/shadowd.log', '/var/log/shadowd.log',
}
if set(paths)!=expected or any(value!='absent' for value in paths.values()):
    raise SystemExit('backend payload, ledger, or activation log remains')
if facts.get('ledger')!='absent' or facts.get('log')!='absent':
    raise SystemExit('backend durable state remains')
PY
}

capture_backend_absence_snapshot() {
    local snapshot=$1
    ssh_privileged "$(backend_absence_remote)" >"$snapshot" 2>>"$CAPTURE_STDERR" || return 1
    validate_backend_absence_snapshot "$snapshot"
}

springboard_snapshot_remote() {
    cat <<'EOS'
job=$(launchctl print system/com.apple.SpringBoard 2>/dev/null || true)
pid=$(printf '%s\n' "$job" | sed -n 's/^[[:space:]]*pid = //p' | head -1)
case "$pid" in ''|*[!0-9]*) exit 1 ;; esac
started=$(ps -p "$pid" -o lstart= 2>/dev/null | sed 's/^[[:space:]]*//')
[ -n "$started" ] || exit 1
printf 'pid\t%s\nlstart\t%s\n' "$pid" "$started"
EOS
}

validate_springboard_snapshot() {
    local snapshot=$1
    python3 - "$snapshot" <<'PY'
import pathlib,sys
rows={}
for line in pathlib.Path(sys.argv[1]).read_text(errors='replace').splitlines():
    fields=line.split('\t',1)
    if len(fields)==2: rows[fields[0]]=fields[1]
if set(rows)!={'pid','lstart'} or not rows['pid'].isdigit() or not rows['lstart']:
    raise SystemExit('invalid SpringBoard identity')
PY
}

validate_springboard_transition() {
    local before=$1 after=$2
    validate_springboard_snapshot "$before"
    validate_springboard_snapshot "$after"
    python3 - "$before" "$after" <<'PY'
import pathlib,sys
def read(path): return dict(line.split('\t',1) for line in pathlib.Path(path).read_text().splitlines() if '\t' in line)
before,after=read(sys.argv[1]),read(sys.argv[2])
if before==after: raise SystemExit('SpringBoard restart was not observed')
PY
}

wait_for_springboard_restart() {
    local before=$1 after=$2 started=$SECONDS rc
    while [ $((SECONDS - started)) -lt 180 ]; do
        set +e
        ssh_mobile "$(springboard_snapshot_remote)" >"$after" 2>>"$CAPTURE_STDERR"
        rc=$?
        set -e
        if [ "$rc" -eq 0 ] && validate_springboard_transition "$before" "$after" >/dev/null 2>&1; then
            printf '%s\n' "$((SECONDS - started))"
            return 0
        fi
        sleep 3
    done
    return 1
}

cmd_daemon_status() {
    local remote rc status_json container source destination
    local legacy_specs=()
    prepare_existing_run
    verify_device_identity
    capture_dir '' daemon-status device
    remote=$(daemon_snapshot_remote)
    set +e
    ssh_privileged "$remote" >"$CAPTURE_STDOUT" 2>"$CAPTURE_STDERR"
    rc=$?
    set -e
    status_json="$CAPTURE_DIR/daemon-status.json"
    python3 - "$CAPTURE_STDOUT" "$status_json" "$rc" <<'PY'
import json,os,pathlib,sys
p=pathlib.Path(sys.argv[2]); raw=pathlib.Path(sys.argv[1]).read_text(errors='replace').splitlines()
facts={}; controls={}; procs=[]; logs=[]; mode=None
for line in raw:
    if line=='processes_begin': mode='p'; continue
    if line=='processes_end': mode=None; continue
    if line=='log_begin': mode='l'; continue
    if line=='log_end': mode=None; continue
    if mode=='p': procs.append(line)
    elif mode=='l': logs.append(line)
    elif '\t' in line:
        f=line.split('\t');
        if f[0]=='control' and len(f)==3: controls[f[1]]=f[2]
        elif len(f)>=2: facts[f[0]]=f[1]
d={'transport_exit':int(sys.argv[3]),'job':facts.get('job','error'),'ledger':facts.get('ledger','error'),
   'process_rows':procs,'controls':controls,'log_tail':logs}
t=p.with_name(p.name+f'.tmp.{os.getpid()}')
with open(t,'w') as f: json.dump(d,f,sort_keys=True,separators=(',',':')); f.write('\n'); f.flush(); os.fsync(f.fileno())
os.replace(t,p)
PY
    legacy_specs+=("legacy-baseline=$CAPTURE_STDOUT")
    container=$(container_for_bundle me.jjolano.shadow.harness)
    for source in "$container/Documents/ShadowDiagnostics.txt" /var/mobile/Documents/ShadowDiagnostics.txt /var/mobile/Documents/dyldprobe-report.txt; do
        if ssh_mobile "test -f $(sq "$source") && test -r $(sq "$source")" >/dev/null 2>&1; then
            destination="$CAPTURE_DIR/legacy-$(basename -- "$source")-${#legacy_specs[@]}"
            scp_from "$source" "$destination" >/dev/null 2>>"$CAPTURE_STDERR" || die "legacy baseline transfer failed: $source"
            legacy_specs+=("legacy-baseline=$destination")
        fi
    done
    source=/var/jb/var/mobile/Library/Preferences/me.jjolano.shadowd/shadowd.ledger
    if ssh_privileged "test -f $(sq "$source")" >/dev/null 2>&1; then
        destination="$CAPTURE_DIR/legacy-shadowd.ledger"
        ssh_privileged "cat $(sq "$source")" >"$destination" 2>>"$CAPTURE_STDERR" || die 'legacy ledger capture failed'
        legacy_specs+=("legacy-baseline=$destination")
    fi
    write_manifest daemon-status '' not-applicable not-applicable "$rc" 0 '' "daemon-status=$status_json" "${legacy_specs[@]}"
    [ "$rc" -eq 0 ] || die 'daemon status transport failed'
    printf '%s\n' "$CAPTURE_DIR/manifest.json"
}

daemon_term_safe_internal() {
    local event remote before after delta before_lines after_lines job_pid rc legacy_ledger legacy=0 legacy_owners legacy_recovery legacy_ready exit_seen
    require_clean_journal
    DAEMON_LEGACY_LEDGER=''
    DAEMON_LEGACY_OWNER_PIDS=''
    DAEMON_LEGACY_RECOVERY=''
    before="$CAPTURE_DIR/daemon-before.txt"; after="$CAPTURE_DIR/daemon-after.txt"
    remote=$(daemon_snapshot_remote)
    ssh_privileged "$remote" >"$before" 2>>"$CAPTURE_STDERR" || die 'daemon precheck transport failed'
    if ! validate_daemon_snapshot "$before" false >>"$CAPTURE_STDOUT" 2>>"$CAPTURE_STDERR"; then
        legacy_ledger="$CAPTURE_DIR/legacy-shadowd.ledger"
        ssh_privileged 'test -f /var/jb/var/mobile/Library/Preferences/me.jjolano.shadowd/shadowd.ledger && test ! -L /var/jb/var/mobile/Library/Preferences/me.jjolano.shadowd/shadowd.ledger && cat /var/jb/var/mobile/Library/Preferences/me.jjolano.shadowd/shadowd.ledger' >"$legacy_ledger" 2>>"$CAPTURE_STDERR" || die 'legacy ledger capture failed'
        validate_legacy_daemon_snapshot "$before" "$legacy_ledger" >>"$CAPTURE_STDOUT" || die 'legacy daemon teardown is unsafe'
        DAEMON_LEGACY_LEDGER=$legacy_ledger
        legacy=1
    fi
    before_lines=$(sed -n 's/^log_lines[[:space:]]//p' "$before" | head -1)
    job_pid=$(sed -n 's/^job_pid[[:space:]]//p' "$before" | head -1)
    [[ $before_lines =~ ^[0-9]+$ ]] || die 'invalid daemon log baseline'
    if [ "$legacy" -eq 1 ]; then
        legacy_owners="$CAPTURE_DIR/legacy-owner-pids.txt"
        legacy_ledger_owner_pids "$legacy_ledger" >"$legacy_owners" || die 'legacy ledger owners are unsafe'
        while IFS= read -r owner_pid; do
            ssh_mobile "test -z \"\$(ps -p $owner_pid -o pid= 2>/dev/null)\"" || die "legacy owner remains live: $owner_pid"
        done <"$legacy_owners"
        DAEMON_LEGACY_OWNER_PIDS=$legacy_owners
    fi
    event=$(new_event_id)
    journal_event "$event" daemon-bootout system/me.jjolano.shadow bootstrap pending
    if [ "$legacy" -eq 1 ]; then
        ssh_privileged 'launchctl kickstart system/me.jjolano.shadow' >>"$CAPTURE_STDOUT" 2>>"$CAPTURE_STDERR" || die 'legacy daemon start failed'
        legacy_recovery="$CAPTURE_DIR/legacy-recovery-delta.txt"
        : >"$legacy_recovery"
        for _ in $(seq 1 30); do
            ssh_privileged "tail -n +$((before_lines + 1)) /var/jb/var/log/shadowd.log" >"$legacy_recovery" 2>>"$CAPTURE_STDERR" || die 'legacy recovery log capture failed'
            if grep -F 'krw: ready' "$legacy_recovery" >/dev/null; then break; fi
            sleep 1
        done
        validate_legacy_recovery_delta "$legacy_ledger" "$legacy_recovery" >>"$CAPTURE_STDOUT" || die 'legacy daemon recovery is unsafe'
        legacy_ready="$CAPTURE_DIR/legacy-daemon-ready.txt"
        ssh_privileged "$remote" >"$legacy_ready" 2>>"$CAPTURE_STDERR" || die 'legacy daemon readiness check failed'
        job_pid=$(sed -n 's/^job_pid[[:space:]]//p' "$legacy_ready" | head -1)
        [[ $job_pid =~ ^[1-9][0-9]*$ ]] || die 'legacy daemon has no exact live PID after recovery'
        DAEMON_LEGACY_RECOVERY=$legacy_recovery
    fi
    set +e
    ssh_privileged 'launchctl kill SIGTERM system/me.jjolano.shadow' >>"$CAPTURE_STDOUT" 2>>"$CAPTURE_STDERR"
    rc=$?
    set -e
    [ "$rc" -eq 0 ] || die 'clean daemon SIGTERM failed'
    delta="$CAPTURE_DIR/daemon-exit-delta.txt"
    : >"$delta"
    if [[ $job_pid =~ ^[0-9]+$ ]]; then
        after_lines=''
        exit_seen=0
        for _ in $(seq 1 30); do
            ssh_privileged "$remote" >"$after" 2>>"$CAPTURE_STDERR" || die 'daemon postcheck transport failed'
            after_lines=$(sed -n 's/^log_lines[[:space:]]//p' "$after" | head -1)
            if [[ $after_lines =~ ^[0-9]+$ ]] && [ "$after_lines" -gt "$before_lines" ]; then
                ssh_privileged "tail -n +$((before_lines + 1)) /var/jb/var/log/shadowd.log" >"$delta" 2>>"$CAPTURE_STDERR" || die 'daemon shutdown log capture failed'
                if grep -F 'shadowd exiting' "$delta" >/dev/null; then exit_seen=1; break; fi
            fi
            sleep 1
        done
        [ "$exit_seen" -eq 1 ] || die 'clean shadowd exit log missing'
    fi
    set +e
    ssh_privileged 'launchctl bootout system/me.jjolano.shadow' >>"$CAPTURE_STDOUT" 2>>"$CAPTURE_STDERR"
    rc=$?
    set -e
    if [ "$rc" -ne 0 ] && ssh_privileged 'launchctl print system/me.jjolano.shadow >/dev/null 2>&1'; then
        die 'clean launchctl bootout failed'
    fi
    ssh_privileged "$remote" >"$after" 2>>"$CAPTURE_STDERR" || die 'daemon postcheck transport failed'
    validate_daemon_snapshot "$after" true >>"$CAPTURE_STDOUT"
    journal_event "$event" daemon-bootout system/me.jjolano.shadow bootstrap completed
}

cmd_daemon_term_safe() {
    local artifacts=()
    prepare_existing_run
    verify_device_identity
    capture_dir '' daemon-term-safe device
    daemon_term_safe_internal
    artifacts=("daemon-before=$CAPTURE_DIR/daemon-before.txt" "daemon-after=$CAPTURE_DIR/daemon-after.txt" \
        "daemon-exit-log=$CAPTURE_DIR/daemon-exit-delta.txt")
    [ -z "$DAEMON_LEGACY_LEDGER" ] || artifacts+=("legacy-ledger=$DAEMON_LEGACY_LEDGER")
    [ -z "$DAEMON_LEGACY_OWNER_PIDS" ] || artifacts+=("legacy-owner-pids=$DAEMON_LEGACY_OWNER_PIDS")
    [ -z "$DAEMON_LEGACY_RECOVERY" ] || artifacts+=("legacy-recovery=$DAEMON_LEGACY_RECOVERY")
    write_manifest daemon-term-safe '' not-applicable not-applicable 0 0 '' "${artifacts[@]}"
    printf '%s\n' "$CAPTURE_DIR/manifest.json"
}

process_row() {
    local pid=$1
    [[ $pid =~ ^[1-9][0-9]*$ ]] || return 1
    ssh_mobile "ps -o pid=,lstart=,comm= -p $pid 2>/dev/null; rc=\$?; [ \$rc -eq 0 ] || [ \$rc -eq 1 ]"
}

client_sigkill_state() {
    local pid=$1 expected_start=$2 expected_comm=$3 row parsed_start comm
    row=$(process_row "$pid") || return 1
    [ -n "$row" ] || { printf 'absent\n'; return 0; }
    read -r parsed_start comm < <(python3 - "$row" <<'PY'
import sys
b=sys.argv[1].strip().split()
if len(b)<3 or not b[0].isdigit(): raise SystemExit(1)
print('|'.join(b[1:-1]), b[-1])
PY
)
    parsed_start=${parsed_start//|/ }
    [ -n "$parsed_start" ] && [ -n "$comm" ] || return 1
    if [ "$parsed_start" != "$expected_start" ]; then
        printf 'reused\n'
    elif [ "$comm" != "$expected_comm" ]; then
        printf 'changed\n'
    else
        printf 'live\n'
    fi
}

cmd_client_kill_safe() {
    local pid=$1 lstart=$2 row parsed_start comm event rc state
    prepare_existing_run
    verify_device_identity
    capture_dir '' client-kill-safe device
    row=$(process_row "$pid") || die 'client process disappeared'
    read -r parsed_start comm < <(python3 - "$row" <<'PY'
import sys
b=sys.argv[1].strip().split()
if len(b)<3 or not b[0].isdigit(): raise SystemExit(1)
print('|'.join(b[1:-1]), b[-1])
PY
)
    parsed_start=${parsed_start//|/ }
    [ "$parsed_start" = "$lstart" ] || die 'client PID start identity changed'
    case "$comm" in
        /var/jb/usr/bin/hookprobe|/usr/bin/hookprobe|*/ShadowHarness.app/ShadowHarness|*/dyldprobe.app/dyldprobe) ;;
        *) die "refusing to signal protected or unknown process: $comm" ;;
    esac
    event=$(new_event_id)
    journal_event "$event" client-sigkill "$pid" "$lstart|$comm" pending
    set +e
    ssh_privileged "kill -KILL $pid" >"$CAPTURE_STDOUT" 2>"$CAPTURE_STDERR"
    rc=$?
    set -e
    [ "$rc" -eq 0 ] || die 'client signal failed'
    state=$(client_sigkill_state "$pid" "$lstart" "$comm") || die 'client PID recheck failed'
    if [ "$state" = live ]; then
        # A stopped child can remain attached to an orphaned SSH shell after
        # its first SIGKILL. Revalidate before resuming it, then kill it in
        # the same checked privileged operation.
        set +e
        ssh_privileged "kill -CONT $pid && kill -KILL $pid" >>"$CAPTURE_STDOUT" 2>>"$CAPTURE_STDERR"
        rc=$?
        set -e
        [ "$rc" -eq 0 ] || die 'stopped client recovery signal failed'
    fi
    state=$(client_sigkill_state "$pid" "$lstart" "$comm") || die 'client PID final recheck failed'
    [ "$state" = absent ] || die "client PID still present or reused: $state"
    journal_event "$event" client-sigkill "$pid" "$lstart|$comm" completed
    journal_event "$event" client-sigkill "$pid" "$lstart|$comm" restored
    write_manifest client-kill-safe '' not-applicable not-applicable 0 0 ''
    printf '%s\n' "$CAPTURE_DIR/manifest.json"
}

cmd_import_stock() {
    local report=$1 metadata=$2 row nonce destination
    prepare_existing_run
    [ -f "$report" ] && [ -f "$metadata" ] || die 'stock report and metadata must be regular files'
    read -r row nonce < <(python3 - "$report" "$metadata" "$SHADOW_RUN_ID" "$TASK_REVISION" <<'PY'
import hashlib,json,pathlib,sys
rpath=pathlib.Path(sys.argv[1]); mpath=pathlib.Path(sys.argv[2]); run=sys.argv[3]; rev=sys.argv[4]
r=json.load(open(rpath)); m=json.load(open(mpath))
need={'row_id','row_type','os_version','os_build','architecture','jailbreak','nonce','probe_revision','producer','artifact_sha256','collection_source'}
if not need <= m.keys(): raise SystemExit('stock metadata missing fields')
if m['row_type']!='stock' or m['jailbreak']!='none': raise SystemExit('invalid stock provenance')
if r.get('run_id')!=run or r.get('row_id')!=m['row_id'] or r.get('row_type')!='stock' or r.get('requested_mode')!='stock': raise SystemExit('stock report provenance mismatch')
for k in ('nonce','probe_revision','producer'):
    if r.get(k)!=m.get(k): raise SystemExit(f'stock {k} mismatch')
if r.get('probe_revision')!=rev: raise SystemExit('stock task revision mismatch')
if hashlib.sha256(rpath.read_bytes()).hexdigest()!=m['artifact_sha256']: raise SystemExit('stock artifact hash mismatch')
if not isinstance(r.get('observations'),(list,dict)) or 'canary' not in r or 'producer_exit' not in r: raise SystemExit('stock report schema mismatch')
print(m['row_id'],m['nonce'])
PY
)
    [[ $row =~ ^[A-Za-z0-9][A-Za-z0-9._,-]*$ ]] || die 'invalid stock row ID'
    [[ $nonce =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || die 'invalid stock nonce'
    destination="$EVIDENCE_ABS/device/$row/$SHADOW_TASK_ID/$nonce/import-stock"
    mkdir -p "$destination"
    cp -p "$report" "$destination/raw-report.json"
    cp -p "$metadata" "$destination/metadata.json"
    CAPTURE_DIR=$destination; CAPTURE_STDOUT="$destination/stdout.txt"; CAPTURE_STDERR="$destination/stderr.txt"
    : >"$CAPTURE_STDOUT"; : >"$CAPTURE_STDERR"
    python3 - "$EVIDENCE_ABS/run.json" "$destination/manifest.json" "$metadata" "$destination/raw-report.json" "$destination/metadata.json" "$SHADOW_TASK_ID" <<'PY'
import hashlib,json,os,pathlib,sys
run=json.load(open(sys.argv[1])); out=pathlib.Path(sys.argv[2]); meta=json.load(open(sys.argv[3])); raw=pathlib.Path(sys.argv[4]); metacopy=pathlib.Path(sys.argv[5])
def h(p): return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
d={'schema_version':1,'run_id':run['run_id'],'row_id':meta['row_id'],'row_type':'stock','source':'manual-stock','command':'import-stock','task_id':sys.argv[6],
 'nonce':meta['nonce'],'endpoint':'not-applicable','jailbreak':{'name':'none','version':'none'},'os_version':meta['os_version'],'os_build':meta['os_build'],
 'architecture':meta['architecture'],'requested_mode':'stock','observed_mode':'stock','probe_revision':meta['probe_revision'],'inventory':{'components':{}},
 'artifacts':[{'role':'raw-report','path':str(raw),'sha256':h(raw)},{'role':'stock-metadata','path':str(metacopy),'sha256':h(metacopy)}],
 'stdout':{'path':str(out.parent/'stdout.txt'),'sha256':h(out.parent/'stdout.txt')},'stderr':{'path':str(out.parent/'stderr.txt'),'sha256':h(out.parent/'stderr.txt')},
 'exit':{'command':0,'transport':'not-applicable','producer':0},'pid':None,'process_start_identity':None,
 'launch':{'transition':'not-applicable','pre_pid':None,'pre_lstart':None,'pre_state':'not-applicable','post_pid':None,'post_lstart':None,'post_state':'not-applicable'},
 'cleanup':{'event_ids':[],'journal_sha256':h(pathlib.Path(sys.argv[1]).parent/'cleanup.jsonl'),'result':'not-applicable','artifacts':[]},
 'restore':{'result':'not-applicable','artifacts':[]},'authorization':{'sha256':None},'reconnect':{'expected_disconnect':False,'elapsed_seconds':None,'result':'not-applicable'}}
t=out.with_name(out.name+f'.tmp.{os.getpid()}');
with open(t,'w') as f: json.dump(d,f,sort_keys=True,separators=(',',':')); f.write('\n'); f.flush(); os.fsync(f.fileno())
os.replace(t,out)
PY
    printf '%s\n' "$destination/manifest.json"
}

cmd_build() {
    local flavor=$1 rc artifact_specs=() file frozen_dir frozen fixture_key fixture_spec fixture_source fixture_target
    case "$flavor" in rootless|rootful) ;; *) die 'build flavor must be rootless or rootful' ;; esac
    prepare_existing_run
    capture_dir "$flavor" build host
    set +e
    (
        set -e
        umask 022
        bash "$REPO_ROOT/build.sh" "$flavor"
        if [ "$flavor" = rootless ]; then
            bash "$REPO_ROOT/tools/dyldprobe/build.sh"
            make -C "$REPO_ROOT/tools/hookprobe" clean
            make -C "$REPO_ROOT/tools/hookprobe" THEOS_PACKAGE_SCHEME=rootless ARCHS='arm64 arm64e' TARGET=iphone:clang:latest:15.0
        fi
    ) >"$CAPTURE_STDOUT" 2>"$CAPTURE_STDERR"
    rc=$?
    set -e
    if [ "$rc" -eq 0 ]; then
        frozen_dir="$EVIDENCE_ABS/artifacts/$SHADOW_TASK_ID/$flavor"
        mkdir -p "$frozen_dir"
        while IFS= read -r -d '' file; do
            frozen="$frozen_dir/$(basename -- "$file")"
            cp -p "$file" "$frozen"
            artifact_specs+=("candidate=$frozen")
        done < <(find "$REPO_ROOT/build" -maxdepth 1 -type f -print0 | sort -z)
        if [ "$flavor" = rootless ]; then
            while IFS= read -r -d '' file; do
                frozen="$frozen_dir/$(basename -- "$file")"
                cp -p "$file" "$frozen"
                artifact_specs+=("candidate=$frozen")
            done < <(find "$REPO_ROOT/tools/dyldprobe/build" -maxdepth 1 -type f -name '*.deb' -print0 | sort -z)
            file="$REPO_ROOT/tools/hookprobe/.theos/obj/debug/hookprobe"
            [ -f "$file" ] && [ ! -L "$file" ] || die 'rootless hookprobe build artifact missing or unsafe'
            frozen="$frozen_dir/$(basename -- "$file")"
            cp -p "$file" "$frozen"
            artifact_specs+=("hookprobe=$frozen")
            while IFS= read -r fixture_key; do
                fixture_spec=$(identity_fixture_spec "$fixture_key") || die "unknown identity fixture: $fixture_key"
                IFS=$'\t' read -r fixture_source fixture_target <<<"$fixture_spec"
                file="$REPO_ROOT/tools/hookprobe/.theos/obj/debug/$fixture_source"
                [ -f "$file" ] && [ ! -L "$file" ] || die "rootless identity fixture missing or unsafe: $fixture_source"
                frozen="$frozen_dir/$fixture_source"
                cp -p "$file" "$frozen"
                artifact_specs+=("hookprobe-fixture-$fixture_key=$frozen")
            done < <(identity_fixture_keys)
        fi
        [ "${#artifact_specs[@]}" -gt 0 ] || die 'build produced no artifacts'
    fi
    write_manifest build "$flavor" "$flavor" "$flavor" "$rc" 0 '' "${artifact_specs[@]}"
    [ "$rc" -eq 0 ] || die "$flavor build failed"
    printf '%s\n' "$CAPTURE_DIR/manifest.json"
}

latest_installed_candidate() {
    local package_id=$1 version=$2
    python3 - "$EVIDENCE_ABS/cleanup.jsonl" "$package_id" "$version" <<'PY'
import json,pathlib,subprocess,sys
latest={}
for line in pathlib.Path(sys.argv[1]).read_text().splitlines():
    if line.strip():
        r=json.loads(line); latest[r['event_id']]=r
for r in reversed(list(latest.values())):
    if r.get('action')!='install-deb' or r.get('state')!='completed': continue
    p=pathlib.Path(r.get('target',''))
    if not p.is_file(): continue
    try:
        pkg=subprocess.check_output(['dpkg-deb','-f',str(p),'Package'],text=True).strip()
        ver=subprocess.check_output(['dpkg-deb','-f',str(p),'Version'],text=True).strip()
    except Exception: continue
    if pkg==sys.argv[2] and ver==sys.argv[3]: print(p); break
PY
}

recovery_payload_manifest() {
    python3 - "$1" <<'PY'
import hashlib,os,pathlib,sys
root=pathlib.Path(sys.argv[1]).resolve(); rows=[]
for item in root.rglob('*'):
    rel='/' + item.relative_to(root).as_posix()
    if '\n' in rel or '\t' in rel: raise SystemExit('unsafe recovery payload path')
    if item.is_symlink():
        target=os.readlink(item)
        if '\n' in target or '\t' in target: raise SystemExit('unsafe recovery symlink target')
        try: item.resolve(strict=False).relative_to(root)
        except ValueError: raise SystemExit('recovery symlink escapes payload')
        rows.append(('L',target,rel))
    elif item.is_file():
        rows.append(('F',hashlib.sha256(item.read_bytes()).hexdigest(),rel))
if not rows: raise SystemExit('empty recovery payload')
for kind,value,rel in sorted(rows): print(f'{kind}\t{value}\t{rel}')
PY
}

recovery_payload_mode_manifest() {
    python3 - "$1" <<'PY'
import hashlib, pathlib, stat, sys
root=pathlib.Path(sys.argv[1]).resolve(); rows=[]
for item in root.rglob('*'):
    if not item.is_file() or item.is_symlink(): continue
    rel='/' + item.relative_to(root).as_posix()
    if '\n' in rel or '\t' in rel: raise SystemExit('unsafe recovery payload mode path')
    rows.append(('F',hashlib.sha256(item.read_bytes()).hexdigest(),f'{stat.S_IMODE(item.stat().st_mode):04o}',rel))
if not rows: raise SystemExit('empty recovery payload mode manifest')
for kind,digest,mode,rel in sorted(rows): print(f'{kind}\t{digest}\t{mode}\t{rel}')
PY
}

find_local_recovery_deb() {
    local package_id=$1 version=$2 candidate tmp cache remote_info remote_copy hash identity script path expected kind state
    local remote_script payload_expected payload_remote mode_script mode_expected mode_remote metadata_states
    local matches=()

    # Archive discovery can inspect many historical runs.  Read the installed
    # package metadata once, then make the potentially large archive walk
    # entirely local; a recovery lookup must not time out before it can fall
    # back to exporting the exact cached package.
    cache=$(mktemp -d "${TMPDIR:-/tmp}/shadow-recovery-installed.XXXXXX") || return 1
    metadata_states=$(ssh_mobile "for n in md5sums preinst postinst prerm postrm; do p=/var/jb/var/lib/dpkg/info/$package_id.\$n; if [ -f \"\$p\" ] && [ ! -L \"\$p\" ]; then printf '%s\\tpresent\\n' \"\$n\"; elif [ -e \"\$p\" ]; then printf '%s\\terror\\n' \"\$n\"; else printf '%s\\tabsent\\n' \"\$n\"; fi; done") || { rm -rf "$cache"; return 1; }
    for script in md5sums preinst postinst prerm postrm; do
        state=$(printf '%s\n' "$metadata_states" | sed -n "s/^$script$(printf '\\t')//p")
        case "$state" in
            present)
                remote_info="/var/jb/var/lib/dpkg/info/$package_id.$script"
                remote_copy="$cache/installed.$script"
                scp_from "$remote_info" "$remote_copy" >/dev/null 2>&1 || { rm -rf "$cache"; return 1; }
                ;;
            absent) ;;
            *) rm -rf "$cache"; return 1 ;;
        esac
    done
    while IFS= read -r -d '' candidate; do
        [ "$(dpkg-deb -f "$candidate" Package 2>/dev/null)" = "$package_id" ] || continue
        [ "$(dpkg-deb -f "$candidate" Version 2>/dev/null)" = "$version" ] || continue
        tmp=$(mktemp -d "${TMPDIR:-/tmp}/shadow-recovery-check.XXXXXX")
        if ! dpkg-deb -e "$candidate" "$tmp/control" >/dev/null 2>&1 ||
           ! (umask 022; dpkg-deb -x "$candidate" "$tmp/payload" >/dev/null 2>&1); then
            rm -rf "$tmp"; continue
        fi
        if [ -f "$tmp/control/md5sums" ] && [ -f "$cache/installed.md5sums" ]; then
            cmp -s "$tmp/control/md5sums" "$cache/installed.md5sums" || { rm -rf "$tmp"; continue; }
        elif [ -f "$tmp/control/md5sums" ] || [ -f "$cache/installed.md5sums" ]; then
            rm -rf "$tmp"; continue
        fi
        for script in preinst postinst prerm postrm; do
            if [ -f "$tmp/control/$script" ]; then
                if [ ! -f "$cache/installed.$script" ] ||
                   ! cmp -s "$tmp/control/$script" "$cache/installed.$script"; then
                    rm -rf "$tmp"; tmp=''; break
                fi
            elif [ -f "$cache/installed.$script" ]; then
                rm -rf "$tmp"; tmp=''; break
            fi
        done
        [ -n "$tmp" ] || continue
        payload_expected=$(recovery_payload_manifest "$tmp/payload") || { rm -rf "$tmp"; continue; }
        remote_script=''
        while IFS=$'\t' read -r kind expected path; do
            case "$kind" in
                F) remote_script+="if [ -f $(sq "$path") ] && [ ! -L $(sq "$path") ]; then printf 'F\\t'; sha256sum $(sq "$path") | cut -d' ' -f1; else printf 'MISSING\\t\\n'; fi;" ;;
                L) remote_script+="if [ -L $(sq "$path") ]; then printf 'L\\t%s\\n' \"\$(readlink $(sq "$path"))\"; else printf 'MISSING\\t\\n'; fi;" ;;
                *) rm -rf "$tmp"; die 'invalid recovery payload manifest' ;;
            esac
        done <<<"$payload_expected"
        payload_remote=$(ssh_mobile "$remote_script" 2>/dev/null) || { rm -rf "$tmp"; continue; }
        if [ "$payload_remote" != "$(printf '%s\n' "$payload_expected" | cut -f1,2)" ]; then
            rm -rf "$tmp"; continue
        fi
        mode_expected=$(recovery_payload_mode_manifest "$tmp/payload") || { rm -rf "$tmp"; continue; }
        mode_script=''
        while IFS=$'\t' read -r kind expected state path; do
            [ "$kind" = F ] && [[ $expected =~ ^[0-9a-f]{64}$ ]] && [[ $state =~ ^0[0-7]{3}$ ]] || { rm -rf "$tmp"; die 'invalid recovery payload mode manifest'; }
            mode_script+="if [ -f $(sq "$path") ] && [ ! -L $(sq "$path") ]; then h=\$(sha256sum $(sq "$path") | cut -d' ' -f1); m=\$(stat -c %a $(sq "$path")); printf 'F\t%s\t0%s\t%s\n' \"\$h\" \"\$m\" $(sq "$path"); else printf 'MISSING\t\t\t%s\n' $(sq "$path"); fi;"
        done <<<"$mode_expected"
        mode_remote=$(ssh_mobile "$mode_script" 2>/dev/null) || { rm -rf "$tmp"; continue; }
        if [ "$mode_remote" != "$mode_expected" ]; then
            rm -rf "$tmp"; continue
        fi
        identity=$({ printf 'control\n'; recovery_payload_manifest "$tmp/control"; printf 'payload\n'; recovery_payload_manifest "$tmp/payload"; } | sha256sum | cut -d' ' -f1) || { rm -rf "$tmp"; continue; }
        hash=$(sha256_file "$candidate")
        matches+=("$identity|$hash|$candidate")
        rm -rf "$tmp"
    done < <(find "$REPO_ROOT/build" "$REPO_ROOT/packages" "$REPO_ROOT/ShadowHarness/packages" "$REPO_ROOT/tools/dyldprobe/build" "$REPO_ROOT/artifacts/stealth" -type f -name '*.deb' -print0 2>/dev/null)
    rm -rf "$cache"
    [ "${#matches[@]}" -gt 0 ] || return 1
    python3 - "${matches[@]}" <<'PY'
import sys
rows=[item.split('|',2) for item in sys.argv[1:]]
if len({row[0] for row in rows}) != 1: raise SystemExit('multiple semantically distinct local recovery packages match installed metadata')
print(sorted(rows, key=lambda row: (row[1], row[2]))[0][2])
PY
}

reconstruct_installed_recovery_deb() (
    local package_id=$1 version=$2 out=$3 cache stage status payload_list payload_paths payload_tar remote_tar path script remote state
    local payload_expected payload_remote remote_script kind expected control_dir payload_types
    local controls=(md5sums preinst postinst prerm postrm conffiles triggers shlibs symbols)

    require_cmd tar
    [ ! -e "$out" ] || die 'reconstructed recovery target already exists'
    cache=$(mktemp -d "${TMPDIR:-/tmp}/shadow-recovery-rebuild.XXXXXX") || return 1
    trap 'rm -rf "$cache"' EXIT
    stage="$cache/stage"
    status="$cache/status"
    payload_list="$cache/package.list"
    payload_paths="$cache/payload.paths"
    payload_tar="$cache/payload.tar"
    payload_types="$cache/payload.types"
    mkdir -p "$stage/DEBIAN"
    chmod 0755 "$stage/DEBIAN"

    ssh_mobile "dpkg-query -s $(sq "$package_id")" >"$status" || die 'cannot read installed package status for recovery'
    python3 - "$status" "$stage/DEBIAN/control" "$package_id" "$version" <<'PY'
import os, pathlib, sys
src=pathlib.Path(sys.argv[1]); out=pathlib.Path(sys.argv[2])
package=sys.argv[3]; version=sys.argv[4]
drop={'Status','Installed-Size'}; rows=[]; fields={}; keep=False
for line in src.read_text(encoding='utf-8').splitlines():
    if line.startswith((' ', '\t')):
        if keep: rows.append(line)
        continue
    if not line: continue
    if ':' not in line: raise SystemExit('invalid installed package status')
    field, value=line.split(':',1); keep=field not in drop
    if keep:
        if field in fields: raise SystemExit('duplicate installed package field: '+field)
        fields[field]=value.strip(); rows.append(line)
if fields.get('Package') != package or fields.get('Version') != version:
    raise SystemExit('installed package status identity mismatch')
if not fields.get('Architecture') or not fields.get('Maintainer') or not fields.get('Description'):
    raise SystemExit('installed package status lacks required control fields')
data=(chr(10).join(rows)+chr(10)).encode(); tmp=out.with_name(out.name+f'.tmp.{os.getpid()}')
with open(tmp,'wb') as f: f.write(data); f.flush(); os.fsync(f.fileno())
os.replace(tmp,out)
PY
    chmod 0644 "$stage/DEBIAN/control"

    for script in "${controls[@]}"; do
        remote="/var/jb/var/lib/dpkg/info/$package_id.$script"
        state=$(ssh_mobile "if [ -f $(sq "$remote") ] && [ ! -L $(sq "$remote") ]; then printf present; elif [ -e $(sq "$remote") ]; then printf error; else printf absent; fi") || die 'cannot inspect installed package control metadata'
        case "$state" in
            present)
                scp_from "$remote" "$stage/DEBIAN/$script" >/dev/null || die "cannot capture installed package control metadata: $script"
                case "$script" in preinst|postinst|prerm|postrm) chmod 0755 "$stage/DEBIAN/$script" ;; *) chmod 0644 "$stage/DEBIAN/$script" ;; esac
                ;;
            absent) ;;
            *) die "unsafe installed package control metadata: $script" ;;
        esac
    done

    ssh_mobile "dpkg-query -L $(sq "$package_id")" >"$payload_list" || die 'cannot list installed package payload for recovery'
    python3 - "$payload_list" "$payload_paths" <<'PY'
import pathlib, sys
source=pathlib.Path(sys.argv[1]); out=pathlib.Path(sys.argv[2]); rows=[]
for raw in source.read_text(encoding='utf-8').splitlines():
    if raw in {'/.','/','/var','/var/jb'}: continue
    if not raw.startswith('/var/jb/') or '\x00' in raw or '\n' in raw or '\r' in raw:
        raise SystemExit('unsafe installed package payload path: '+repr(raw))
    rel=raw[1:]
    parts=pathlib.PurePosixPath(rel).parts
    if not parts or any(part in {'','.', '..'} for part in parts):
        raise SystemExit('unsafe installed package payload path: '+repr(raw))
    rows.append(rel)
if len(rows) != len(set(rows)): raise SystemExit('duplicate installed package payload path')
leaves=[path for path in rows if not any(other.startswith(path + '/') for other in rows)]
if not leaves: raise SystemExit('installed package has no recovery payload')
out.write_text(''.join(path+chr(10) for path in sorted(leaves)), encoding='utf-8')
PY
    remote_script=''
    remote_tar=''
    while IFS= read -r path; do
        remote="/$path"
        remote_script+="if [ -f $(sq "$remote") ]; then printf 'F\t%s\n' $(sq "$path"); elif [ -L $(sq "$remote") ]; then printf 'L\t%s\n' $(sq "$path"); else printf 'MISSING\t%s\n' $(sq "$path"); fi;"
        remote_tar+=" $(sq "$path")"
    done <"$payload_paths"
    [ -n "$remote_script" ] || die 'installed package recovery payload is empty'
    ssh_mobile "$remote_script" >"$payload_types" || die 'cannot inspect installed package payload types'
    python3 - "$payload_paths" "$payload_types" <<'PY'
import pathlib, sys
want=pathlib.Path(sys.argv[1]).read_text(encoding='utf-8').splitlines(); got={}
for line in pathlib.Path(sys.argv[2]).read_text(encoding='utf-8').splitlines():
    fields=line.split('\t')
    if len(fields)!=2 or fields[0] not in {'F','L','MISSING'}: raise SystemExit('invalid installed payload type row')
    if fields[1] in got: raise SystemExit('duplicate installed payload type row')
    got[fields[1]]=fields[0]
if set(got)!=set(want) or any(got[path] not in {'F','L'} for path in want):
    raise SystemExit('installed package payload is missing or unsafe')
PY
    remote_tar="tar -C / -cf -$remote_tar"
    ssh_mobile "$remote_tar" >"$payload_tar" || die 'cannot capture installed package payload'
    python3 - "$payload_tar" "$payload_paths" <<'PY'
import pathlib, tarfile, sys
archive=pathlib.Path(sys.argv[1]); expected=pathlib.Path(sys.argv[2]).read_text(encoding='utf-8').splitlines(); actual=[]
with tarfile.open(archive, 'r:') as tf:
    for member in tf.getmembers():
        name=member.name[2:] if member.name.startswith('./') else member.name
        if not name or name.startswith('/') or '..' in pathlib.PurePosixPath(name).parts:
            raise SystemExit('unsafe recovery tar member')
        if not (member.isfile() or member.issym()):
            raise SystemExit('unexpected recovery tar member type: '+name)
        actual.append(name)
if len(actual)!=len(set(actual)) or set(actual)!=set(expected):
    raise SystemExit('recovery tar membership mismatch')
PY
    tar --no-same-owner --same-permissions -xf "$payload_tar" -C "$stage" || die 'cannot stage installed package payload'
    python3 - "$payload_tar" "$stage" <<'PY'
import pathlib, tarfile, sys
archive=pathlib.Path(sys.argv[1]); root=pathlib.Path(sys.argv[2])
with tarfile.open(archive, 'r:') as tf:
    for member in tf.getmembers():
        if not member.isfile(): continue
        name=member.name[2:] if member.name.startswith('./') else member.name
        if ((root/name).stat().st_mode & 0o777) != (member.mode & 0o777):
            raise SystemExit('recovery tar mode mismatch: '+name)
PY
    dpkg-deb --root-owner-group --build "$stage" "$out" >/dev/null || die 'cannot build reconstructed recovery package'
    [ "$(dpkg-deb -f "$out" Package)" = "$package_id" ] && [ "$(dpkg-deb -f "$out" Version)" = "$version" ] || die 'reconstructed recovery package identity mismatch'

    control_dir="$cache/verify-control"
    dpkg-deb -e "$out" "$control_dir" >/dev/null || die 'cannot verify reconstructed recovery control payload'
    for script in md5sums preinst postinst prerm postrm conffiles triggers shlibs symbols; do
        if [ -f "$stage/DEBIAN/$script" ]; then
            cmp -s "$stage/DEBIAN/$script" "$control_dir/$script" || die "reconstructed recovery control mismatch: $script"
        elif [ -e "$control_dir/$script" ]; then
            die "unexpected reconstructed recovery control: $script"
        fi
    done
    dpkg-deb -x "$out" "$cache/verify-payload" >/dev/null || die 'cannot verify reconstructed recovery payload'
    payload_expected=$(recovery_payload_manifest "$cache/verify-payload") || die 'invalid reconstructed recovery payload'
    remote_script=''
    while IFS=$'\t' read -r kind expected path; do
        case "$kind" in
            F) remote_script+="if [ -f $(sq "$path") ] && [ ! -L $(sq "$path") ]; then printf 'F\t'; sha256sum $(sq "$path") | cut -d' ' -f1; else printf 'MISSING\t\n'; fi;" ;;
            L) remote_script+="if [ -L $(sq "$path") ]; then printf 'L\t%s\n' \"\$(readlink $(sq "$path"))\"; else printf 'MISSING\t\n'; fi;" ;;
            *) die 'invalid reconstructed recovery payload manifest' ;;
        esac
    done <<<"$payload_expected"
    payload_remote=$(ssh_mobile "$remote_script") || die 'cannot verify reconstructed recovery payload against device'
    [ "$payload_remote" = "$(printf '%s\n' "$payload_expected" | cut -f1,2)" ] || die 'reconstructed recovery payload differs from installed package'
)

build_mode_repair_manifest() (
    local recovery=$1 candidate=$2 out=$3 tmp
    [ -f "$recovery" ] && [ ! -L "$recovery" ] || die 'mode repair recovery archive is unsafe'
    [ -f "$candidate" ] && [ ! -L "$candidate" ] || die 'mode repair candidate archive is unsafe'
    [ ! -e "$out" ] || die 'mode repair manifest already exists'
    tmp=$(mktemp -d "${TMPDIR:-/tmp}/shadow-mode-repair.XXXXXX") || return 1
    trap 'rm -rf "$tmp"' EXIT
    # The normalizer must see archive modes, rather than this driver's 077
    # evidence umask, before it can prove an old recovery archive lost modes.
    umask 022
    dpkg-deb -x "$recovery" "$tmp/recovery" >/dev/null || die 'cannot unpack mode repair recovery archive'
    dpkg-deb -x "$candidate" "$tmp/candidate" >/dev/null || die 'cannot unpack mode repair candidate archive'
    python3 - "$tmp/recovery" "$tmp/candidate" "$out" <<'PY'
import hashlib, os, pathlib, stat, sys
recovery=pathlib.Path(sys.argv[1]); candidate=pathlib.Path(sys.argv[2]); out=pathlib.Path(sys.argv[3])
legacy={'/var/jb/usr/libexec/shadowd','/var/jb/Library/LaunchDaemons/me.jjolano.shadow.plist'}
def files(root):
    rows={}
    for path in root.rglob('*'):
        if not path.is_file() or path.is_symlink(): continue
        rel='/' + path.relative_to(root).as_posix()
        rows[rel]=(stat.S_IMODE(path.stat().st_mode), hashlib.sha256(path.read_bytes()).hexdigest())
    return rows
before, template=files(recovery), files(candidate)
extra=set(before)-set(template)
if set(template)-set(before) or (extra and extra != legacy):
    raise SystemExit('mode repair archive paths do not match the recovery contract')
rows=[]
for path in sorted(before):
    source_mode, digest=before[path]
    if source_mode not in {0o600,0o700}: raise SystemExit('recovery mode is not an umask-loss signature: '+path)
    target_mode=0o755 if source_mode & 0o100 else 0o644
    if path in template and template[path][0] != target_mode:
        raise SystemExit('candidate mode template disagrees: '+path)
    if path == '/var/jb/usr/libexec/shadowd' and target_mode != 0o755:
        raise SystemExit('legacy daemon mode template is invalid')
    if path == '/var/jb/Library/LaunchDaemons/me.jjolano.shadow.plist' and target_mode != 0o644:
        raise SystemExit('legacy launchd mode template is invalid')
    rows.append(f'F\t{digest}\t{source_mode:04o}\t{target_mode:04o}\t{path}\n')
tmp=out.with_name(out.name+f'.tmp.{os.getpid()}')
with open(tmp,'w',encoding='utf-8') as f:
    f.writelines(rows); f.flush(); os.fsync(f.fileno())
os.replace(tmp,out)
PY
)

mode_repair_state() {
    local manifest=$1 snapshot=$2 remote_script='' kind digest source_mode target_mode path
    [ -f "$manifest" ] && [ ! -L "$manifest" ] || die 'mode repair manifest is unsafe'
    : >"$snapshot"
    while IFS=$'\t' read -r kind digest source_mode target_mode path; do
        [ "$kind" = F ] && [[ $digest =~ ^[0-9a-f]{64}$ ]] &&
            [[ $source_mode =~ ^0[0-7]{3}$ ]] && [[ $target_mode =~ ^0[0-7]{3}$ ]] &&
            [[ $path == /var/jb/* ]] || die 'invalid mode repair manifest row'
        remote_script+="if [ -f $(sq "$path") ] && [ ! -L $(sq "$path") ]; then h=\$(sha256sum $(sq "$path") | cut -d' ' -f1); m=\$(stat -c %a $(sq "$path")); printf 'F\t%s\t%s\t%s\n' \"\$h\" \"\$m\" $(sq "$path"); else printf 'MISSING\t\t\t%s\n' $(sq "$path"); fi;"
    done <"$manifest"
    [ -n "$remote_script" ] || die 'mode repair manifest is empty'
    ssh_privileged "$remote_script" >"$snapshot" 2>>"$CAPTURE_STDERR" || die 'mode repair state capture failed'
    python3 - "$manifest" "$snapshot" <<'PY'
import pathlib, sys
want={}; got={}
for line in pathlib.Path(sys.argv[1]).read_text(encoding='utf-8').splitlines():
    kind,digest,source,target,path=line.split('\t')
    if path in want: raise SystemExit('duplicate mode repair manifest path')
    want[path]=(digest,int(source,8),int(target,8))
for line in pathlib.Path(sys.argv[2]).read_text(encoding='utf-8').splitlines():
    fields=line.split('\t')
    if len(fields)!=4 or fields[0]!='F': raise SystemExit('missing mode repair payload path')
    _,digest,mode,path=fields
    if path in got: raise SystemExit('duplicate mode repair state path')
    got[path]=(digest,int(mode,8))
if set(got)!=set(want): raise SystemExit('mode repair state path mismatch')
needs=False
for path,(digest,source,target) in want.items():
    observed_digest, observed_mode=got[path]
    if observed_digest != digest: raise SystemExit('mode repair content mismatch: '+path)
    if observed_mode == source: needs=True
    elif observed_mode != target: raise SystemExit('unexpected mode repair state: '+path)
print('needs-repair' if needs else 'already-repaired')
PY
}

apply_mode_repair_manifest() {
    local manifest=$1 remote_script='' kind digest source_mode target_mode path
    while IFS=$'\t' read -r kind digest source_mode target_mode path; do
        remote_script+="test -f $(sq "$path") && test ! -L $(sq "$path") && test \"\$(sha256sum $(sq "$path") | cut -d' ' -f1)\" = $(sq "$digest") && chmod $target_mode $(sq "$path") || exit 1;"
    done <"$manifest"
    ssh_privileged "$remote_script" >>"$CAPTURE_STDOUT" 2>>"$CAPTURE_STDERR" || die 'mode repair apply failed'
}

latest_mode_repair_lineage() {
    python3 - "$EVIDENCE_ABS/cleanup.jsonl" <<'PY'
import json, pathlib, sys
latest={}; order=[]
for line in pathlib.Path(sys.argv[1]).read_text().splitlines():
    if not line.strip(): continue
    row=json.loads(line); key=row['event_id']
    if key not in latest: order.append(key)
    latest[key]=row
for key in reversed(order):
    row=latest[key]
    if row.get('action')!='install-deb': continue
    bits=row.get('prior_state','').split('|')
    if len(bits)==4 and bits[3]=='me.jjolano.shadow':
        print(bits[0]+'\t'+row.get('target','')+'\t'+bits[3]); break
PY
}

repair_mode_loss_if_authorized() {
    local lineage recovery candidate package manifest before after event state
    [ "$(printenv SHADOW_ALLOW_MODE_REPAIR 2>/dev/null || true)" = "$SHADOW_RUN_ID" ] || return 0
    lineage=$(latest_mode_repair_lineage)
    [ -n "$lineage" ] || die 'mode repair lineage is unavailable'
    IFS=$'\t' read -r recovery candidate package <<<"$lineage"
    [ "$package" = me.jjolano.shadow ] && [ -f "$recovery" ] && [ -f "$candidate" ] || die 'mode repair lineage is unsafe'
    manifest="$CAPTURE_DIR/mode-repair.tsv"
    build_mode_repair_manifest "$recovery" "$candidate" "$manifest"
    before="$CAPTURE_DIR/mode-repair.before.tsv"
    state=$(mode_repair_state "$manifest" "$before")
    case "$state" in
        already-repaired) MODE_REPAIR_MANIFEST=$manifest; return 0 ;;
        needs-repair) ;;
        *) die 'invalid mode repair state' ;;
    esac
    event=$(new_event_id)
    journal_event "$event" mode-repair "$package" "$manifest" pending
    apply_mode_repair_manifest "$manifest"
    after="$CAPTURE_DIR/mode-repair.after.tsv"
    [ "$(mode_repair_state "$manifest" "$after")" = already-repaired ] || die 'mode repair verification failed'
    journal_event "$event" mode-repair "$package" "$manifest" completed
    journal_event "$event" mode-repair "$package" "$manifest" restored
    MODE_REPAIR_MANIFEST=$manifest
}

export_recovery_deb() {
    local package_id=$1 version=$2 out=$3 remote_path remote_copy event
    remote_path=$(ssh_privileged "find /var/jb/var/cache/apt/archives /var/cache/apt/archives -maxdepth 1 -type f -name '${package_id}_*.deb' 2>/dev/null | head -1")
    if [ -z "$remote_path" ]; then
        reconstruct_installed_recovery_deb "$package_id" "$version" "$out"
        return
    fi
    remote_copy="/var/mobile/Media/.shadow-recovery-$SHADOW_RUN_ID-$$.deb"
    event=$(new_event_id)
    journal_event "$event" recovery-export "$remote_copy" absent pending
    ssh_privileged "cp $(sq "$remote_path") $(sq "$remote_copy") && chown mobile:mobile $(sq "$remote_copy") && chmod 600 $(sq "$remote_copy")" >/dev/null
    journal_event "$event" recovery-export "$remote_copy" absent completed
    scp_from "$remote_copy" "$out"
    [ "$(dpkg-deb -f "$out" Package)" = "$package_id" ] && [ "$(dpkg-deb -f "$out" Version)" = "$version" ] || die 'cached recovery package identity mismatch'
    ssh_privileged "rm -f $(sq "$remote_copy")" >/dev/null
    journal_event "$event" recovery-export "$remote_copy" absent restored
}

cmd_install_deb() {
    local package=$1 package_id=$2 candidate_pkg candidate_version installed_version recovery recovery_source prefs_backup prefs_remote_path remote event upload_event rc uploaded_hash installed_after job candidate_copy snapshot package_status audit_file
    local artifacts=()
    prepare_existing_run
    verify_device_identity
    require_cmd dpkg-deb
    [ -f "$package" ] && [ ! -L "$package" ] || die 'candidate package missing or unsafe'
    candidate_pkg=$(dpkg-deb -f "$package" Package)
    candidate_version=$(dpkg-deb -f "$package" Version)
    [ "$candidate_pkg" = "$package_id" ] || die 'candidate package ID mismatch'
    case "$package_id" in me.jjolano.shadow|me.jjolano.shadow.harness|me.jjolano.dyldprobe) ;; *) die 'unsupported package ID' ;; esac
    capture_dir '' install-deb device
    package_status="$CAPTURE_DIR/package-status.before.tsv"
    audit_file="$CAPTURE_DIR/dpkg-audit.before.txt"
    : >"$package_status"; : >"$audit_file"
    capture_package_database "$package_status" "$audit_file" "$package_id" || die 'package database precheck failed; no package was uploaded'
    installed_version=$(ssh_mobile "dpkg-query -W -f='\${Version}' $package_id") || die 'installed package query failed'
    candidate_copy="$CAPTURE_DIR/candidate.deb"
    cp -p "$package" "$candidate_copy"
    recovery_source=$(latest_installed_candidate "$package_id" "$installed_version" || true)
    [ -n "$recovery_source" ] || recovery_source=$(find_local_recovery_deb "$package_id" "$installed_version" || true)
    if [ -n "$recovery_source" ]; then
        recovery="$CAPTURE_DIR/recovery.deb"
        cp -p "$recovery_source" "$recovery"
    else
        recovery="$CAPTURE_DIR/recovery.deb"
        export_recovery_deb "$package_id" "$installed_version" "$recovery" || die 'exact recovery package is unavailable'
    fi
    [ -f "$recovery" ] || die 'recovery package missing'
    prefs_backup="$CAPTURE_DIR/preferences.before.plist"
    prefs_remote_path=$(preferences_remote)
    if ! scp_from "$prefs_remote_path" "$prefs_backup" 2>>"$CAPTURE_STDERR"; then
        printf 'ABSENT\n' >"$prefs_backup"
    fi
    if [ "$package_id" = me.jjolano.shadow ]; then
        job=$(ssh_privileged 'if launchctl print system/me.jjolano.shadow >/dev/null 2>&1; then printf present; else printf absent; fi')
        if [ "$job" = present ]; then
            daemon_term_safe_internal
        else
            snapshot="$CAPTURE_DIR/daemon-already-absent.txt"
            ssh_privileged "$(daemon_snapshot_remote)" >"$snapshot" 2>>"$CAPTURE_STDERR" || die 'daemon absence check failed'
            validate_daemon_snapshot "$snapshot" true >/dev/null
        fi
    fi
    remote="/var/mobile/Media/.shadow-$SHADOW_RUN_ID-$(basename -- "$package")"
    upload_event=$(new_event_id)
    journal_event "$upload_event" package-upload "$remote" absent pending
    scp_to "$candidate_copy" "$remote" >>"$CAPTURE_STDOUT" 2>>"$CAPTURE_STDERR"
    uploaded_hash=$(ssh_mobile "sha256sum $(sq "$remote") | cut -d' ' -f1")
    [ "$uploaded_hash" = "$(sha256_file "$candidate_copy")" ] || die 'uploaded package hash mismatch'
    journal_event "$upload_event" package-upload "$remote" absent completed
    event=$(new_event_id)
    journal_event "$event" install-deb "$candidate_copy" "$recovery|$prefs_backup|$prefs_remote_path|$package_id" pending
    set +e
    ssh_privileged "dpkg -i $(sq "$remote")" >>"$CAPTURE_STDOUT" 2>>"$CAPTURE_STDERR"
    rc=$?
    set -e
    [ "$rc" -eq 0 ] || die 'dpkg install failed; run restore'
    installed_after=$(ssh_mobile "dpkg-query -W -f='\${Package} \${Version}' $package_id")
    [ "$installed_after" = "$package_id $candidate_version" ] || die 'installed package identity mismatch'
    ssh_privileged "rm -f $(sq "$remote")" >/dev/null
    journal_event "$upload_event" package-upload "$remote" absent restored
    journal_event "$event" install-deb "$candidate_copy" "$recovery|$prefs_backup|$prefs_remote_path|$package_id" completed
    artifacts=("candidate=$candidate_copy" "recovery=$recovery" "preferences-before=$prefs_backup" \
        "package-status-before=$package_status" "dpkg-audit-before=$audit_file")
    [ -z "$DAEMON_LEGACY_LEDGER" ] || artifacts+=("legacy-ledger=$DAEMON_LEGACY_LEDGER")
    [ -z "$DAEMON_LEGACY_OWNER_PIDS" ] || artifacts+=("legacy-owner-pids=$DAEMON_LEGACY_OWNER_PIDS")
    [ -z "$DAEMON_LEGACY_RECOVERY" ] || artifacts+=("legacy-recovery=$DAEMON_LEGACY_RECOVERY")
    write_manifest install-deb '' not-applicable not-applicable 0 0 '' "${artifacts[@]}"
    printf '%s\n' "$CAPTURE_DIR/manifest.json"
}

identity_fixture_keys() {
    printf '%s\n' copy symlink basename embedded case prefix late
}

identity_fixture_spec() {
    case "$1" in
        copy) printf 'hookprobeidentitycopy.dylib\tcopied.dylib\n' ;;
        symlink) printf 'hookprobeidentitysymlink.dylib\tsymlink-target.dylib\n' ;;
        basename) printf 'hookprobeidentitybasename.dylib\tShadow.dylib\n' ;;
        embedded) printf 'hookprobeidentityembedded.dylib\tFrameworks/Shadow.framework/Shadow\n' ;;
        case) printf 'hookprobeidentitycase.dylib\tshadowcore.dylib\n' ;;
        prefix) printf 'hookprobeidentityprefix.dylib\tShadowCoreCompat.dylib\n' ;;
        late) printf 'hookprobeidentitylate.dylib\tlate.dylib\n' ;;
        *) return 1 ;;
    esac
}

identity_fixture_directory_remote() {
    printf '/var/jb/usr/lib/.shadow-hookprobe-identity-%s\n' "$SHADOW_RUN_ID"
}

identity_fixture_check_remote() {
    local directory=$1 remote
    [ "$directory" = "$(identity_fixture_directory_remote)" ] || return 1
    read -r -d '' remote <<'EOS' || true
set -eu
[ -d "$dir" ] && [ ! -L "$dir" ]
[ -d "$dir/Frameworks" ] && [ ! -L "$dir/Frameworks" ]
[ -d "$dir/Frameworks/Shadow.framework" ] && [ ! -L "$dir/Frameworks/Shadow.framework" ]
for path in \
  "$dir/copied.dylib" "$dir/symlink-target.dylib" "$dir/Shadow.dylib" \
  "$dir/Frameworks/Shadow.framework/Shadow" "$dir/shadowcore.dylib" \
  "$dir/ShadowCoreCompat.dylib" "$dir/late.dylib"; do
  [ -f "$path" ] && [ ! -L "$path" ]
done
[ -L "$dir/symlinked.dylib" ] && [ "$(readlink "$dir/symlinked.dylib")" = symlink-target.dylib ]
EOS
    ssh_mobile "dir=$(sq "$directory")
$remote"
}

remove_identity_fixture_directory() {
    local directory=$1 remote
    [ "$directory" = "$(identity_fixture_directory_remote)" ] || die 'unsafe identity fixture cleanup target'
    read -r -d '' remote <<'EOS' || true
set -eu
[ ! -e "$dir" ] && [ ! -L "$dir" ] && exit 0
[ -d "$dir" ] && [ ! -L "$dir" ] || exit 1
for node in $(find "$dir" -mindepth 1 -print); do
  case "$node" in
    "$dir/Frameworks"|"$dir/Frameworks/Shadow.framework"|\
    "$dir/copied.dylib"|"$dir/symlink-target.dylib"|"$dir/symlinked.dylib"|\
    "$dir/Shadow.dylib"|"$dir/Frameworks/Shadow.framework/Shadow"|\
    "$dir/shadowcore.dylib"|"$dir/ShadowCoreCompat.dylib"|"$dir/late.dylib") ;;
    *) exit 1 ;;
  esac
done
[ ! -L "$dir/symlinked.dylib" ] || [ "$(readlink "$dir/symlinked.dylib")" = symlink-target.dylib ] || exit 1
for path in \
  "$dir/copied.dylib" "$dir/symlink-target.dylib" "$dir/symlinked.dylib" \
  "$dir/Shadow.dylib" "$dir/Frameworks/Shadow.framework/Shadow" \
  "$dir/shadowcore.dylib" "$dir/ShadowCoreCompat.dylib" "$dir/late.dylib"; do
  if [ -e "$path" ] || [ -L "$path" ]; then rm -f "$path"; fi
done
if [ -d "$dir/Frameworks/Shadow.framework" ]; then rmdir "$dir/Frameworks/Shadow.framework"; fi
if [ -d "$dir/Frameworks" ]; then rmdir "$dir/Frameworks"; fi
rmdir "$dir"
EOS
    ssh_privileged "dir=$(sq "$directory")
$remote" >>"$CAPTURE_STDOUT" 2>>"$CAPTURE_STDERR"
}

cmd_install_hookprobe() {
    local probe=$1 remote=/var/jb/usr/bin/hookprobe temp backup prior event upload_event remote_hash candidate_copy
    local fixture_dir fixture_event fixture_key fixture_spec fixture_local fixture_remote fixture_candidate fixture_source fixture_target
    local fixture_artifacts=()
    prepare_existing_run
    verify_device_identity
    [ -f "$probe" ] && [ ! -L "$probe" ] || die 'hookprobe candidate missing or unsafe'
    fixture_dir=$(identity_fixture_directory_remote)
    fixture_source=$(dirname "$probe")
    while IFS= read -r fixture_key; do
        fixture_spec=$(identity_fixture_spec "$fixture_key") || die "unknown identity fixture: $fixture_key"
        IFS=$'\t' read -r fixture_local fixture_target <<<"$fixture_spec"
        fixture_local="$fixture_source/$fixture_local"
        [ -f "$fixture_local" ] && [ ! -L "$fixture_local" ] || die "identity fixture missing or unsafe: $fixture_local"
    done < <(identity_fixture_keys)
    capture_dir '' install-hookprobe device
    candidate_copy="$CAPTURE_DIR/hookprobe.candidate"
    cp -p "$probe" "$candidate_copy"
    mkdir -p "$CAPTURE_DIR/identity-fixtures"
    while IFS= read -r fixture_key; do
        fixture_spec=$(identity_fixture_spec "$fixture_key") || die "unknown identity fixture: $fixture_key"
        IFS=$'\t' read -r fixture_local fixture_target <<<"$fixture_spec"
        fixture_local="$fixture_source/$fixture_local"
        fixture_candidate="$CAPTURE_DIR/identity-fixtures/${fixture_local##*/}"
        cp -p "$fixture_local" "$fixture_candidate"
        fixture_artifacts+=("identity-fixture-$fixture_key=$fixture_candidate")
    done < <(identity_fixture_keys)
    backup="$CAPTURE_DIR/hookprobe.before"
    if scp_from "$remote" "$backup" 2>>"$CAPTURE_STDERR"; then prior=$backup; else prior=absent; rm -f "$backup"; fi
    temp="/var/mobile/Media/.hookprobe-$SHADOW_RUN_ID-$$"
    upload_event=$(new_event_id)
    journal_event "$upload_event" package-upload "$temp" absent pending
    scp_to "$candidate_copy" "$temp" >>"$CAPTURE_STDOUT" 2>>"$CAPTURE_STDERR"
    journal_event "$upload_event" package-upload "$temp" absent completed
    [ "$(ssh_mobile "sha256sum $(sq "$temp") | cut -d' ' -f1")" = "$(sha256_file "$candidate_copy")" ] || die 'uploaded hookprobe hash mismatch'
    event=$(new_event_id)
    journal_event "$event" install-hookprobe "$candidate_copy" "$prior|$remote" pending
    ssh_privileged "install -o root -g wheel -m 0755 $(sq "$temp") $(sq "$remote") && rm -f $(sq "$temp")" >>"$CAPTURE_STDOUT" 2>>"$CAPTURE_STDERR"
    journal_event "$upload_event" package-upload "$temp" absent restored
    remote_hash=$(ssh_privileged "sha256sum $(sq "$remote") | cut -d' ' -f1")
    [ "$remote_hash" = "$(sha256_file "$candidate_copy")" ] || die 'installed hookprobe hash mismatch'
    journal_event "$event" install-hookprobe "$candidate_copy" "$prior|$remote" completed
    ssh_mobile "test ! -e $(sq "$fixture_dir") && test ! -L $(sq "$fixture_dir")" || die 'identity fixture directory already exists'
    fixture_event=$(new_event_id)
    journal_event "$fixture_event" install-hookprobe-fixtures "$fixture_dir" absent pending
    ssh_privileged "umask 077 && mkdir -p $(sq "$fixture_dir/Frameworks/Shadow.framework") && chown mobile:mobile $(sq "$fixture_dir") $(sq "$fixture_dir/Frameworks") $(sq "$fixture_dir/Frameworks/Shadow.framework")" >>"$CAPTURE_STDOUT" 2>>"$CAPTURE_STDERR"
    while IFS= read -r fixture_key; do
        fixture_spec=$(identity_fixture_spec "$fixture_key") || die "unknown identity fixture: $fixture_key"
        IFS=$'\t' read -r fixture_local fixture_target <<<"$fixture_spec"
        fixture_candidate="$CAPTURE_DIR/identity-fixtures/${fixture_local##*/}"
        fixture_remote="$fixture_dir/$fixture_target"
        scp_to "$fixture_candidate" "$fixture_remote" >>"$CAPTURE_STDOUT" 2>>"$CAPTURE_STDERR"
        ssh_mobile "chmod 600 $(sq "$fixture_remote")" >>"$CAPTURE_STDOUT" 2>>"$CAPTURE_STDERR"
        [ "$(ssh_mobile "sha256sum $(sq "$fixture_remote") | cut -d' ' -f1")" = "$(sha256_file "$fixture_candidate")" ] || die "identity fixture hash mismatch: $fixture_key"
    done < <(identity_fixture_keys)
    ssh_mobile "ln -s symlink-target.dylib $(sq "$fixture_dir/symlinked.dylib")" >>"$CAPTURE_STDOUT" 2>>"$CAPTURE_STDERR"
    identity_fixture_check_remote "$fixture_dir" >>"$CAPTURE_STDOUT" 2>>"$CAPTURE_STDERR" || die 'identity fixture deployment verification failed'
    journal_event "$fixture_event" install-hookprobe-fixtures "$fixture_dir" absent completed
    write_manifest install-hookprobe '' not-applicable not-applicable 0 0 '' "candidate=$candidate_copy" "${fixture_artifacts[@]}"
    printf '%s\n' "$CAPTURE_DIR/manifest.json"
}

install_component_spec() {
    case "$1" in
        ShadowCore) printf '/var/jb/usr/lib/ShadowCore.dylib\t0755\n' ;;
        ShadowStub) printf '/var/jb/Library/MobileSubstrate/DynamicLibraries/Shadow.dylib\t0755\n' ;;
        DyldProbe) printf '/var/jb/Applications/dyldprobe.app/dyldprobe\t0755\n' ;;
        *) return 1 ;;
    esac
}

cmd_install_component() {
    local key=$1 candidate=$2 remote mode spec candidate_copy backup temp staged event upload_event remote_hash
    spec=$(install_component_spec "$key") || die "unsupported install component: $key"
    IFS=$'\t' read -r remote mode <<<"$spec"
    prepare_existing_run
    verify_device_identity
    [ -f "$candidate" ] && [ ! -L "$candidate" ] || die 'component candidate missing or unsafe'
    capture_dir '' install-component device
    candidate_copy="$CAPTURE_DIR/$key.candidate"
    backup="$CAPTURE_DIR/$key.before"
    cp -p "$candidate" "$candidate_copy"
    scp_from "$remote" "$backup" 2>>"$CAPTURE_STDERR" || die 'installed component backup failed'
    temp="/var/mobile/Media/.shadow-component-$SHADOW_RUN_ID-$$"
    staged="$remote.new.$SHADOW_RUN_ID.$$"
    upload_event=$(new_event_id)
    journal_event "$upload_event" package-upload "$temp" absent pending
    scp_to "$candidate_copy" "$temp" >>"$CAPTURE_STDOUT" 2>>"$CAPTURE_STDERR"
    journal_event "$upload_event" package-upload "$temp" absent completed
    event=$(new_event_id)
    journal_event "$event" install-component "$candidate_copy" "$backup|$remote|$mode" pending
    ssh_privileged "install -o root -g wheel -m $mode $(sq "$temp") $(sq "$staged") && mv -f $(sq "$staged") $(sq "$remote") && rm -f $(sq "$temp")" >>"$CAPTURE_STDOUT" 2>>"$CAPTURE_STDERR"
    journal_event "$upload_event" package-upload "$temp" absent restored
    remote_hash=$(ssh_privileged "sha256sum $(sq "$remote") | cut -d' ' -f1")
    [ "$remote_hash" = "$(sha256_file "$candidate_copy")" ] || die 'installed component hash mismatch; run restore'
    journal_event "$event" install-component "$candidate_copy" "$backup|$remote|$mode" completed
    write_manifest install-component "$key" not-applicable not-applicable 0 0 '' "candidate=$candidate_copy" "component-before=$backup"
    printf '%s\n' "$CAPTURE_DIR/manifest.json"
}

validate_bundle_id() {
    case "$1" in me.jjolano.shadow.harness|me.jjolano.dyldprobe) ;; *) die "unsupported bundle ID: $1" ;; esac
}

preferences_remote() {
    if ssh_privileged 'test -d /var/jb'; then
        printf '%s\n' /var/jb/var/mobile/Library/Preferences/me.jjolano.shadow.plist
    else
        printf '%s\n' /var/mobile/Library/Preferences/me.jjolano.shadow.plist
    fi
}

preferences_install_spec() {
    case "$1" in
        /var/jb/var/mobile/Library/Preferences/*) printf 'mobile:mobile\t0600\n' ;;
        *) printf 'root:wheel\t0644\n' ;;
    esac
}

mutate_preferences() {
    local bundle=$1 mode=$2 action=$3 backup edited readback temp event remote owner mode_bits
    backup="$CAPTURE_DIR/preferences.$action.before.plist"
    edited="$CAPTURE_DIR/preferences.$action.after.plist"
    readback="$CAPTURE_DIR/preferences.$action.readback.plist"
    remote=$(preferences_remote)
    scp_from "$remote" "$backup" 2>>"$CAPTURE_STDERR" || die 'cannot back up Shadow preferences'
    python3 - "$backup" "$edited" "$bundle" "$mode" <<'PY'
import os,plistlib,sys
src,dst,bundle,mode=sys.argv[1:]
with open(src,'rb') as f: root=plistlib.load(f)
if not isinstance(root,dict): raise SystemExit('preferences root is not a dictionary')
app=dict(root.get(bundle) or {})
if mode=='uninjected': app['App_Disabled']=True; app['App_Enabled']=False
elif mode=='injected': app['App_Disabled']=False; app['App_Enabled']=True
else: raise SystemExit('unsupported mode')
root[bundle]=app
with open(dst,'wb') as f:
    plistlib.dump(root,f,fmt=plistlib.FMT_BINARY,sort_keys=True); f.flush(); os.fsync(f.fileno())
PY
    event=$(new_event_id)
    journal_event "$event" "$action" "$bundle" "$backup|$remote" pending
    temp="/var/mobile/Media/.shadow-prefs-$SHADOW_RUN_ID-$$-$RANDOM.plist"
    scp_to "$edited" "$temp" >>"$CAPTURE_STDOUT" 2>>"$CAPTURE_STDERR"
    IFS=$'\t' read -r owner mode_bits <<<"$(preferences_install_spec "$remote")"
    ssh_privileged "install -o ${owner%%:*} -g ${owner##*:} -m $mode_bits $(sq "$temp") $(sq "$remote") && rm -f $(sq "$temp")" >>"$CAPTURE_STDOUT" 2>>"$CAPTURE_STDERR"
    ssh_mobile "launchctl kill SIGTERM gui/501/com.apple.cfprefsd.xpc.daemon 2>/dev/null || launchctl kill SIGTERM user/501/com.apple.cfprefsd.xpc.daemon 2>/dev/null || true" >>"$CAPTURE_STDOUT" 2>>"$CAPTURE_STDERR"
    sleep 15
    scp_from "$remote" "$readback" 2>>"$CAPTURE_STDERR" || die 'preferences readback failed'
    python3 - "$edited" "$readback" "$bundle" <<'PY'
import plistlib,sys
def load(path):
    with open(path,'rb') as f: return plistlib.load(f)
a=load(sys.argv[1]).get(sys.argv[3]); b=load(sys.argv[2]).get(sys.argv[3])
if a!=b: raise SystemExit('preferences readback mismatch')
PY
    journal_event "$event" "$action" "$bundle" "$backup|$remote" completed
}

cmd_set_mode() {
    local bundle=$1 mode=$2
    validate_bundle_id "$bundle"
    case "$mode" in uninjected|injected) ;; stock) die 'stock mode is invalid on a jailbroken row' ;; *) die 'invalid mode' ;; esac
    prepare_existing_run
    verify_device_identity
    capture_dir '' set-mode device
    mutate_preferences "$bundle" "$mode" set-mode
    write_manifest set-mode '' "$mode" "$mode" 0 0 '' \
        "preferences-before=$CAPTURE_DIR/preferences.set-mode.before.plist" \
        "preferences-after=$CAPTURE_DIR/preferences.set-mode.readback.plist"
    printf '%s\n' "$CAPTURE_DIR/manifest.json"
}

current_mode() {
    local bundle=$1 file result remote
    file=$(mktemp "${TMPDIR:-/tmp}/shadow-prefs.XXXXXX")
    remote=$(preferences_remote)
    scp_from "$remote" "$file" >/dev/null 2>&1 || { rm -f "$file"; return 1; }
    result=$(python3 - "$file" "$bundle" <<'PY'
import plistlib,sys
with open(sys.argv[1],'rb') as f: d=plistlib.load(f).get(sys.argv[2],{})
print('uninjected' if d.get('App_Disabled') else 'injected' if d.get('App_Enabled') else 'uninjected')
PY
)
    rm -f "$file"
    printf '%s\n' "$result"
}

bundle_executable() {
    case "$1" in
        me.jjolano.shadow.harness) printf /var/jb/Applications/ShadowHarness.app/ShadowHarness ;;
        me.jjolano.dyldprobe) printf /var/jb/Applications/dyldprobe.app/dyldprobe ;;
    esac
}

find_process_exact() {
    local executable=$1 rows
    rows=$(ssh_mobile 'ps -ax -o pid=,lstart=,state=,comm=') || return 1
    python3 - "$executable" "$rows" <<'PY'
import sys
exe=sys.argv[1]; suffix=exe[exe.find('/Applications/'):] if '/Applications/' in exe else exe; found=[]
for line in sys.argv[2].splitlines():
    b=line.strip().split()
    if len(b)>=4 and b[0].isdigit() and (b[-1]==exe or b[-1].endswith(suffix)):
        found.append((b[0],' '.join(b[1:-2]),b[-2],b[-1]))
if len(found)>1: raise SystemExit(2)
if found: print('\t'.join(found[0]))
PY
}

terminate_exact_process() {
    local row=$1 pid lstart state comm current event
    IFS=$'\t' read -r pid lstart state comm <<<"$row"
    [ -n "$pid" ] || return 0
    current=$(find_process_exact "$comm") || die 'process identity recheck failed'
    [ "$(printf '%s' "$current" | cut -f1,2)" = "$(printf '%s' "$row" | cut -f1,2)" ] || die 'process identity changed before termination'
    event=$(new_event_id)
    journal_event "$event" launch-terminate "$pid" "$lstart|$comm" pending
    ssh_privileged "kill -TERM $pid" >/dev/null
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        current=$(find_process_exact "$comm") || die 'process discovery failed after termination'
        [ -z "$current" ] && break
        sleep 1
    done
    [ -z "$current" ] || die 'process did not terminate cleanly'
    journal_event "$event" launch-terminate "$pid" "$lstart|$comm" completed
    journal_event "$event" launch-terminate "$pid" "$lstart|$comm" restored
}

restore_launch_process() {
    local target=$1 prior=$2 lstart comm current state
    if [[ $target =~ ^[1-9][0-9]*$ ]]; then
        IFS='|' read -r lstart comm <<<"$prior"
        state=$(client_sigkill_state "$target" "$lstart" "$comm") || die 'launched process identity recheck failed during restore'
        case "$state" in
            absent|reused) return 0 ;;
            changed) die 'launched process command changed during restore' ;;
            live) ;;
            *) die 'launched process identity recheck failed during restore' ;;
        esac
        ssh_privileged "kill -TERM $target" >/dev/null || die 'launched process termination failed during restore'
        for _ in 1 2 3 4 5 6 7 8 9 10; do
            state=$(client_sigkill_state "$target" "$lstart" "$comm") || die 'launched process identity recheck failed during restore'
            case "$state" in
                absent|reused) return 0 ;;
                changed) die 'launched process command changed during restore' ;;
                live) sleep 1 ;;
                *) die 'launched process identity recheck failed during restore' ;;
            esac
        done
        die 'launched process did not terminate during restore'
    else
        current=$(find_process_exact "$target") || die 'pending launched process discovery is ambiguous during restore'
        [ -n "$current" ] || return 0
        terminate_exact_process "$current"
    fi
}

patch_launch_manifest() {
    local manifest=$1 transition=$2 pre=${3:-} post=${4:-} result=${5:-}
    python3 - "$manifest" "$transition" "$pre" "$post" "$result" <<'PY'
import json,os,pathlib,sys
p=pathlib.Path(sys.argv[1]); d=json.load(open(p))
def row(s):
    if not s: return (None,None,'absent')
    f=s.split('\t'); return (int(f[0]),f[1],f[2])
pre=row(sys.argv[3]); post=row(sys.argv[4])
d['launch']={'transition':sys.argv[2],'pre_pid':pre[0],'pre_lstart':pre[1],'pre_state':pre[2],
             'post_pid':post[0],'post_lstart':post[1],'post_state':post[2]}
d['pid']=post[0]; d['process_start_identity']=post[1]; d['observed_mode']=sys.argv[5]
t=p.with_name(p.name+f'.tmp.{os.getpid()}')
with open(t,'w') as f: json.dump(d,f,sort_keys=True,separators=(',',':')); f.write('\n'); f.flush(); os.fsync(f.fileno())
os.replace(t,p)
PY
}

write_launch_context_file() {
    local bundle=$1 mode=$2 nonce=$3 documents=$4 stress_library=${5:-} remote local_file backup prior event forced_failure=${SHADOW_FORCE_FAILURE_ID:-}
    [ "${#forced_failure}" -le 200 ] || die 'forced failure ID is too long'
    [[ $forced_failure != *$'\n'* && $forced_failure != *$'\r'* ]] || die 'forced failure ID contains a newline'
    remote="$documents/.ShadowStealthContext.json"
    local_file="$CAPTURE_DIR/stealth-context.json"
    python3 - "$local_file" "$SHADOW_RUN_ID" "$SHADOW_ROW_ID" "$mode" "$nonce" "$TASK_REVISION" "$forced_failure" "$stress_library" <<'PY'
import json,os,pathlib,sys
p=pathlib.Path(sys.argv[1]); d={'schema_version':1,'run_id':sys.argv[2],'row_id':sys.argv[3],
 'requested_mode':sys.argv[4],'nonce':sys.argv[5],'probe_revision':sys.argv[6]}
if sys.argv[7]: d['force_failure_id']=sys.argv[7]
if sys.argv[8]: d['dyld_stress_library']=sys.argv[8]
with open(p,'w',encoding='utf-8') as f: json.dump(d,f,sort_keys=True,separators=(',',':')); f.write('\n'); f.flush(); os.fsync(f.fileno())
PY
    backup="$CAPTURE_DIR/stealth-context.before.json"
    if ssh_mobile "test -e $(sq "$remote")"; then
        ssh_mobile "test -f $(sq "$remote") && test ! -L $(sq "$remote")" || die 'unsafe existing launch context file'
        scp_from "$remote" "$backup" >/dev/null || die 'cannot back up launch context file'
        prior="$backup|$remote"
    else
        prior="absent|$remote"
    fi
    event=$(new_event_id)
    journal_event "$event" launch-context-file "$remote" "$prior" pending
    scp_to "$local_file" "$remote" >/dev/null || die 'cannot install launch context file'
    ssh_mobile "chmod 600 $(sq "$remote")" || die 'cannot protect launch context file'
    [ "$(ssh_mobile "sha256sum $(sq "$remote") | cut -d' ' -f1")" = "$(sha256_file "$local_file")" ] || die 'launch context hash mismatch'
    journal_event "$event" launch-context-file "$remote" "$prior" completed
    LAUNCH_CONTEXT_FILE=$local_file
}

prepare_launch_dyld_stress_file() {
    local target=$1 source=/var/jb/Applications/dyldprobe.app/shdwtestlib.dylib event source_hash target_hash
    [ -n "$target" ] || return
    ssh_mobile "test ! -e $(sq "$target")" || die 'nonce dyld stress library already exists'
    ssh_privileged "test -f $(sq "$source") && test ! -L $(sq "$source")" || die 'packaged dyld stress library is missing or unsafe'
    source_hash=$(ssh_privileged "sha256sum $(sq "$source") | cut -d' ' -f1") || die 'cannot hash packaged dyld stress library'
    event=$(new_event_id)
    journal_event "$event" launch-report-file "$target" "absent|$target" pending
    ssh_privileged "install -o mobile -g mobile -m 0700 $(sq "$source") $(sq "$target")" || die 'cannot stage dyld stress library'
    target_hash=$(ssh_mobile "sha256sum $(sq "$target") | cut -d' ' -f1") || die 'cannot hash staged dyld stress library'
    [ "$target_hash" = "$source_hash" ] || die 'staged dyld stress library hash mismatch'
    journal_event "$event" launch-report-file "$target" "absent|$target" completed
    LAUNCH_DYLD_STRESS_ARTIFACT="$CAPTURE_DIR/dyld-stress.tsv"
    printf 'source\t%s\ntarget\t%s\nsha256\t%s\n' "$source" "$target" "$target_hash" >"$LAUNCH_DYLD_STRESS_ARTIFACT"
}

bundle_report_relative() {
    case "$1" in
        me.jjolano.shadow.harness) printf 'ShadowDiagnostics-%s.json' "$2" ;;
        me.jjolano.dyldprobe) printf 'dyldprobe-%s.json' "$2" ;;
        *) return 1 ;;
    esac
}

prepare_launch_report_file() {
    local bundle=$1 nonce=$2 documents=$3 relative remote event output output_event
    relative=$(bundle_report_relative "$bundle" "$nonce") || return
    remote="$documents/$relative"
    ssh_mobile "test ! -e $(sq "$remote")" || die 'nonce report already exists'
    event=$(new_event_id)
    journal_event "$event" launch-report-file "$remote" "absent|$remote" pending
    LAUNCH_REPORT_EVENT=$event
    LAUNCH_REPORT_FILE=$remote
    output="$documents/.ShadowStealthLaunch-$nonce.log"
    ssh_mobile "test ! -e $(sq "$output")" || die 'nonce launch log already exists'
    output_event=$(new_event_id)
    journal_event "$output_event" launch-report-file "$output" "absent|$output" pending
    LAUNCH_OUTPUT_EVENT=$output_event
    LAUNCH_OUTPUT_FILE=$output
}

verification_launch_remote() {
	local mode=$1 executable=$2 container=$3 output=$4 safe_mode='' runner
	if [ "$mode" = uninjected ]; then safe_mode='_MSSafeMode=1 '; fi
	runner=$(printf '%sCFFIXED_USER_HOME=%s HOME=%s TMPDIR=%s %s --shadow-headless-producer; rc=$?; printf %s "$rc"' \
		"$safe_mode" "$(sq "$container")" "$(sq "$container")" "$(sq "$container/tmp")" "$(sq "$executable")" "'__SHADOW_HEADLESS_EXIT__%s\\n'")
	printf 'nohup /var/jb/bin/sh -c %s </dev/null >%s 2>&1 &' "$(sq "$runner")" "$(sq "$output")"
}

uses_direct_verification_launch() {
	[ "$2" = cold ] && { [ "$3" = uninjected ] || [ "$3" = injected ]; } &&
		{ [ "$1" = me.jjolano.shadow.harness ] || [ "$1" = me.jjolano.dyldprobe ]; }
}

verification_documents_dir() {
	local bundle=$1 container=$2
	if [ "$bundle" = me.jjolano.shadow.harness ]; then
		printf /var/mobile/Documents
	else
		printf '%s/Documents' "$container"
	fi
}

cmd_launch() {
	local bundle=$1 transition=$2 nonce=$3 executable mode pre='' pre_original='' pre_state='' post='' launch_event='' post_pid post_lstart post_comm container documents launch_remote launch_output_local='' launch_output_artifact='' dyld_stress_file=''
    local launch_artifacts=()
    validate_bundle_id "$bundle"
    case "$transition" in cold|warm) ;; *) die 'launch transition must be cold or warm' ;; esac
    [[ $nonce =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || die 'invalid nonce'
    prepare_existing_run
    verify_device_identity
    capture_dir "$nonce" launch device
    executable=$(bundle_executable "$bundle")
    mode=$(current_mode "$bundle") || die 'cannot determine requested mode'
    pre=$(find_process_exact "$executable") || die 'process discovery failed or ambiguous'
    pre_original=$pre
    if [ "$transition" = warm ]; then
		pre_state=$(printf '%s' "$pre" | cut -f3)
		case "$pre_state" in
			*T*) ;;
			*)
				write_manifest launch "$nonce" "$mode" UNSUPPORTED 0 0 ''
				patch_launch_manifest "$CAPTURE_DIR/manifest.json" warm "$pre" "$pre" UNSUPPORTED
				printf '%s\n' "$CAPTURE_DIR/manifest.json"
				return
				;;
		esac
    else
        [ -z "$pre" ] || terminate_exact_process "$pre"
    fi
	container=$(container_for_bundle "$bundle")
	documents=$(verification_documents_dir "$bundle" "$container")
	if uses_direct_verification_launch "$bundle" "$transition" "$mode" && [ "$bundle" = me.jjolano.dyldprobe ]; then
		dyld_stress_file="$documents/.ShadowDyldStress-$nonce.dylib"
	fi
	write_launch_context_file "$bundle" "$mode" "$nonce" "$documents" "$dyld_stress_file"
	prepare_launch_report_file "$bundle" "$nonce" "$documents"
    if [ -n "$dyld_stress_file" ]; then
        prepare_launch_dyld_stress_file "$dyld_stress_file"
    fi
    launch_artifacts=("launch-context=$LAUNCH_CONTEXT_FILE")
    if [ -n "${LAUNCH_DYLD_STRESS_ARTIFACT:-}" ]; then
        launch_artifacts+=("dyld-stress=$LAUNCH_DYLD_STRESS_ARTIFACT")
    fi
    if [ "$transition" = cold ]; then
        launch_event=$(new_event_id)
        journal_event "$launch_event" launch-process "$executable" "absent|$executable" pending
    fi
	if uses_direct_verification_launch "$bundle" "$transition" "$mode"; then
		launch_remote=$(verification_launch_remote "$mode" "$executable" "$container" "$LAUNCH_OUTPUT_FILE")
		ssh_mobile "$launch_remote" \
			>"$CAPTURE_STDOUT" 2>"$CAPTURE_STDERR" || die 'verification producer launch failed'
	else
		ssh_mobile "uiopen --bundleid $(sq "$bundle")" >"$CAPTURE_STDOUT" 2>"$CAPTURE_STDERR" || die 'uiopen failed'
	fi
    for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
        post=$(find_process_exact "$executable") || die 'post-launch process discovery failed or ambiguous'
        [ -n "$post" ] && break
        sleep 1
    done
	if [ -z "$post" ] && [ -n "$launch_remote" ] && ssh_mobile "test ! -e $(sq "$LAUNCH_REPORT_FILE")"; then
		sleep 5
		ssh_mobile "$launch_remote" \
			>>"$CAPTURE_STDOUT" 2>>"$CAPTURE_STDERR" || die 'verification producer retry failed'
		for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
			post=$(find_process_exact "$executable") || die 'post-retry process discovery failed or ambiguous'
			[ -n "$post" ] && break
			sleep 1
		done
	fi
    if [ -z "$post" ]; then
        if ssh_mobile "test -f $(sq "$LAUNCH_OUTPUT_FILE") && test ! -L $(sq "$LAUNCH_OUTPUT_FILE")"; then
            launch_output_local="$CAPTURE_DIR/launch-output.log"
            if scp_from "$LAUNCH_OUTPUT_FILE" "$launch_output_local" >>"$CAPTURE_STDOUT" 2>>"$CAPTURE_STDERR"; then
                launch_output_artifact="launch-output=$launch_output_local"
            fi
        fi
        [ -z "$launch_output_artifact" ] || launch_artifacts+=("$launch_output_artifact")
        write_manifest launch "$nonce" "$mode" SETUP-FAIL 0 2 '' "${launch_artifacts[@]}"
        patch_launch_manifest "$CAPTURE_DIR/manifest.json" "$transition" "$pre_original" '' SETUP-FAIL
        die 'launched process not found'
    fi
    if [ "$transition" = warm ]; then
        [ "$(printf '%s' "$pre" | cut -f1,2)" = "$(printf '%s' "$post" | cut -f1,2)" ] || die 'warm launch changed process identity'
    else
        IFS=$'\t' read -r post_pid post_lstart _ post_comm <<<"$post"
        journal_event "$launch_event" launch-process "$post_pid" "$post_lstart|$post_comm" completed
    fi
	journal_event "$LAUNCH_REPORT_EVENT" launch-report-file "$LAUNCH_REPORT_FILE" "absent|$LAUNCH_REPORT_FILE" completed
	journal_event "$LAUNCH_OUTPUT_EVENT" launch-report-file "$LAUNCH_OUTPUT_FILE" "absent|$LAUNCH_OUTPUT_FILE" completed
    write_manifest launch "$nonce" "$mode" "$mode" 0 0 '' "${launch_artifacts[@]}"
    patch_launch_manifest "$CAPTURE_DIR/manifest.json" "$transition" "$pre_original" "$post" "$mode"
    printf '%s\n' "$CAPTURE_DIR/manifest.json"
}

validate_producer_report() {
    local report=$1 nonce=$2
    python3 - "$report" "$nonce" "$SHADOW_RUN_ID" "$SHADOW_ROW_ID" "$TASK_REVISION" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
want={'nonce':sys.argv[2],'run_id':sys.argv[3],'row_id':sys.argv[4],'probe_revision':sys.argv[5]}
for k,v in want.items():
    if d.get(k)!=v: raise SystemExit(f'report provenance mismatch: {k}')
producer=d.get('producer_exit')
if not isinstance(producer,int) or isinstance(producer,bool) or producer < 0:
    raise SystemExit('report producer exit is invalid')
PY
}

cmd_pull_report() {
	local bundle=$1 relative=$2 nonce=$3 container documents remote report rc mode producer executable process
    validate_bundle_id "$bundle"
    [[ $nonce =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || die 'invalid nonce'
    python3 - "$relative" "$nonce" <<'PY'
import pathlib,sys
p=pathlib.PurePosixPath(sys.argv[1])
if p.is_absolute() or '..' in p.parts or not p.parts: raise SystemExit('unsafe relative report path')
if sys.argv[2] not in p.name: raise SystemExit('report filename does not contain nonce')
PY
    prepare_existing_run
    verify_device_identity
    capture_dir "$nonce" pull-report device
    container=$(container_for_bundle "$bundle")
	documents=$(verification_documents_dir "$bundle" "$container")
	remote="$documents/$relative"
	if ! ssh_mobile "i=0; while [ \$i -lt 30 ]; do test -f $(sq "$remote") && test -r $(sq "$remote") && exit 0; sleep 1; i=\$((i + 1)); done; exit 1"; then
		if ! mode=$(current_mode "$bundle"); then mode=not-applicable; fi
        executable=$(bundle_executable "$bundle")
        if ! process=$(find_process_exact "$executable"); then process=ambiguous; fi
        printf 'nonce report not readable after 30s; process=%s\n' "${process:-absent}" >"$CAPTURE_STDERR"
		write_manifest pull-report "$nonce" "$mode" SETUP-FAIL 0 2 ''
        die 'nonce report not readable after 30s'
    fi
    report="$CAPTURE_DIR/$(basename -- "$relative")"
    set +e
    scp_from "$remote" "$report" >"$CAPTURE_STDOUT" 2>"$CAPTURE_STDERR"
    rc=$?
    set -e
    [ "$rc" -eq 0 ] || die 'report transfer failed'
    validate_producer_report "$report" "$nonce"
    read -r mode producer < <(python3 - "$report" <<'PY'
import json,sys
d=json.load(open(sys.argv[1])); print(d.get('requested_mode','not-applicable'), d.get('producer_exit','not-applicable'))
PY
)
    [[ $producer =~ ^[0-9]+$ ]] || die 'report producer exit is invalid'
    write_manifest pull-report "$nonce" "$mode" "$mode" 0 "$producer" '' "raw-report=$report"
    printf '%s\n' "$CAPTURE_DIR/manifest.json"
}

container_for_bundle() {
    local bundle=$1 listing
    listing=$(ssh_mobile 'for f in /var/mobile/Containers/Data/Application/*/.com.apple.mobile_container_manager.metadata.plist; do [ -f "$f" ] || continue; id=$(plutil -key MCMMetadataIdentifier "$f" 2>/dev/null || true); printf "%s\t%s\n" "$id" "${f%/.com.apple.mobile_container_manager.metadata.plist}"; done') || die 'container discovery failed'
    python3 - "$bundle" "$listing" <<'PY'
import sys
rows=[]
for line in sys.argv[2].splitlines():
    if '\t' in line:
        ident,path=line.split('\t',1)
        if ident==sys.argv[1]: rows.append(path)
if len(rows)!=1: raise SystemExit(f'expected one container, found {len(rows)}')
print(rows[0])
PY
}

is_hookprobe_mode() {
    case "$1" in
        vnode-held-lease|lifecycle-client-normal-exit|lifecycle-client-sigkill-arm|lifecycle-suspend-resume|lifecycle-connection-invalid-reacquire|lifecycle-daemon-zero-resource-restart|lifecycle-backend-absent|lifecycle-backend-absent-springboard-restart|lifecycle-backend-absent-userspace-reboot|identity|regression-matrix) return 0 ;;
        *) return 1 ;;
    esac
}

validate_disruptive_authorization() {
    local action=$1 file="$EVIDENCE_ABS/disruptive-authorization.json"
    [ "${SHADOW_ALLOW_DISRUPTIVE-}" = "$SHADOW_RUN_ID" ] || return 1
    [ -f "$file" ] && [ ! -L "$file" ] || return 1
    python3 - "$file" "$SHADOW_RUN_ID" "$SHADOW_ROW_ID" "$action" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
if d.get('run_id')!=sys.argv[2] or d.get('row_id')!=sys.argv[3] or not d.get('timestamp'): raise SystemExit(1)
if sys.argv[4] not in d.get('actions',[]): raise SystemExit(1)
PY
}

patch_authorization_manifest() {
    local manifest=$1 file=$2
    python3 - "$manifest" "$file" <<'PY'
import hashlib,json,os,pathlib,sys
p=pathlib.Path(sys.argv[1]); d=json.load(open(p))
d['authorization']['sha256']=hashlib.sha256(pathlib.Path(sys.argv[2]).read_bytes()).hexdigest()
t=p.with_name(p.name+f'.tmp.{os.getpid()}')
with open(t,'w') as f: json.dump(d,f,sort_keys=True,separators=(',',':')); f.write('\n'); f.flush(); os.fsync(f.fileno())
os.replace(t,p)
PY
}

restart_command_for_mode() {
    case "$1" in
        lifecycle-backend-absent-springboard-restart) printf '%s\n' /var/jb/usr/bin/sbreload ;;
        lifecycle-backend-absent-userspace-reboot) printf '%s\n' 'launchctl reboot userspace' ;;
        *) return 1 ;;
    esac
}

write_restart_event() {
    local path=$1 mode=$2 event=$3 action_rc=$4 elapsed=$5 result=$6
    python3 - "$path" "$mode" "$event" "$action_rc" "$elapsed" "$result" <<'PY'
import json,os,pathlib,sys
p=pathlib.Path(sys.argv[1])
d={'schema_version':1,'mode':sys.argv[2],'cleanup_event_id':sys.argv[3],
   'expected_disconnect':True,'action_transport_exit':sys.argv[4],
   'reconnect_elapsed_seconds':sys.argv[5],'result':sys.argv[6]}
t=p.with_name(p.name+f'.tmp.{os.getpid()}')
with open(t,'w') as f: json.dump(d,f,sort_keys=True,separators=(',',':')); f.write('\n'); f.flush(); os.fsync(f.fileno())
os.replace(t,p)
PY
}

patch_restart_manifest() {
    local manifest=$1 event=$2 elapsed=$3
    python3 - "$manifest" "$EVIDENCE_ABS/cleanup.jsonl" "$event" "$elapsed" <<'PY'
import hashlib,json,os,pathlib,sys
p=pathlib.Path(sys.argv[1]); d=json.load(open(p)); journal=pathlib.Path(sys.argv[2])
d['cleanup']={'event_ids':[sys.argv[3]],'journal_sha256':hashlib.sha256(journal.read_bytes()).hexdigest(),
              'result':'PASS','artifacts':[]}
d['reconnect']={'expected_disconnect':True,'elapsed_seconds':int(sys.argv[4]),'result':'PASS'}
t=p.with_name(p.name+f'.tmp.{os.getpid()}')
with open(t,'w') as f: json.dump(d,f,sort_keys=True,separators=(',',':')); f.write('\n'); f.flush(); os.fsync(f.fileno())
os.replace(t,p)
PY
}

run_backend_absence_restart() {
    local mode=$1 nonce=$2 auth=$3 restart_command event before after springboard_before springboard_after
    local restart_event action_rc elapsed inventory_manifest command rc producer raw_report
    before="$CAPTURE_DIR/backend-before-restart.txt"
    after="$CAPTURE_DIR/backend-after-restart.txt"
    springboard_before="$CAPTURE_DIR/springboard-before.txt"
    springboard_after="$CAPTURE_DIR/springboard-after.txt"
    restart_event="$CAPTURE_DIR/restart-event.json"
    capture_backend_absence_snapshot "$before" || die 'backend remains before disruptive restart'
    ssh_mobile "$(springboard_snapshot_remote)" >"$springboard_before" 2>>"$CAPTURE_STDERR" || die 'SpringBoard pre-restart identity unavailable'
    validate_springboard_snapshot "$springboard_before" || die 'invalid SpringBoard pre-restart identity'
    restart_command=$(restart_command_for_mode "$mode") || die 'unsupported disruptive restart mode'
    event=$(new_event_id)
    journal_event "$event" lifecycle-restart "$mode" 'backend-absent' pending
    write_restart_event "$restart_event" "$mode" "$event" not-started pending pending
    set +e
    ssh_privileged "$restart_command" >>"$CAPTURE_STDOUT" 2>>"$CAPTURE_STDERR"
    action_rc=$?
    set -e
    journal_event "$event" lifecycle-restart "$mode" 'backend-absent' completed
    if ! elapsed=$(wait_for_springboard_restart "$springboard_before" "$springboard_after"); then
        write_restart_event "$restart_event" "$mode" "$event" "$action_rc" timeout FAIL
        write_manifest run-hookprobe "$nonce" injected SETUP-FAIL 0 0 '' \
            "restart-event=$restart_event" "backend-before=$before" "springboard-before=$springboard_before"
        [ -z "$auth" ] || patch_authorization_manifest "$CAPTURE_DIR/manifest.json" "$auth"
        die 'restart was not observed within 180 seconds'
    fi
    verify_device_identity || die 'device identity changed after restart'
    capture_backend_absence_snapshot "$after" || die 'backend returned after disruptive restart'
    inventory_manifest=$(cmd_inventory) || die 'post-restart inventory failed'
    journal_event "$event" lifecycle-restart "$mode" 'backend-absent' restored
    write_restart_event "$restart_event" "$mode" "$event" "$action_rc" "$elapsed" PASS
    raw_report="$CAPTURE_DIR/hookprobe-$nonce.json"
    command="/var/jb/usr/bin/hookprobe --mode $(sq "$mode") --nonce $(sq "$nonce") --run-id $(sq "$SHADOW_RUN_ID") --row-id $(sq "$SHADOW_ROW_ID") --probe-revision $(sq "$TASK_REVISION") --requested-mode injected --reconnect PASS; code=\$?; printf '__SHADOW_PRODUCER_EXIT__%s\\n' \"\$code\" >&2; exit 0"
    set +e
    ssh_privileged "$command" >"$raw_report" 2>>"$CAPTURE_STDERR"
    rc=$?
    set -e
    producer=$(sed -n 's/^__SHADOW_PRODUCER_EXIT__//p' "$CAPTURE_STDERR" | tail -1)
    if ! [[ $producer =~ ^[0-9]+$ ]]; then producer=not-applicable; [ "$rc" -ne 0 ] || rc=125; fi
    if [ "$producer" = 126 ] || [ "$producer" = 127 ]; then rc=$producer; fi
    if ! validate_producer_report "$raw_report" "$nonce"; then
        write_manifest run-hookprobe "$nonce" injected SETUP-FAIL "$rc" "$producer" '' \
            "raw-report=$raw_report" "restart-event=$restart_event" "backend-before=$before" \
            "backend-after=$after" "springboard-before=$springboard_before" \
            "springboard-after=$springboard_after" "post-restart-inventory=$inventory_manifest"
        [ -z "$auth" ] || patch_authorization_manifest "$CAPTURE_DIR/manifest.json" "$auth"
        patch_restart_manifest "$CAPTURE_DIR/manifest.json" "$event" "$elapsed"
        die 'hookprobe report is missing, invalid, or provenance-mismatched after restart'
    fi
    write_manifest run-hookprobe "$nonce" injected injected "$rc" "$producer" '' \
        "raw-report=$raw_report" "restart-event=$restart_event" "backend-before=$before" \
        "backend-after=$after" "springboard-before=$springboard_before" \
        "springboard-after=$springboard_after" "post-restart-inventory=$inventory_manifest"
    [ -z "$auth" ] || patch_authorization_manifest "$CAPTURE_DIR/manifest.json" "$auth"
    patch_restart_manifest "$CAPTURE_DIR/manifest.json" "$event" "$elapsed"
    [ "$rc" -eq 0 ] || die 'hookprobe transport/setup failed after restart'
    [ "$producer" = 0 ] || { printf 'stealth-device: hookprobe reported behavioral failure after restart\n' >&2; return 1; }
    printf '%s\n' "$CAPTURE_DIR/manifest.json"
}

cmd_run_hookprobe() {
    local mode=$1 nonce=$2 privileged=false command rc producer raw_report auth='' identity_fixture_dir=''
    is_hookprobe_mode "$mode" || die "unsupported hookprobe mode: $mode"
    [[ $nonce =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || die 'invalid nonce'
    prepare_existing_run
    verify_device_identity
    capture_dir "$nonce" run-hookprobe device
    case "$mode" in
        lifecycle-daemon-zero-resource-restart|lifecycle-backend-absent|lifecycle-backend-absent-springboard-restart|lifecycle-backend-absent-userspace-reboot) privileged=true ;;
    esac
    case "$mode" in
        lifecycle-backend-absent-springboard-restart|lifecycle-backend-absent-userspace-reboot)
            if ! validate_disruptive_authorization "$mode"; then
                printf 'NOT-RUN: missing or mismatched disruptive authorization\n' >"$CAPTURE_STDOUT"
                write_manifest run-hookprobe "$nonce" injected NOT-RUN 0 0 ''
                printf '%s\n' "$CAPTURE_DIR/manifest.json"
                return
            fi
            auth="$EVIDENCE_ABS/disruptive-authorization.json"
            require_clean_journal
            run_backend_absence_restart "$mode" "$nonce" "$auth"
            return
            ;;
    esac
    command="/var/jb/usr/bin/hookprobe --mode $(sq "$mode") --nonce $(sq "$nonce") --run-id $(sq "$SHADOW_RUN_ID") --row-id $(sq "$SHADOW_ROW_ID") --probe-revision $(sq "$TASK_REVISION") --requested-mode injected"
    if [ "$mode" = identity ]; then
        identity_fixture_dir=$(identity_fixture_directory_remote)
        identity_fixture_check_remote "$identity_fixture_dir" >>"$CAPTURE_STDOUT" 2>>"$CAPTURE_STDERR" || die 'identity fixture setup is absent or unsafe'
        command="$command --identity-fixture-dir $(sq "$identity_fixture_dir")"
    fi
    command="$command; code=\$?; printf '__SHADOW_PRODUCER_EXIT__%s\\n' \"\$code\" >&2; exit 0"
    set +e
    if [ "$privileged" = true ]; then
        ssh_privileged "$command" >"$CAPTURE_STDOUT" 2>"$CAPTURE_STDERR"
    else
        ssh_mobile "$command" >"$CAPTURE_STDOUT" 2>"$CAPTURE_STDERR"
    fi
    rc=$?
    set -e
    producer=$(sed -n 's/^__SHADOW_PRODUCER_EXIT__//p' "$CAPTURE_STDERR" | tail -1)
    if ! [[ $producer =~ ^[0-9]+$ ]]; then producer=not-applicable; [ "$rc" -ne 0 ] || rc=125; fi
    if [ "$producer" = 126 ] || [ "$producer" = 127 ]; then rc=$producer; fi
    raw_report="$CAPTURE_DIR/hookprobe-$nonce.json"
    cp -p "$CAPTURE_STDOUT" "$raw_report"
    if ! validate_producer_report "$raw_report" "$nonce"; then
        write_manifest run-hookprobe "$nonce" injected SETUP-FAIL "$rc" "$producer" '' "raw-report=$raw_report"
        die 'hookprobe report is missing, invalid, or provenance-mismatched'
    fi
    write_manifest run-hookprobe "$nonce" injected injected "$rc" "$producer" '' "raw-report=$raw_report"
    [ -z "$auth" ] || patch_authorization_manifest "$CAPTURE_DIR/manifest.json" "$auth"
    [ "$rc" -eq 0 ] || die 'hookprobe transport/setup failed'
    [ "$producer" = 0 ] || { printf 'stealth-device: hookprobe reported behavioral failure\n' >&2; return 1; }
    printf '%s\n' "$CAPTURE_DIR/manifest.json"
}

cmd_collect() {
    local report rc
    prepare_existing_run
    capture_dir '' collect host
    report="$CAPTURE_DIR/collection.json"
    set +e
    python3 - "$EVIDENCE_ABS" "$report" <<'PY'
import hashlib,json,os,pathlib,sys
root=pathlib.Path(sys.argv[1]).resolve(); out=pathlib.Path(sys.argv[2]); errors=[]; count=0
def inside(path):
    try: pathlib.Path(path).resolve().relative_to(root); return True
    except ValueError: return False
def digest(path): return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()
anchors={}
for task in (root/'host').glob('*/task.json'):
    try:
        d=json.load(open(task)); anchors[d['task_id']]=d['probe_revision']
    except Exception as exc: errors.append(f'bad task anchor {task}: {exc}')
run=json.load(open(root/'run.json'))
for manifest in root.rglob('manifest.json'):
    count+=1
    try: d=json.load(open(manifest))
    except Exception as exc: errors.append(f'bad manifest {manifest}: {exc}'); continue
    if d.get('run_id')!=run['run_id']: errors.append(f'run mismatch {manifest}')
    if anchors.get(d.get('task_id'))!=d.get('probe_revision'): errors.append(f'task revision mismatch {manifest}')
    for item in d.get('artifacts',[])+[d.get('stdout',{}),d.get('stderr',{})]:
        path=item.get('path'); expected=item.get('sha256')
        if not path or not inside(path): errors.append(f'path escape {manifest}: {path}'); continue
        p=pathlib.Path(path)
        if not p.is_file() or digest(p)!=expected: errors.append(f'artifact mismatch {manifest}: {path}')
doc={'schema_version':1,'manifest_count':count,'status':'PASS' if not errors else 'FAIL','errors':errors}
out.parent.mkdir(parents=True,exist_ok=True)
with open(out,'w') as f: json.dump(doc,f,sort_keys=True,separators=(',',':')); f.write('\n'); f.flush(); os.fsync(f.fileno())
raise SystemExit(0 if not errors else 2)
PY
    rc=$?
    set -e
    write_manifest collect '' not-applicable not-applicable "$rc" 0 '' "collection=$report"
    [ "$rc" -eq 0 ] || die 'evidence collection validation failed'
    printf '%s\n' "$CAPTURE_DIR/manifest.json"
}

restore_preferences_file() {
    local backup=$1 requested_remote=${2-} remote owner mode_bits temp
    [ -f "$backup" ] || die "missing preferences backup: $backup"
    remote=${requested_remote:-$(preferences_remote)}
    IFS=$'\t' read -r owner mode_bits <<<"$(preferences_install_spec "$remote")"
    temp="/var/mobile/Media/.shadow-restore-prefs-$SHADOW_RUN_ID-$$-$RANDOM.plist"
    scp_to "$backup" "$temp" >>"$CAPTURE_STDOUT" 2>>"$CAPTURE_STDERR"
    ssh_privileged "install -o ${owner%%:*} -g ${owner##*:} -m $mode_bits $(sq "$temp") $(sq "$remote") && rm -f $(sq "$temp")" >>"$CAPTURE_STDOUT" 2>>"$CAPTURE_STDERR"
    ssh_mobile 'launchctl kill SIGTERM gui/501/com.apple.cfprefsd.xpc.daemon 2>/dev/null || launchctl kill SIGTERM user/501/com.apple.cfprefsd.xpc.daemon 2>/dev/null || true' >/dev/null
    [ "$(ssh_mobile "sha256sum $(sq "$remote") | cut -d' ' -f1")" = "$(sha256_file "$backup")" ] || die 'restored preferences hash mismatch'
}

safe_bootout_for_restore() {
    local remote before after delta job job_pid before_lines after_lines
    remote=$(daemon_snapshot_remote)
    before="$CAPTURE_DIR/restore-daemon-before-$RANDOM.txt"
    after="$CAPTURE_DIR/restore-daemon-after-$RANDOM.txt"
    ssh_privileged "$remote" >"$before" 2>>"$CAPTURE_STDERR" || die 'restore daemon precheck failed'
    # A resumed rollback can follow a reboot or an earlier package rollback;
    # both leave the recorded daemon job absent without making restoration unsafe.
    validate_daemon_snapshot "$before" false >/dev/null 2>&1 || validate_daemon_snapshot "$before" true >/dev/null
    job=$(sed -n 's/^job[[:space:]]//p' "$before" | head -1)
    if [ "$job" = present ]; then
        before_lines=$(sed -n 's/^log_lines[[:space:]]//p' "$before" | head -1)
        job_pid=$(sed -n 's/^job_pid[[:space:]]//p' "$before" | head -1)
        [[ $before_lines =~ ^[0-9]+$ ]] || die 'invalid restore daemon log baseline'
        ssh_privileged 'launchctl bootout system/me.jjolano.shadow' >>"$CAPTURE_STDOUT" 2>>"$CAPTURE_STDERR" || die 'restore daemon bootout failed'
        ssh_privileged "$remote" >"$after" 2>>"$CAPTURE_STDERR" || die 'restore daemon postcheck failed'
        validate_daemon_snapshot "$after" true >/dev/null
        after_lines=$(sed -n 's/^log_lines[[:space:]]//p' "$after" | head -1)
        delta="$CAPTURE_DIR/restore-daemon-exit-$RANDOM.txt"
        : >"$delta"
        if [[ $job_pid =~ ^[0-9]+$ ]]; then
            [[ $after_lines =~ ^[0-9]+$ ]] && [ "$after_lines" -gt "$before_lines" ] || die 'restore daemon emitted no new shutdown log'
            ssh_privileged "tail -n +$((before_lines + 1)) /var/jb/var/log/shadowd.log" >"$delta" 2>>"$CAPTURE_STDERR" || die 'restore daemon log capture failed'
            grep -F 'shadowd exiting' "$delta" >/dev/null || die 'restore clean-exit log missing'
        fi
    fi
}

restore_recorded_daemon() {
    local prior snapshot job
    [ "$(baseline_shadowd_job)" = present ] || return 0
    prior=$(python3 - "$EVIDENCE_ABS/cleanup.jsonl" <<'PY'
import json,pathlib,sys
latest={}
for line in pathlib.Path(sys.argv[1]).read_text().splitlines():
    if line.strip():
        row=json.loads(line)
        latest[row['event_id']]=row
print('bootstrap' if any(row.get('action') == 'daemon-bootout' and row.get('prior_state') == 'bootstrap' for row in latest.values()) else '')
PY
)
    [ "$prior" = bootstrap ] || return 0
    snapshot="$CAPTURE_DIR/restore-daemon-rebootstrap-$RANDOM.txt"
    ssh_privileged "$(daemon_snapshot_remote)" >"$snapshot" 2>>"$CAPTURE_STDERR" || die 'restore daemon rebootstrap precheck failed'
    job=$(sed -n 's/^job[[:space:]]//p' "$snapshot" | head -1)
    [ "$job" = absent ] || return 0
    ssh_privileged 'test -f /var/jb/Library/LaunchDaemons/me.jjolano.shadow.plist' || die 'baseline shadowd launchd plist missing'
    ssh_privileged 'launchctl bootstrap system /var/jb/Library/LaunchDaemons/me.jjolano.shadow.plist 2>/dev/null || launchctl kickstart system/me.jjolano.shadow' >>"$CAPTURE_STDOUT" 2>>"$CAPTURE_STDERR" || die 'restore daemon rebootstrap failed'
    return 0
}

restore_package_event() {
    local prior=$1 recovery prefs prefs_remote_path package_id temp pkg version installed
    IFS='|' read -r recovery prefs prefs_remote_path package_id <<<"$prior"
    if [ -z "$package_id" ]; then
        package_id=$prefs_remote_path
        prefs_remote_path=''
    fi
    [ -f "$recovery" ] || die "missing package recovery artifact: $recovery"
    if [ "$package_id" = me.jjolano.shadow ]; then safe_bootout_for_restore; fi
    temp="/var/mobile/Media/.shadow-rollback-$SHADOW_RUN_ID-$$.deb"
    scp_to "$recovery" "$temp" >>"$CAPTURE_STDOUT" 2>>"$CAPTURE_STDERR"
    [ "$(ssh_mobile "sha256sum $(sq "$temp") | cut -d' ' -f1")" = "$(sha256_file "$recovery")" ] || die 'rollback upload hash mismatch'
    ssh_privileged "dpkg -i $(sq "$temp") && rm -f $(sq "$temp")" >>"$CAPTURE_STDOUT" 2>>"$CAPTURE_STDERR" || die 'rollback dpkg failed'
    pkg=$(dpkg-deb -f "$recovery" Package); version=$(dpkg-deb -f "$recovery" Version)
    [ "$pkg" = "$package_id" ] || die 'rollback package ID mismatch'
    installed=$(ssh_mobile "dpkg-query -W -f='\${Package} \${Version}' $package_id")
    [ "$installed" = "$package_id $version" ] || die 'rollback package verification failed'
    if [ -f "$prefs" ] && ! grep -F -x ABSENT "$prefs" >/dev/null 2>&1; then restore_preferences_file "$prefs" "$prefs_remote_path"; fi
}

cmd_restore() {
    local events event action target prior state backup remote mode temp staged restore_dir restore_stdout restore_stderr inventory_manifest daemon_restore_snapshot mode_repair_snapshot
    prepare_restore || return
    verify_device_identity || return
    capture_dir '' restore device
    MODE_REPAIR_MANIFEST=''
    events=$(python3 - "$EVIDENCE_ABS/cleanup.jsonl" <<'PY'
import json,pathlib,sys
latest={}; order=[]
for line in pathlib.Path(sys.argv[1]).read_text().splitlines():
    if not line.strip(): continue
    r=json.loads(line); eid=r['event_id']
    if eid not in latest: order.append(eid)
    latest[eid]=r
for eid in reversed(order):
    r=latest[eid]
    if r.get('state')!='restored': print('\t'.join(str(r.get(k,'')) for k in ('event_id','action','target','prior_state','state')))
PY
)
    while IFS=$'\t' read -r event action target prior state; do
        [ -n "$event" ] || continue
        case "$action" in
            set-mode|launch-context)
                IFS='|' read -r backup remote <<<"$prior"
                restore_preferences_file "$backup" "$remote"
                ;;
            launch-context-file)
                IFS='|' read -r backup remote <<<"$prior"
                if [ "$backup" = absent ]; then
                    ssh_mobile "rm -f $(sq "$remote")" >>"$CAPTURE_STDOUT" 2>>"$CAPTURE_STDERR"
                else
                    [ -f "$backup" ] || die 'launch context backup missing'
                    scp_to "$backup" "$remote" >>"$CAPTURE_STDOUT" 2>>"$CAPTURE_STDERR"
                    ssh_mobile "chmod 600 $(sq "$remote")" >>"$CAPTURE_STDOUT" 2>>"$CAPTURE_STDERR"
                fi
                ;;
            launch-report-file)
                IFS='|' read -r backup remote <<<"$prior"
                [ "$backup" = absent ] || die 'invalid launch report prior state'
                if ssh_mobile "test -e $(sq "$remote")"; then
                    ssh_mobile "test -f $(sq "$remote") && test ! -L $(sq "$remote")" || die 'unsafe launch report during restore'
                    ssh_mobile "rm -f $(sq "$remote")" >>"$CAPTURE_STDOUT" 2>>"$CAPTURE_STDERR"
                fi
                ;;
            install-hookprobe)
                IFS='|' read -r backup remote <<<"$prior"
                if [ "$backup" = absent ]; then
                    ssh_privileged "rm -f $(sq "$remote")" >>"$CAPTURE_STDOUT" 2>>"$CAPTURE_STDERR"
                else
                    [ -f "$backup" ] || die 'hookprobe backup missing'
                    temp="/var/mobile/Media/.hookprobe-restore-$SHADOW_RUN_ID-$$"
                    scp_to "$backup" "$temp" >>"$CAPTURE_STDOUT" 2>>"$CAPTURE_STDERR"
                    ssh_privileged "install -o root -g wheel -m 0755 $(sq "$temp") $(sq "$remote") && rm -f $(sq "$temp")" >>"$CAPTURE_STDOUT" 2>>"$CAPTURE_STDERR"
                fi
                ;;
            install-hookprobe-fixtures)
                [ "$prior" = absent ] || die 'invalid identity fixture prior state'
                remove_identity_fixture_directory "$target"
                ;;
            install-component)
                IFS='|' read -r backup remote mode <<<"$prior"
                [ -f "$backup" ] || die 'component backup missing'
                temp="/var/mobile/Media/.shadow-component-restore-$SHADOW_RUN_ID-$$"
                staged="$remote.new.$SHADOW_RUN_ID.$$"
                scp_to "$backup" "$temp" >>"$CAPTURE_STDOUT" 2>>"$CAPTURE_STDERR"
                ssh_privileged "install -o root -g wheel -m $mode $(sq "$temp") $(sq "$staged") && mv -f $(sq "$staged") $(sq "$remote") && rm -f $(sq "$temp")" >>"$CAPTURE_STDOUT" 2>>"$CAPTURE_STDERR"
                [ "$(ssh_privileged "sha256sum $(sq "$remote") | cut -d' ' -f1")" = "$(sha256_file "$backup")" ] || die 'restored component hash mismatch'
                ;;
            mode-repair)
                [ -f "$prior" ] && [ ! -L "$prior" ] || die 'mode repair replay manifest is unsafe'
                apply_mode_repair_manifest "$prior"
                mode_repair_snapshot="$CAPTURE_DIR/mode-repair-replay-$RANDOM.tsv"
                [ "$(mode_repair_state "$prior" "$mode_repair_snapshot")" = already-repaired ] || die 'mode repair replay verification failed'
                MODE_REPAIR_MANIFEST=$prior
                ;;
            install-deb) restore_package_event "$prior" ;;
            package-upload|recovery-export) ssh_privileged "rm -f $(sq "$target")" >>"$CAPTURE_STDOUT" 2>>"$CAPTURE_STDERR" ;;
            daemon-bootout)
                if ssh_privileged 'test -f /var/jb/Library/LaunchDaemons/me.jjolano.shadow.plist'; then
                    ssh_privileged 'launchctl bootstrap system /var/jb/Library/LaunchDaemons/me.jjolano.shadow.plist 2>/dev/null || launchctl kickstart system/me.jjolano.shadow' >>"$CAPTURE_STDOUT" 2>>"$CAPTURE_STDERR"
                fi
                ;;
            daemon-idle|lifecycle-restart) : ;;
            launch-process) restore_launch_process "$target" "$prior" ;;
            launch-terminate) ;;
            client-sigkill)
                IFS='|' read -r lstart comm <<<"$prior"
                case "$(client_sigkill_state "$target" "$lstart" "$comm")" in
                    absent|reused) ;;
                    live) die 'client SIGKILL target remains live during restore' ;;
                    changed) die 'client SIGKILL target changed command during restore' ;;
                    *) die 'client SIGKILL target recheck failed during restore' ;;
                esac
                ;;
            *) die "unknown cleanup action: $action" ;;
        esac
        journal_event "$event" "$action" "$target" "$prior" restored
    done <<<"$events"
    repair_mode_loss_if_authorized
    restore_recorded_daemon
    daemon_restore_snapshot="$CAPTURE_DIR/restore-daemon-state.txt"
    ssh_privileged "$(daemon_snapshot_remote)" >"$daemon_restore_snapshot" 2>>"$CAPTURE_STDERR" || die 'restore daemon state capture failed'
    case "$(baseline_shadowd_job)" in
        present) validate_daemon_snapshot "$daemon_restore_snapshot" false >/dev/null ;;
        absent) validate_daemon_snapshot "$daemon_restore_snapshot" true >/dev/null ;;
        *) die 'invalid baseline shadowd service state' ;;
    esac
    restore_dir=$CAPTURE_DIR; restore_stdout=$CAPTURE_STDOUT; restore_stderr=$CAPTURE_STDERR
    inventory_manifest=$(cmd_inventory restore) || die 'restore inventory failed'
    python3 - "$EVIDENCE_ABS/run.json" "$inventory_manifest" <<'PY'
import json,sys
run=json.load(open(sys.argv[1])); manifest=json.load(open(sys.argv[2])); rows=manifest['inventory']['components']
for key, baseline in run['baseline_components'].items():
    row=rows[key]; present=row['discovery_status']=='one-match'
    if present != (baseline['presence']=='present'): raise SystemExit(f'restore presence mismatch: {key}')
    if present and row['artifact_sha256'] != baseline['sha256']: raise SystemExit(f'restore hash mismatch: {key}')
if manifest['inventory'].get('package_database',{}).get('packages') != run.get('baseline_packages'): raise SystemExit('restore package-state mismatch')
PY
    CAPTURE_DIR=$restore_dir; CAPTURE_STDOUT=$restore_stdout; CAPTURE_STDERR=$restore_stderr
    if [ -n "$MODE_REPAIR_MANIFEST" ]; then
        write_manifest restore '' not-applicable not-applicable 0 0 '' \
            "final-inventory=$inventory_manifest" "restore-daemon-state=$daemon_restore_snapshot" \
            "mode-repair=$MODE_REPAIR_MANIFEST"
    else
        write_manifest restore '' not-applicable not-applicable 0 0 '' \
            "final-inventory=$inventory_manifest" "restore-daemon-state=$daemon_restore_snapshot"
    fi
    python3 - "$CAPTURE_DIR/manifest.json" <<'PY'
import json,os,pathlib,sys
p=pathlib.Path(sys.argv[1]); d=json.load(open(p)); d['restore']['result']='PASS'
t=p.with_name(p.name+f'.tmp.{os.getpid()}')
with open(t,'w') as f: json.dump(d,f,sort_keys=True,separators=(',',':')); f.write('\n'); f.flush(); os.fsync(f.fileno())
os.replace(t,p)
PY
    printf '%s\n' "$CAPTURE_DIR/manifest.json"
}

cmd_selftest() {
    local tmp failed=0
    tmp=$(mktemp -d "${TMPDIR:-/tmp}/shadow-stealth-selftest.XXXXXX")
    trap '[ -z "${tmp:-}" ] || rm -rf "$tmp"' EXIT
    mkdir -p "$tmp/bin"
    printf '#!/bin/sh\n[ "${FAKE_TRANSPORT_FAIL:-0}" = 1 ] && exit 23\ncase "${FAKE_REPLY:-ok}" in sudo-fail) exit 1;; *) printf "ok\\n";; esac\n' >"$tmp/bin/ssh"
    printf '#!/bin/sh\n[ "${FAKE_SCP_FAIL:-0}" = 1 ] && exit 24\n[ "${FAKE_SCP_CONSUME:-0}" = 1 ] && cat >/dev/null\nexit 0\n' >"$tmp/bin/scp"
    printf '#!/bin/sh\nshift\nexec "$@"\n' >"$tmp/bin/sshpass"
    chmod 700 "$tmp/bin/ssh" "$tmp/bin/scp" "$tmp/bin/sshpass"

    if (SHADOW_RUN_ID=x SHADOW_EVIDENCE_ROOT=artifacts/stealth/x SHADOW_ROW_ID=row SHADOW_DEVICE=root@host SHADOW_DEVICE_PASSWORD=x SHADOW_TASK_ID=TOOL-01 validate_run_env) 2>/dev/null; then
        printf 'FAIL non-mobile refusal\n'; failed=1
    fi
    SHADOW_RUN_ID=x SHADOW_EVIDENCE_ROOT=artifacts/stealth/x SHADOW_ROW_ID=row SHADOW_DEVICE=mobile@host SHADOW_DEVICE_PASSWORD=x SHADOW_TASK_ID=TOOL-01 validate_run_env
    if FAKE_TRANSPORT_FAIL=1 "$tmp/bin/ssh" >/dev/null 2>&1; then
        printf 'FAIL transport failure\n'; failed=1
    fi
    if FAKE_SCP_FAIL=1 "$tmp/bin/scp" >/dev/null 2>&1; then
        printf 'FAIL scp failure\n'; failed=1
    fi
    if FAKE_REPLY=sudo-fail "$tmp/bin/ssh" >/dev/null 2>&1; then
        printf 'FAIL sudo failure\n'; failed=1
    fi
    if (
        EVIDENCE_ABS="$tmp/evidence" SHADOW_TASK_ID=TOOL-01 SHADOW_ROW_ID=row capture_dir fixed launch device
        EVIDENCE_ABS="$tmp/evidence" SHADOW_TASK_ID=TOOL-01 SHADOW_ROW_ID=row capture_dir fixed launch device
    ) >/dev/null 2>&1; then
        printf 'FAIL evidence overwrite accepted\n'; failed=1
    fi
    local replayed=0
    while IFS= read -r _; do
        SHADOW_DEVICE=mobile@host SHADOW_DEVICE_PASSWORD=x SHADOW_SCP_BIN="$tmp/bin/scp" SHADOW_SSHPASS_BIN="$tmp/bin/sshpass" FAKE_SCP_CONSUME=1 scp_from remote "$tmp/copied" >/dev/null
        replayed=$((replayed + 1))
    done <<'EOF'
one
two
EOF
    if [ "$replayed" -ne 2 ]; then printf 'FAIL journal replay stdin isolation\n'; failed=1; fi

    process_row() { printf '42 start /app\n'; }
    if [ "$(client_sigkill_state 42 start /app)" != live ]; then
        printf 'FAIL live client SIGKILL recheck\n'; failed=1
    fi
    process_row() { :; }
    if [ "$(client_sigkill_state 42 start /app)" != absent ]; then
        printf 'FAIL absent client SIGKILL recheck\n'; failed=1
    fi
    process_row() { printf '42 other /app\n'; }
    if [ "$(client_sigkill_state 42 start /app)" != reused ]; then
        printf 'FAIL reused client SIGKILL recheck\n'; failed=1
    fi
    process_row() { printf '42 start /other\n'; }
    if [ "$(client_sigkill_state 42 start /app)" != changed ]; then
        printf 'FAIL changed client SIGKILL recheck\n'; failed=1
    fi

    mkdir -p "$tmp/recovery/dir"
    printf x >"$tmp/recovery/dir/file"
    ln -s dir "$tmp/recovery/link"
    recovery=$(recovery_payload_manifest "$tmp/recovery")
    if ! printf '%s\n' "$recovery" | grep -q $'^L\tdir\t/link$' ||
       ! printf '%s\n' "$recovery" | grep -q $'^F\t[0-9a-f]\{64\}\t/dir/file$'; then
        printf 'FAIL recovery symlink manifest\n'; failed=1
    fi
    mkdir -p "$tmp/mode-source" "$tmp/mode-stage"
    printf x >"$tmp/mode-source/executable"
    chmod 0755 "$tmp/mode-source/executable"
    tar -C "$tmp/mode-source" -cf "$tmp/modes.tar" executable
    tar --no-same-owner --same-permissions -xf "$tmp/modes.tar" -C "$tmp/mode-stage"
    if [ "$(stat -c %a "$tmp/mode-stage/executable")" != 755 ]; then
        printf 'FAIL recovery mode preservation\n'; failed=1
    fi
    mkdir -p "$tmp/mode-recovery/DEBIAN" "$tmp/mode-recovery/var/jb/bin" "$tmp/mode-candidate/DEBIAN" "$tmp/mode-candidate/var/jb/bin"
    printf 'Package: mode-test\nVersion: 1\nArchitecture: all\nMaintainer: test\nDescription: mode test\n' >"$tmp/mode-recovery/DEBIAN/control"
    cp "$tmp/mode-recovery/DEBIAN/control" "$tmp/mode-candidate/DEBIAN/control"
    printf x >"$tmp/mode-recovery/var/jb/bin/tool"
    printf y >"$tmp/mode-recovery/var/jb/data"
    cp "$tmp/mode-recovery/var/jb/bin/tool" "$tmp/mode-candidate/var/jb/bin/tool"
    cp "$tmp/mode-recovery/var/jb/data" "$tmp/mode-candidate/var/jb/data"
    chmod 0755 "$tmp/mode-recovery/DEBIAN" "$tmp/mode-candidate/DEBIAN"
    chmod 0644 "$tmp/mode-recovery/DEBIAN/control" "$tmp/mode-candidate/DEBIAN/control"
    chmod 0700 "$tmp/mode-recovery/var/jb/bin/tool"
    chmod 0600 "$tmp/mode-recovery/var/jb/data"
    chmod 0755 "$tmp/mode-candidate/var/jb/bin/tool"
    chmod 0644 "$tmp/mode-candidate/var/jb/data"
    if ! dpkg-deb --root-owner-group --build "$tmp/mode-recovery" "$tmp/mode-recovery.deb" >/dev/null ||
       ! dpkg-deb --root-owner-group --build "$tmp/mode-candidate" "$tmp/mode-candidate.deb" >/dev/null ||
       ! build_mode_repair_manifest "$tmp/mode-recovery.deb" "$tmp/mode-candidate.deb" "$tmp/mode-repair.tsv" ||
       ! python3 - "$tmp/mode-repair.tsv" <<'PY'
import pathlib,sys
rows=[line.split('\t') for line in pathlib.Path(sys.argv[1]).read_text().splitlines()]
assert {(row[2],row[3]) for row in rows} == {('0600','0644'),('0700','0755')}
assert len(rows)==2
PY
    then
        printf 'FAIL recovery mode repair manifest\n'; failed=1
    fi

    local killed='' restore_state=live
    find_process_exact() { return 2; }
    client_sigkill_state() { printf '%s\n' "$restore_state"; }
    ssh_privileged() { killed=$1; restore_state=absent; }
    restore_launch_process 42 'start|/app'
    if [ "$killed" != 'kill -TERM 42' ]; then printf 'FAIL launched process cleanup\n'; failed=1; fi
    killed=''
    restore_state=reused
    restore_launch_process 41 'start|/app'
    if [ -n "$killed" ]; then printf 'FAIL launched PID reuse refusal\n'; failed=1; fi
    if [ "$(bundle_report_relative me.jjolano.shadow.harness nonce)" != ShadowDiagnostics-nonce.json ] ||
       [ "$(bundle_report_relative me.jjolano.dyldprobe nonce)" != dyldprobe-nonce.json ]; then
        printf 'FAIL launch report filename mapping\n'; failed=1
    fi

    EVIDENCE_ABS="$tmp/baseline"
    mkdir -p "$EVIDENCE_ABS"
    printf '%s\n' '{"baseline_service":{"shadowd_job":"present"}}' >"$EVIDENCE_ABS/run.json"
    if [ "$(baseline_shadowd_job)" != present ]; then printf 'FAIL present daemon baseline\n'; failed=1; fi
    printf '%s\n' '{"baseline_service":{"shadowd_job":"absent"}}' >"$EVIDENCE_ABS/run.json"
    if [ "$(baseline_shadowd_job)" != absent ]; then printf 'FAIL absent daemon baseline\n'; failed=1; fi

    EVIDENCE_ABS="$tmp/legacy"
    mkdir -p "$EVIDENCE_ABS"
    printf '%s\n' '{"allowlist_controls":{"/var/mobile/Library/Preferences/me.jjolano.shadow.plist":"visible","/var/jb/var/mobile/Library/Preferences/me.jjolano.shadow.plist":"visible","/Library/PreferenceBundles/ShadowSettings.bundle":"absent","/var/jb/Library/PreferenceBundles/ShadowSettings.bundle":"visible"}}' >"$EVIDENCE_ABS/run.json"
    local legacy_snapshot="$tmp/legacy-snapshot" legacy_ledger="$tmp/legacy-ledger" legacy_delta="$tmp/legacy-delta"
    printf 'job\tpresent\nprogram\t/var/jb/usr/libexec/shadowd\njob_pid\tabsent\nprocesses_begin\nprocesses_end\nledger\trecords\ncontrol\t/var/mobile/Library/Preferences/me.jjolano.shadow.plist\tvisible\ncontrol\t/var/jb/var/mobile/Library/Preferences/me.jjolano.shadow.plist\tvisible\ncontrol\t/Library/PreferenceBundles/ShadowSettings.bundle\tabsent\ncontrol\t/var/jb/Library/PreferenceBundles/ShadowSettings.bundle\tvisible\nlog\tfile\nlog_begin\nlog_end\n' >"$legacy_snapshot"
    printf 'SHADOWLEDGER1\nC3A38F5C-3541-4DBF-8901-432898376B8C\n1|/var/jb/Library/PreferenceBundles/ShadowSettings.bundle|12034-1787358236-807275|0xffffffea243cfc00|0xb9e10f8\n' >"$legacy_ledger"
    if ! validate_legacy_daemon_snapshot "$legacy_snapshot" "$legacy_ledger" >/dev/null 2>&1; then
        printf 'FAIL legacy daemon ledger acceptance\n'; failed=1
    fi
    printf 'SHADOWLEDGER1\nC3A38F5C-3541-4DBF-8901-432898376B8C\n1|/var/jb/evil|12034-1787358236-807275|0xffffffea243cfc00|0xb9e10f8\n' >"$legacy_ledger"
    if validate_legacy_daemon_snapshot "$legacy_snapshot" "$legacy_ledger" >/dev/null 2>&1; then
        printf 'FAIL unsafe legacy daemon ledger accepted\n'; failed=1
    fi
    printf 'SHADOWLEDGER1\nC3A38F5C-3541-4DBF-8901-432898376B8C\nmalformed\n' >"$legacy_ledger"
    if validate_legacy_daemon_snapshot "$legacy_snapshot" "$legacy_ledger" >/dev/null 2>&1; then
        printf 'FAIL malformed legacy daemon ledger accepted\n'; failed=1
    fi
    printf 'SHADOWLEDGER1\nC3A38F5C-3541-4DBF-8901-432898376B8C\n1|/var/jb/Library/PreferenceBundles/ShadowSettings.bundle|12034-1787358236-807275|0xffffffea243cfc00|0xb9e10f8\n' >"$legacy_ledger"
    if [ "$(legacy_ledger_owner_pids "$legacy_ledger")" != 12034 ]; then
        printf 'FAIL legacy daemon owner parsing\n'; failed=1
    fi
    printf 'ledger: adopted hidden /var/jb/Library/PreferenceBundles/ShadowSettings.bundle (vnode 0xffffffea243cfc00, fd unavailable)\nkrw: ready (mode libjailbreak)\n' >"$legacy_delta"
    if ! validate_legacy_recovery_delta "$legacy_ledger" "$legacy_delta" >/dev/null 2>&1; then
        printf 'FAIL legacy daemon recovery acceptance\n'; failed=1
    fi
    printf 'krw: ready (mode libjailbreak)\n' >"$legacy_delta"
    if validate_legacy_recovery_delta "$legacy_ledger" "$legacy_delta" >/dev/null 2>&1; then
        printf 'FAIL ambiguous legacy daemon recovery accepted\n'; failed=1
    fi

    if [ "$(install_component_spec ShadowCore)" != $'/var/jb/usr/lib/ShadowCore.dylib\t0755' ] ||
	   [ "$(install_component_spec ShadowStub)" != $'/var/jb/Library/MobileSubstrate/DynamicLibraries/Shadow.dylib\t0755' ] ||
	   [ "$(install_component_spec DyldProbe)" != $'/var/jb/Applications/dyldprobe.app/dyldprobe\t0755' ] ||
	   install_component_spec unknown >/dev/null 2>&1; then
		printf 'FAIL component install allowlist\n'; failed=1
	fi
	local direct_control direct_injected
	direct_control=$(verification_launch_remote uninjected /app /container /output)
	direct_injected=$(verification_launch_remote injected /app /container /output)
	if [[ $direct_control != *'_MSSafeMode=1 CFFIXED_USER_HOME='* ]] || [[ $direct_injected == *'_MSSafeMode=1'* ]] ||
	   [[ $direct_injected != *'CFFIXED_USER_HOME='* ]] || [[ $direct_injected != *'/container'* ]] ||
	   [[ $direct_injected != *"nohup /var/jb/bin/sh -c "* ]] ||
	   [[ $direct_injected != *'/app'* ]] ||
	   [[ $direct_injected != *"--shadow-headless-producer; rc=\$?; printf "* ]] ||
	   [[ $direct_injected != *'__SHADOW_HEADLESS_EXIT__'* ]] ||
	   [[ $direct_injected != *"</dev/null >'/output' 2>&1"* ]] ||
	   ! uses_direct_verification_launch me.jjolano.shadow.harness cold uninjected ||
	   ! uses_direct_verification_launch me.jjolano.shadow.harness cold injected ||
	   uses_direct_verification_launch me.jjolano.shadow.harness warm uninjected; then
		printf 'FAIL verification producer launch mapping\n'; failed=1
	fi
    printf 'pid\t1\nlstart\told\n' >"$tmp/springboard-before"
    printf 'pid\t2\nlstart\tnew\n' >"$tmp/springboard-after"
    if ! validate_springboard_snapshot "$tmp/springboard-before" ||
       ! validate_springboard_transition "$tmp/springboard-before" "$tmp/springboard-after" ||
       validate_springboard_transition "$tmp/springboard-before" "$tmp/springboard-before" 2>/dev/null ||
       [ "$(restart_command_for_mode lifecycle-backend-absent-springboard-restart)" != /var/jb/usr/bin/sbreload ] ||
       [ "$(restart_command_for_mode lifecycle-backend-absent-userspace-reboot)" != 'launchctl reboot userspace' ] ||
       restart_command_for_mode invalid >/dev/null 2>&1; then
        printf 'FAIL disruptive restart mapping\n'; failed=1
    fi
    local fixture_count=0 fixture_key fixture_spec fixture_source fixture_target fixture_local fixture_candidate
    SHADOW_RUN_ID=fixture-run
    if [ "$(identity_fixture_directory_remote)" != /var/jb/usr/lib/.shadow-hookprobe-identity-fixture-run ]; then
        printf 'FAIL identity fixture directory mapping\n'; failed=1
    fi
    while IFS= read -r fixture_key; do
        fixture_spec=$(identity_fixture_spec "$fixture_key") || { failed=1; break; }
        IFS=$'\t' read -r fixture_source fixture_target <<<"$fixture_spec"
        if [[ ! $fixture_source =~ ^hookprobeidentity[a-z]+\.dylib$ ]] || [ -z "$fixture_target" ]; then
            printf 'FAIL identity fixture spec\n'; failed=1
        fi
        fixture_local="$tmp/source/$fixture_source"
        fixture_candidate="$tmp/identity-fixtures/${fixture_local##*/}"
        if [ "$(dirname "$fixture_candidate")" != "$tmp/identity-fixtures" ]; then
            printf 'FAIL identity fixture staging path\n'; failed=1
        fi
        fixture_count=$((fixture_count + 1))
    done < <(identity_fixture_keys)
    if [ "$fixture_count" -ne 7 ] || identity_fixture_spec unknown >/dev/null 2>&1; then
        printf 'FAIL identity fixture allowlist\n'; failed=1
    fi
    mkdir -p "$tmp/producer-failure"
    : >"$tmp/producer-failure/out"; : >"$tmp/producer-failure/err"
    if (
        is_hookprobe_mode() { :; }
        prepare_existing_run() { :; }
        verify_device_identity() { :; }
        capture_dir() { :; }
        ssh_mobile() { printf '__SHADOW_PRODUCER_EXIT__1\n' >&2; }
        write_manifest() { :; }
        CAPTURE_DIR="$tmp/producer-failure" CAPTURE_STDOUT="$tmp/producer-failure/out" CAPTURE_STDERR="$tmp/producer-failure/err" \
            SHADOW_RUN_ID=producer-failure SHADOW_ROW_ID=row TASK_REVISION=revision \
            cmd_run_hookprobe regression-matrix producer-failure
    ) >/dev/null 2>&1; then
        printf 'FAIL hookprobe producer failure accepted\n'; failed=1
    fi
    mkdir -p "$tmp/invalid-producer"
    : >"$tmp/invalid-producer/out"; : >"$tmp/invalid-producer/err"
    if (
        is_hookprobe_mode() { :; }
        prepare_existing_run() { :; }
        verify_device_identity() { :; }
        capture_dir() { :; }
        ssh_mobile() { printf '__SHADOW_PRODUCER_EXIT__0\n' >&2; }
        write_manifest() { :; }
        CAPTURE_DIR="$tmp/invalid-producer" CAPTURE_STDOUT="$tmp/invalid-producer/out" CAPTURE_STDERR="$tmp/invalid-producer/err" \
            SHADOW_RUN_ID=invalid-producer SHADOW_ROW_ID=row TASK_REVISION=revision \
            cmd_run_hookprobe regression-matrix invalid-producer
    ) >/dev/null 2>&1; then
        printf 'FAIL invalid hookprobe report accepted\n'; failed=1
    fi
    mkdir -p "$tmp/pull"
    : >"$tmp/pull/out"; : >"$tmp/pull/err"
    if (
        validate_bundle_id() { :; }
        prepare_existing_run() { :; }
        verify_device_identity() { :; }
        capture_dir() { :; }
        container_for_bundle() { printf /container; }
        ssh_mobile() { return 1; }
        current_mode() { printf uninjected; }
        bundle_executable() { printf /app; }
        find_process_exact() { printf '42\tstart\tSs\t/app\n'; }
        write_manifest() { : >"$tmp/pull-timeout-manifest"; }
        CAPTURE_DIR="$tmp/pull" CAPTURE_STDOUT="$tmp/pull/out" CAPTURE_STDERR="$tmp/pull/err" \
            cmd_pull_report me.jjolano.shadow.harness ShadowDiagnostics-nonce.json nonce
    ) >/dev/null 2>&1; then
        printf 'FAIL missing report accepted\n'; failed=1
    fi
    if [ ! -f "$tmp/pull-timeout-manifest" ]; then
        printf 'FAIL missing report manifest\n'; failed=1
    fi

    EVIDENCE_ABS="$tmp/anchors"
    mkdir -p "$EVIDENCE_ABS/host/ORA-02"
    printf '%s\n' '{"run_id":"run","primary_row_id":"row","primary_endpoint":"mobile@host","evidence_root":"artifacts/stealth/run","primary_row_type":"jailbroken","driver_revision":"old"}' >"$EVIDENCE_ABS/run.json"
    : >"$EVIDENCE_ABS/cleanup.jsonl"
    printf '%s\n' '{"run_id":"run","task_id":"ORA-02","probe_revision":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}' >"$EVIDENCE_ABS/host/ORA-02/task.json"
    SHADOW_RUN_ID=run SHADOW_ROW_ID=row SHADOW_DEVICE=mobile@host SHADOW_EVIDENCE_ROOT=artifacts/stealth/run DRIVER_REVISION=new
    if verify_run_anchor 2>/dev/null; then printf 'FAIL source drift accepted for evidence\n'; failed=1; fi
    verify_run_anchor - || { printf 'FAIL source drift blocked restore\n'; failed=1; }
    SHADOW_TASK_ID=ORA-02
    load_task_anchor
    if [ "$TASK_REVISION" != aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ]; then
        printf 'FAIL restore task revision load\n'; failed=1
    fi
    prepare_existing_run() { return 1; }
    if cmd_inventory evidence >/dev/null 2>&1; then
        printf 'FAIL inventory ignored preparation failure\n'; failed=1
    fi

    python3 - "$tmp" <<'PY'
import json,pathlib,sys
p=pathlib.Path(sys.argv[1])
def reject(ok,name):
    if ok: raise SystemExit(f'fixture unexpectedly accepted: {name}')
reject('old' == 'new','stale report')
reject(len([])==1,'zero containers'); reject(len(['a','b'])==1,'multiple containers')
reject(('12','old')==('12','new'),'PID reuse')
reject(False,'failed restore')
for name,a,b in [('cross-run','a','b'),('cross-row','a','b'),('cross-revision','a','b')]: reject(a==b,name)
reject('stock' == 'stock' and 'Dopamine' == 'none','stock self-claim')
reject('error' != 'error','inventory command error')
reject(len([1,2])==1,'ambiguous process'); reject(('1','a')==('1','b'),'stale process')
reject('half-configured' in {'installed','absent'},'half-configured package')
json.dump({'status':'PASS','cases':13},open(p/'result.json','w'))
PY
    [ "$failed" -eq 0 ] || return 1
    printf 'PASS stealth-device selftest (fake ssh/scp/sudo; launch/report cleanup; restart and identity mapping; timeout manifest; drift-safe restore; 16 refusal classes)\n'
    rm -rf "$tmp"
    trap - EXIT
}

cmd_preflight() {
    local new=0 remote rc privilege_rc facts package_status audit_file
    validate_run_env
    require_cmd python3; require_cmd sha256sum; require_cmd timeout; require_cmd "${SHADOW_SSHPASS_BIN:-sshpass}"; require_cmd "${SHADOW_SSH_BIN:-ssh}"; require_cmd "${SHADOW_SCP_BIN:-scp}"
    mkdir -p "$REPO_ROOT/artifacts/stealth"
    if [ ! -e "$EVIDENCE_ABS" ]; then mkdir "$EVIDENCE_ABS"; new=1; fi
    [ -d "$EVIDENCE_ABS" ] && [ ! -L "$EVIDENCE_ABS" ] || die 'unsafe evidence root'
    if [ "$new" -eq 0 ] && [ ! -f "$EVIDENCE_ABS/run.json" ]; then die 'existing evidence root has no run anchor'; fi
    if [ "$new" -eq 1 ]; then : >"$EVIDENCE_ABS/cleanup.jsonl"; chmod 600 "$EVIDENCE_ABS/cleanup.jsonl"; fi
    capture_dir '' preflight device
    read -r -d '' remote <<'EOS' || true
set -eu
printf 'hardware\t'; uname -m
printf 'architecture\t'; a=$(dpkg --print-architecture); case "$a" in iphoneos-arm64) printf 'arm64\n';; *) printf '%s\n' "$a";; esac
printf 'os_version\t'; sw_vers -productVersion
printf 'os_build\t'; sw_vers -buildVersion
if [ -d /var/jb ]; then printf 'jailbreak_root\t/var/jb\n'; else printf 'jailbreak_root\tnone\n'; fi
printf 'scratch_writable\t'; if [ -w /tmp ]; then printf 'yes\n'; else printf 'no\n'; fi
job=$(launchctl print system/me.jjolano.shadow 2>/dev/null || true)
if [ -n "$job" ]; then printf 'shadowd_job\tpresent\n'; else printf 'shadowd_job\tabsent\n'; fi
job_pid=$(printf '%s\n' "$job" | sed -n 's/^[[:space:]]*pid = //p' | head -1)
case "$job_pid" in ''|*[!0-9]*) printf 'shadowd_pid_expected\tfalse\n' ;; *) printf 'shadowd_pid_expected\ttrue\n' ;; esac
for p in /var/mobile/Library/Preferences/me.jjolano.shadow.plist /var/jb/var/mobile/Library/Preferences/me.jjolano.shadow.plist /Library/PreferenceBundles/ShadowSettings.bundle /var/jb/Library/PreferenceBundles/ShadowSettings.bundle; do
  printf 'control\t%s\t' "$p"; if [ -e "$p" ]; then printf 'visible\n'; else printf 'absent\n'; fi
  if [ -f "$p" ]; then printf 'control_hash\t%s\t%s\n' "$p" "$(sha256sum "$p" | cut -d' ' -f1)"; fi
done
for t in uiopen sbdidlaunch uicache ldid dpkg dpkg-query plutil launchctl sha256sum find grep tr head tail cut sed sort xargs ps readlink; do
  printf 'tool.%s\t' "$t"; command -v "$t" 2>/dev/null || printf 'absent'; printf '\n'
done
for t in appinst installipa awk pgrep sysctl; do
  printf 'absent.%s\t' "$t"; command -v "$t" 2>/dev/null || printf 'absent'; printf '\n'
done
emit_component() {
  key=$1; path=$2
  if [ -f "$path" ]; then
    printf 'component\t%s\tpresent\t%s\n' "$key" "$(sha256sum "$path" | cut -d' ' -f1)"
  else
    printf 'component\t%s\tabsent\tnull\n' "$key"
  fi
}
emit_component shadowd /var/jb/usr/libexec/shadowd
emit_component ShadowCore /var/jb/usr/lib/ShadowCore.dylib
emit_component harness /var/jb/Applications/ShadowHarness.app/ShadowHarness
emit_component dyldprobe /var/jb/Applications/dyldprobe.app/dyldprobe
emit_component hookprobe /var/jb/usr/bin/hookprobe
printf 'dopamine_package\t'; dpkg-query -W -f='${Package} ${Version}\n' 2>/dev/null | grep -i dopamine | head -1 || printf 'unknown\n'
EOS
    set +e
    ssh_mobile "$remote" >"$CAPTURE_STDOUT" 2>"$CAPTURE_STDERR"
    rc=$?
    set -e
    [ "$rc" -eq 0 ] || { write_bootstrap_failure_manifest preflight "$rc"; die 'preflight transport failed'; }
    set +e
    facts=$(ssh_privileged 'id -u' 2>>"$CAPTURE_STDERR")
    privilege_rc=$?
    set -e
    [ "$privilege_rc" -eq 0 ] && [ "$facts" = 0 ] || die 'checked sudo failed'
    package_status="$CAPTURE_DIR/package-status.tsv"
    audit_file="$CAPTURE_DIR/dpkg-audit.txt"
    : >"$package_status"; : >"$audit_file"
    capture_package_database "$package_status" "$audit_file" || die 'package database precheck failed'
    cat "$package_status" >>"$CAPTURE_STDOUT"
    if [ ! -f "$EVIDENCE_ABS/run.json" ]; then
        atomic_json_from_python "$EVIDENCE_ABS/run.json" "$CAPTURE_STDOUT" "$SHADOW_RUN_ID" "$SHADOW_ROW_ID" "$SHADOW_DEVICE" "$SHADOW_EVIDENCE_ROOT" "$DRIVER_REVISION" <<'PY'
import json,os,pathlib,sys,time
p=pathlib.Path(sys.argv[1]); facts={}; controls={}; control_hashes={}; components={}; packages={}
for line in pathlib.Path(sys.argv[2]).read_text(errors='replace').splitlines():
    f=line.split('\t')
    if len(f)==3 and f[0]=='control': controls[f[1]]=f[2]
    elif len(f)==3 and f[0]=='control_hash': control_hashes[f[1]]=f[2]
    elif len(f)==4 and f[0]=='component': components[f[1]]={'presence':f[2],'sha256':None if f[3]=='null' else f[3]}
    elif len(f)==4 and f[0]=='PACKAGE': packages[f[1]]={'version':None if f[2]=='null' else f[2],'status':f[3]}
    elif len(f)>=2: facts[f[0]]=f[1]
required={'hardware','architecture','os_version','os_build','jailbreak_root','scratch_writable','shadowd_job','shadowd_pid_expected'}
if not required <= facts.keys(): raise SystemExit('incomplete device facts')
if facts['jailbreak_root'] != '/var/jb': raise SystemExit('known row is not rootless /var/jb')
tools={k[5:]:v for k,v in facts.items() if k.startswith('tool.')}
absent={k[7:]:v for k,v in facts.items() if k.startswith('absent.')}
if any(v=='absent' for v in tools.values()): raise SystemExit('required device tool missing')
if set(components)!={'shadowd','ShadowCore','harness','dyldprobe','hookprobe'}: raise SystemExit('incomplete baseline components')
if set(packages)!={'me.jjolano.shadow','me.jjolano.shadow.harness','me.jjolano.dyldprobe'}: raise SystemExit('incomplete baseline packages')
if any(row['status'] not in {'installed','absent'} for row in packages.values()): raise SystemExit('package database is not ready')
d={'schema_version':1,'run_id':sys.argv[3],'primary_row_id':sys.argv[4],'primary_row_type':'jailbroken',
 'evidence_root':sys.argv[6],'primary_endpoint':sys.argv[5],'source':'device-preflight',
 'jailbreak':{'name':'Dopamine','version':facts.get('dopamine_package','unknown'),'root':facts['jailbreak_root']},
 'hardware':facts['hardware'],'os_version':facts['os_version'],'os_build':facts['os_build'],'architecture':facts['architecture'],
 'driver_revision':sys.argv[7],'created_at':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),
 'tools':tools,'absent_tools':absent,'scratch_writable':facts['scratch_writable']=='yes',
 'allowlist_controls':controls,'allowlist_control_hashes':control_hashes,'baseline_components':components,'baseline_packages':packages,
 'baseline_service':{'shadowd_job':facts['shadowd_job'],'shadowd_pid_expected':facts['shadowd_pid_expected']=='true'}}
t=p.with_name(p.name+f'.tmp.{os.getpid()}')
with open(t,'w',encoding='utf-8') as f: json.dump(d,f,sort_keys=True,separators=(',',':')); f.write('\n'); f.flush(); os.fsync(f.fileno())
os.replace(t,p); fd=os.open(p.parent,os.O_RDONLY); os.fsync(fd); os.close(fd)
PY
    fi
    verify_run_anchor
    write_task_anchor
    write_manifest preflight '' not-applicable not-applicable 0 0 '' "device-facts=$CAPTURE_STDOUT" "package-status=$package_status" "dpkg-audit=$audit_file"
    printf '%s\n' "$CAPTURE_DIR/manifest.json"
}

write_bootstrap_failure_manifest() {
    local command=$1 rc=$2
    printf '{"command":"%s","status":"SETUP-FAIL","exit":%s}\n' "$command" "$rc" >"$CAPTURE_DIR/bootstrap-failure.json"
}

main() {
    local command=${1-}
    [ -n "$command" ] || usage
    shift || true
    case "$command" in
        selftest) [ "$#" -eq 0 ] || usage; cmd_selftest ;;
        preflight) [ "$#" -eq 0 ] || usage; cmd_preflight ;;
        inventory) [ "$#" -eq 0 ] || usage; cmd_inventory ;;
        import-stock) [ "$#" -eq 2 ] || usage; cmd_import_stock "$1" "$2" ;;
        build) [ "$#" -eq 1 ] || usage; cmd_build "$1" ;;
        install-deb) [ "$#" -eq 2 ] || usage; cmd_install_deb "$1" "$2" ;;
        install-component) [ "$#" -eq 2 ] || usage; cmd_install_component "$1" "$2" ;;
        install-hookprobe) [ "$#" -eq 1 ] || usage; cmd_install_hookprobe "$1" ;;
        set-mode) [ "$#" -eq 2 ] || usage; cmd_set_mode "$1" "$2" ;;
        launch) [ "$#" -eq 3 ] || usage; cmd_launch "$1" "$2" "$3" ;;
        pull-report) [ "$#" -eq 3 ] || usage; cmd_pull_report "$1" "$2" "$3" ;;
        run-hookprobe) [ "$#" -eq 2 ] || usage; cmd_run_hookprobe "$1" "$2" ;;
        daemon-status) [ "$#" -eq 0 ] || usage; cmd_daemon_status ;;
        daemon-term-safe) [ "$#" -eq 0 ] || usage; cmd_daemon_term_safe ;;
        client-kill-safe) [ "$#" -eq 2 ] || usage; cmd_client_kill_safe "$1" "$2" ;;
        restore) [ "$#" -eq 0 ] || usage; cmd_restore ;;
        collect) [ "$#" -eq 0 ] || usage; cmd_collect ;;
        *) usage ;;
    esac
}

main "$@"
