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
emit_file ShadowCore me.jjolano.shadow /var/jb/Library/MobileSubstrate/DynamicLibraries/ShadowCore.dylib false
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
lines=$(sed -n '$=' "$log" 2>/dev/null || true)
printf 'log_lines\t%s\n' "${lines:-0}"
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
    local event remote before after delta before_lines after_lines job_pid rc
    require_clean_journal
    before="$CAPTURE_DIR/daemon-before.txt"; after="$CAPTURE_DIR/daemon-after.txt"
    remote=$(daemon_snapshot_remote)
    ssh_privileged "$remote" >"$before" 2>>"$CAPTURE_STDERR" || die 'daemon precheck transport failed'
    validate_daemon_snapshot "$before" false >>"$CAPTURE_STDOUT"
    before_lines=$(sed -n 's/^log_lines[[:space:]]//p' "$before" | head -1)
    job_pid=$(sed -n 's/^job_pid[[:space:]]//p' "$before" | head -1)
    [[ $before_lines =~ ^[0-9]+$ ]] || die 'invalid daemon log baseline'
    event=$(new_event_id)
    journal_event "$event" daemon-bootout system/me.jjolano.shadow bootstrap pending
    set +e
    ssh_privileged 'launchctl bootout system/me.jjolano.shadow' >>"$CAPTURE_STDOUT" 2>>"$CAPTURE_STDERR"
    rc=$?
    set -e
    [ "$rc" -eq 0 ] || die 'clean launchctl bootout failed'
    ssh_privileged "$remote" >"$after" 2>>"$CAPTURE_STDERR" || die 'daemon postcheck transport failed'
    validate_daemon_snapshot "$after" true >>"$CAPTURE_STDOUT"
    after_lines=$(sed -n 's/^log_lines[[:space:]]//p' "$after" | head -1)
    delta="$CAPTURE_DIR/daemon-exit-delta.txt"
    : >"$delta"
    if [[ $job_pid =~ ^[0-9]+$ ]]; then
        [[ $after_lines =~ ^[0-9]+$ ]] && [ "$after_lines" -gt "$before_lines" ] || die 'daemon emitted no new shutdown log'
        ssh_privileged "tail -n +$((before_lines + 1)) /var/jb/var/log/shadowd.log" >"$delta" 2>>"$CAPTURE_STDERR" || die 'daemon shutdown log capture failed'
        grep -F 'shadowd exiting' "$delta" >/dev/null || die 'clean shadowd exit log missing'
    fi
    journal_event "$event" daemon-bootout system/me.jjolano.shadow bootstrap completed
}

cmd_daemon_term_safe() {
    prepare_existing_run
    verify_device_identity
    capture_dir '' daemon-term-safe device
    daemon_term_safe_internal
    write_manifest daemon-term-safe '' not-applicable not-applicable 0 0 '' \
        "daemon-before=$CAPTURE_DIR/daemon-before.txt" "daemon-after=$CAPTURE_DIR/daemon-after.txt" \
        "daemon-exit-log=$CAPTURE_DIR/daemon-exit-delta.txt"
    printf '%s\n' "$CAPTURE_DIR/manifest.json"
}

process_row() {
    local pid=$1
    [[ $pid =~ ^[1-9][0-9]*$ ]] || return 1
    ssh_mobile "ps -o pid=,lstart=,comm= -p $pid"
}

cmd_client_kill_safe() {
    local pid=$1 lstart=$2 row parsed_start comm event rc
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
    if process_row "$pid" >/dev/null 2>&1; then die 'client PID still present or reused'; fi
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
    local flavor=$1 rc artifact_specs=() file frozen_dir frozen
    case "$flavor" in rootless|rootful) ;; *) die 'build flavor must be rootless or rootful' ;; esac
    prepare_existing_run
    capture_dir "$flavor" build host
    set +e
    bash "$REPO_ROOT/build.sh" "$flavor" >"$CAPTURE_STDOUT" 2>"$CAPTURE_STDERR"
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

find_local_recovery_deb() {
    local package_id=$1 version=$2 candidate tmp remote_info remote_copy hash script path expected kind
    local remote_script payload_expected payload_remote
    local matches=()
    while IFS= read -r -d '' candidate; do
        [ "$(dpkg-deb -f "$candidate" Package 2>/dev/null)" = "$package_id" ] || continue
        [ "$(dpkg-deb -f "$candidate" Version 2>/dev/null)" = "$version" ] || continue
        tmp=$(mktemp -d "${TMPDIR:-/tmp}/shadow-recovery-check.XXXXXX")
        if ! dpkg-deb -e "$candidate" "$tmp/control" >/dev/null 2>&1 ||
           ! dpkg-deb -x "$candidate" "$tmp/payload" >/dev/null 2>&1; then
            rm -rf "$tmp"; continue
        fi
        if [ -f "$tmp/control/md5sums" ]; then
            remote_info="/var/jb/var/lib/dpkg/info/$package_id.md5sums"
            remote_copy="$tmp/installed.md5sums"
            if ! scp_from "$remote_info" "$remote_copy" >/dev/null 2>&1 || ! cmp -s "$tmp/control/md5sums" "$remote_copy"; then
                rm -rf "$tmp"; continue
            fi
        fi
        for script in preinst postinst prerm postrm; do
            if [ -f "$tmp/control/$script" ]; then
                if ! scp_from "/var/jb/var/lib/dpkg/info/$package_id.$script" "$tmp/installed.$script" >/dev/null 2>&1 ||
                   ! cmp -s "$tmp/control/$script" "$tmp/installed.$script"; then
                    rm -rf "$tmp"; tmp=''; break
                fi
            elif ssh_mobile "test -e $(sq "/var/jb/var/lib/dpkg/info/$package_id.$script")" >/dev/null 2>&1; then
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
        hash=$(sha256_file "$candidate")
        matches+=("$hash|$candidate")
        rm -rf "$tmp"
    done < <(find "$REPO_ROOT/build" "$REPO_ROOT/packages" "$REPO_ROOT/ShadowHarness/packages" "$REPO_ROOT/tools/dyldprobe/build" -type f -name '*.deb' -print0 2>/dev/null)
    [ "${#matches[@]}" -gt 0 ] || return 1
    python3 - "${matches[@]}" <<'PY'
import sys
rows={item.split('|',1)[0]:item.split('|',1)[1] for item in sys.argv[1:]}
if len(rows)!=1: raise SystemExit('multiple non-identical local recovery packages match installed metadata')
print(next(iter(rows.values())))
PY
}

export_recovery_deb() {
    local package_id=$1 version=$2 out=$3 remote_path remote_copy event
    remote_path=$(ssh_privileged "find /var/jb/var/cache/apt/archives /var/cache/apt/archives -maxdepth 1 -type f -name '${package_id}_*.deb' 2>/dev/null | head -1")
    [ -n "$remote_path" ] || return 1
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
    local package=$1 package_id=$2 candidate_pkg candidate_version installed_version recovery recovery_source prefs_backup remote event upload_event rc uploaded_hash installed_after job candidate_copy snapshot package_status audit_file
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
    if ! scp_from /var/mobile/Library/Preferences/me.jjolano.shadow.plist "$prefs_backup" 2>>"$CAPTURE_STDERR"; then
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
    journal_event "$event" install-deb "$candidate_copy" "$recovery|$prefs_backup|$package_id" pending
    set +e
    ssh_privileged "dpkg -i $(sq "$remote")" >>"$CAPTURE_STDOUT" 2>>"$CAPTURE_STDERR"
    rc=$?
    set -e
    [ "$rc" -eq 0 ] || die 'dpkg install failed; run restore'
    installed_after=$(ssh_mobile "dpkg-query -W -f='\${Package} \${Version}' $package_id")
    [ "$installed_after" = "$package_id $candidate_version" ] || die 'installed package identity mismatch'
    ssh_privileged "rm -f $(sq "$remote")" >/dev/null
    journal_event "$upload_event" package-upload "$remote" absent restored
    journal_event "$event" install-deb "$candidate_copy" "$recovery|$prefs_backup|$package_id" completed
    write_manifest install-deb '' not-applicable not-applicable 0 0 '' "candidate=$candidate_copy" "recovery=$recovery" "preferences-before=$prefs_backup" "package-status-before=$package_status" "dpkg-audit-before=$audit_file"
    printf '%s\n' "$CAPTURE_DIR/manifest.json"
}

cmd_install_hookprobe() {
    local probe=$1 remote=/var/jb/usr/bin/hookprobe temp backup prior event upload_event remote_hash candidate_copy
    prepare_existing_run
    verify_device_identity
    [ -f "$probe" ] && [ ! -L "$probe" ] || die 'hookprobe candidate missing or unsafe'
    capture_dir '' install-hookprobe device
    candidate_copy="$CAPTURE_DIR/hookprobe.candidate"
    cp -p "$probe" "$candidate_copy"
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
    write_manifest install-hookprobe '' not-applicable not-applicable 0 0 '' "candidate=$candidate_copy"
    printf '%s\n' "$CAPTURE_DIR/manifest.json"
}

install_component_spec() {
    case "$1" in
        ShadowCore) printf '/var/jb/Library/MobileSubstrate/DynamicLibraries/ShadowCore.dylib\t0755\n' ;;
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

mutate_preferences() {
    local bundle=$1 mode=$2 action=$3 backup edited readback temp event
    backup="$CAPTURE_DIR/preferences.$action.before.plist"
    edited="$CAPTURE_DIR/preferences.$action.after.plist"
    readback="$CAPTURE_DIR/preferences.$action.readback.plist"
    scp_from /var/mobile/Library/Preferences/me.jjolano.shadow.plist "$backup" 2>>"$CAPTURE_STDERR" || die 'cannot back up Shadow preferences'
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
    journal_event "$event" "$action" "$bundle" "$backup|/var/mobile/Library/Preferences/me.jjolano.shadow.plist" pending
    temp="/var/mobile/Media/.shadow-prefs-$SHADOW_RUN_ID-$$-$RANDOM.plist"
    scp_to "$edited" "$temp" >>"$CAPTURE_STDOUT" 2>>"$CAPTURE_STDERR"
    ssh_privileged "install -o root -g wheel -m 0644 $(sq "$temp") /var/mobile/Library/Preferences/me.jjolano.shadow.plist && rm -f $(sq "$temp")" >>"$CAPTURE_STDOUT" 2>>"$CAPTURE_STDERR"
    ssh_mobile "launchctl kill SIGTERM gui/501/com.apple.cfprefsd.xpc.daemon 2>/dev/null || launchctl kill SIGTERM user/501/com.apple.cfprefsd.xpc.daemon 2>/dev/null || true" >>"$CAPTURE_STDOUT" 2>>"$CAPTURE_STDERR"
    sleep 15
    scp_from /var/mobile/Library/Preferences/me.jjolano.shadow.plist "$readback" 2>>"$CAPTURE_STDERR" || die 'preferences readback failed'
    python3 - "$edited" "$readback" "$bundle" <<'PY'
import plistlib,sys
def load(path):
    with open(path,'rb') as f: return plistlib.load(f)
a=load(sys.argv[1]).get(sys.argv[3]); b=load(sys.argv[2]).get(sys.argv[3])
if a!=b: raise SystemExit('preferences readback mismatch')
PY
    journal_event "$event" "$action" "$bundle" "$backup|/var/mobile/Library/Preferences/me.jjolano.shadow.plist" completed
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
    local bundle=$1 file result
    file=$(mktemp "${TMPDIR:-/tmp}/shadow-prefs.XXXXXX")
    scp_from /var/mobile/Library/Preferences/me.jjolano.shadow.plist "$file" >/dev/null 2>&1 || { rm -f "$file"; return 1; }
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
    local target=$1 prior=$2 lstart comm current
    if [[ $target =~ ^[1-9][0-9]*$ ]]; then
        IFS='|' read -r lstart comm <<<"$prior"
        current=$(find_process_exact "$comm") || die 'launched process discovery is ambiguous during restore'
        [ -n "$current" ] || return 0
        [ "$(printf '%s' "$current" | cut -f1,2)" = "$target"$'\t'"$lstart" ] || return 0
    else
        current=$(find_process_exact "$target") || die 'pending launched process discovery is ambiguous during restore'
        [ -n "$current" ] || return 0
    fi
    terminate_exact_process "$current"
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
    local bundle=$1 mode=$2 nonce=$3 documents=$4 remote local_file backup prior event forced_failure=${SHADOW_FORCE_FAILURE_ID:-}
    [ "${#forced_failure}" -le 200 ] || die 'forced failure ID is too long'
    [[ $forced_failure != *$'\n'* && $forced_failure != *$'\r'* ]] || die 'forced failure ID contains a newline'
    remote="$documents/.ShadowStealthContext.json"
    local_file="$CAPTURE_DIR/stealth-context.json"
    python3 - "$local_file" "$SHADOW_RUN_ID" "$SHADOW_ROW_ID" "$mode" "$nonce" "$TASK_REVISION" "$forced_failure" <<'PY'
import json,os,pathlib,sys
p=pathlib.Path(sys.argv[1]); d={'schema_version':1,'run_id':sys.argv[2],'row_id':sys.argv[3],
 'requested_mode':sys.argv[4],'nonce':sys.argv[5],'probe_revision':sys.argv[6]}
if sys.argv[7]: d['force_failure_id']=sys.argv[7]
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

bundle_report_relative() {
    case "$1" in
        me.jjolano.shadow.harness) printf 'ShadowDiagnostics-%s.json' "$2" ;;
        me.jjolano.dyldprobe) printf 'dyldprobe-%s.json' "$2" ;;
        *) return 1 ;;
    esac
}

prepare_launch_report_file() {
    local bundle=$1 nonce=$2 documents=$3 relative remote event
    relative=$(bundle_report_relative "$bundle" "$nonce") || return
    remote="$documents/$relative"
    ssh_mobile "test ! -e $(sq "$remote")" || die 'nonce report already exists'
    event=$(new_event_id)
    journal_event "$event" launch-report-file "$remote" "absent|$remote" pending
    LAUNCH_REPORT_EVENT=$event
	LAUNCH_REPORT_FILE=$remote
}

verification_launch_remote() {
	local mode=$1 executable=$2 container=$3 safe_mode=''
	if [ "$mode" = uninjected ]; then safe_mode='_MSSafeMode=1 '; fi
	printf '%sCFFIXED_USER_HOME=%s HOME=%s TMPDIR=%s nohup %s --shadow-headless-producer </dev/null >/dev/null 2>&1 &' \
		"$safe_mode" "$(sq "$container")" "$(sq "$container")" "$(sq "$container/tmp")" "$(sq "$executable")"
}

uses_direct_verification_launch() {
	[ "$2" = cold ] && [ "$3" = uninjected ] &&
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
	local bundle=$1 transition=$2 nonce=$3 executable mode pre='' pre_original='' pre_state='' post='' launch_event='' post_pid post_lstart post_comm container documents launch_remote
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
	write_launch_context_file "$bundle" "$mode" "$nonce" "$documents"
	prepare_launch_report_file "$bundle" "$nonce" "$documents"
    if [ "$transition" = cold ]; then
        launch_event=$(new_event_id)
        journal_event "$launch_event" launch-process "$executable" "absent|$executable" pending
    fi
	if uses_direct_verification_launch "$bundle" "$transition" "$mode"; then
		launch_remote=$(verification_launch_remote "$mode" "$executable" "$container")
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
    [ -n "$post" ] || die 'launched process not found'
    if [ "$transition" = warm ]; then
        [ "$(printf '%s' "$pre" | cut -f1,2)" = "$(printf '%s' "$post" | cut -f1,2)" ] || die 'warm launch changed process identity'
    else
        IFS=$'\t' read -r post_pid post_lstart _ post_comm <<<"$post"
        journal_event "$launch_event" launch-process "$post_pid" "$post_lstart|$post_comm" completed
    fi
	journal_event "$LAUNCH_REPORT_EVENT" launch-report-file "$LAUNCH_REPORT_FILE" "absent|$LAUNCH_REPORT_FILE" completed
    write_manifest launch "$nonce" "$mode" "$mode" 0 0 '' "launch-context=$LAUNCH_CONTEXT_FILE"
    patch_launch_manifest "$CAPTURE_DIR/manifest.json" "$transition" "$pre_original" "$post" "$mode"
    printf '%s\n' "$CAPTURE_DIR/manifest.json"
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
    python3 - "$report" "$nonce" "$SHADOW_RUN_ID" "$SHADOW_ROW_ID" "$TASK_REVISION" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
want={'nonce':sys.argv[2],'run_id':sys.argv[3],'row_id':sys.argv[4],'probe_revision':sys.argv[5]}
for k,v in want.items():
    if d.get(k)!=v: raise SystemExit(f'report provenance mismatch: {k}')
PY
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

cmd_run_hookprobe() {
    local mode=$1 nonce=$2 privileged=false command rc producer raw_report auth=''
    is_hookprobe_mode "$mode" || die "unsupported hookprobe mode: $mode"
    [[ $nonce =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || die 'invalid nonce'
    prepare_existing_run
    verify_device_identity
    capture_dir "$nonce" run-hookprobe device
    case "$mode" in
        lifecycle-daemon-zero-resource-restart|lifecycle-backend-absent-springboard-restart|lifecycle-backend-absent-userspace-reboot) privileged=true ;;
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
            ;;
    esac
    command="/var/jb/usr/bin/hookprobe --mode $(sq "$mode") --nonce $(sq "$nonce") --run-id $(sq "$SHADOW_RUN_ID") --row-id $(sq "$SHADOW_ROW_ID") --probe-revision $(sq "$TASK_REVISION") --requested-mode injected; code=\$?; printf '__SHADOW_PRODUCER_EXIT__%s\\n' \"\$code\" >&2; exit 0"
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
    write_manifest run-hookprobe "$nonce" injected injected "$rc" "$producer" '' "raw-report=$raw_report"
    [ -z "$auth" ] || patch_authorization_manifest "$CAPTURE_DIR/manifest.json" "$auth"
    [ "$rc" -eq 0 ] || die 'hookprobe transport/setup failed'
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
    local backup=$1 remote=/var/mobile/Library/Preferences/me.jjolano.shadow.plist temp
    [ -f "$backup" ] || die "missing preferences backup: $backup"
    temp="/var/mobile/Media/.shadow-restore-prefs-$SHADOW_RUN_ID-$$-$RANDOM.plist"
    scp_to "$backup" "$temp" >>"$CAPTURE_STDOUT" 2>>"$CAPTURE_STDERR"
    ssh_privileged "install -o root -g wheel -m 0644 $(sq "$temp") $(sq "$remote") && rm -f $(sq "$temp")" >>"$CAPTURE_STDOUT" 2>>"$CAPTURE_STDERR"
    ssh_mobile 'launchctl kill SIGTERM gui/501/com.apple.cfprefsd.xpc.daemon 2>/dev/null || launchctl kill SIGTERM user/501/com.apple.cfprefsd.xpc.daemon 2>/dev/null || true' >/dev/null
    [ "$(ssh_mobile "sha256sum $(sq "$remote") | cut -d' ' -f1")" = "$(sha256_file "$backup")" ] || die 'restored preferences hash mismatch'
}

safe_bootout_for_restore() {
    local remote before after delta job job_pid before_lines after_lines
    remote=$(daemon_snapshot_remote)
    before="$CAPTURE_DIR/restore-daemon-before-$RANDOM.txt"
    after="$CAPTURE_DIR/restore-daemon-after-$RANDOM.txt"
    ssh_privileged "$remote" >"$before" 2>>"$CAPTURE_STDERR" || die 'restore daemon precheck failed'
    validate_daemon_snapshot "$before" false >/dev/null
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

restore_package_event() {
    local prior=$1 recovery prefs package_id temp pkg version installed
    IFS='|' read -r recovery prefs package_id <<<"$prior"
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
    if [ -f "$prefs" ] && ! grep -F -x ABSENT "$prefs" >/dev/null 2>&1; then restore_preferences_file "$prefs"; fi
}

cmd_restore() {
    local events event action target prior state backup remote mode temp staged restore_dir restore_stdout restore_stderr inventory_manifest daemon_restore_snapshot
    prepare_restore || return
    verify_device_identity || return
    capture_dir '' restore device
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
                restore_preferences_file "$backup"
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
            install-component)
                IFS='|' read -r backup remote mode <<<"$prior"
                [ -f "$backup" ] || die 'component backup missing'
                temp="/var/mobile/Media/.shadow-component-restore-$SHADOW_RUN_ID-$$"
                staged="$remote.new.$SHADOW_RUN_ID.$$"
                scp_to "$backup" "$temp" >>"$CAPTURE_STDOUT" 2>>"$CAPTURE_STDERR"
                ssh_privileged "install -o root -g wheel -m $mode $(sq "$temp") $(sq "$staged") && mv -f $(sq "$staged") $(sq "$remote") && rm -f $(sq "$temp")" >>"$CAPTURE_STDOUT" 2>>"$CAPTURE_STDERR"
                [ "$(ssh_privileged "sha256sum $(sq "$remote") | cut -d' ' -f1")" = "$(sha256_file "$backup")" ] || die 'restored component hash mismatch'
                ;;
            install-deb) restore_package_event "$prior" ;;
            package-upload|recovery-export) ssh_privileged "rm -f $(sq "$target")" >>"$CAPTURE_STDOUT" 2>>"$CAPTURE_STDERR" ;;
            daemon-bootout)
                if ssh_privileged 'test -f /var/jb/Library/LaunchDaemons/me.jjolano.shadow.plist'; then
                    ssh_privileged 'launchctl bootstrap system /var/jb/Library/LaunchDaemons/me.jjolano.shadow.plist 2>/dev/null || launchctl kickstart system/me.jjolano.shadow' >>"$CAPTURE_STDOUT" 2>>"$CAPTURE_STDERR"
                fi
                ;;
            daemon-idle) : ;;
            launch-process) restore_launch_process "$target" "$prior" ;;
            launch-terminate|client-sigkill) ;;
            *) die "unknown cleanup action: $action" ;;
        esac
        journal_event "$event" "$action" "$target" "$prior" restored
    done <<<"$events"
    daemon_restore_snapshot="$CAPTURE_DIR/restore-daemon-state.txt"
    ssh_privileged "$(daemon_snapshot_remote)" >"$daemon_restore_snapshot" 2>>"$CAPTURE_STDERR" || die 'restore daemon state capture failed'
    validate_daemon_snapshot "$daemon_restore_snapshot" false >/dev/null
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
    write_manifest restore '' not-applicable not-applicable 0 0 '' \
        "final-inventory=$inventory_manifest" "restore-daemon-state=$daemon_restore_snapshot"
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
    trap 'rm -rf "$tmp"' EXIT
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

    mkdir -p "$tmp/recovery/dir"
    printf x >"$tmp/recovery/dir/file"
    ln -s dir "$tmp/recovery/link"
    recovery=$(recovery_payload_manifest "$tmp/recovery")
    if ! printf '%s\n' "$recovery" | grep -q $'^L\tdir\t/link$' ||
       ! printf '%s\n' "$recovery" | grep -q $'^F\t[0-9a-f]\{64\}\t/dir/file$'; then
        printf 'FAIL recovery symlink manifest\n'; failed=1
    fi

    local killed=''
    find_process_exact() { printf '42\tstart\tRs\t/app\n'; }
    terminate_exact_process() { killed=$1; }
    restore_launch_process 42 'start|/app'
    if [ -z "$killed" ]; then printf 'FAIL launched process cleanup\n'; failed=1; fi
    killed=''
    restore_launch_process 41 'start|/app'
    if [ -n "$killed" ]; then printf 'FAIL launched PID reuse refusal\n'; failed=1; fi
    if [ "$(bundle_report_relative me.jjolano.shadow.harness nonce)" != ShadowDiagnostics-nonce.json ] ||
       [ "$(bundle_report_relative me.jjolano.dyldprobe nonce)" != dyldprobe-nonce.json ]; then
        printf 'FAIL launch report filename mapping\n'; failed=1
    fi
	if [ "$(install_component_spec ShadowCore)" != $'/var/jb/Library/MobileSubstrate/DynamicLibraries/ShadowCore.dylib\t0755' ] ||
	   [ "$(install_component_spec ShadowStub)" != $'/var/jb/Library/MobileSubstrate/DynamicLibraries/Shadow.dylib\t0755' ] ||
	   [ "$(install_component_spec DyldProbe)" != $'/var/jb/Applications/dyldprobe.app/dyldprobe\t0755' ] ||
	   install_component_spec unknown >/dev/null 2>&1; then
		printf 'FAIL component install allowlist\n'; failed=1
	fi
	local direct_control direct_injected
	direct_control=$(verification_launch_remote uninjected /app /container)
	direct_injected=$(verification_launch_remote injected /app /container)
	if [[ $direct_control != _MSSafeMode=1* ]] || [[ $direct_injected == *'_MSSafeMode=1'* ]] ||
	   [[ $direct_injected != *"CFFIXED_USER_HOME='/container'"* ]] ||
	   [[ $direct_injected != *"'/app' --shadow-headless-producer </dev/null"* ]] ||
	   ! uses_direct_verification_launch me.jjolano.shadow.harness cold uninjected ||
	   uses_direct_verification_launch me.jjolano.shadow.harness cold injected ||
	   uses_direct_verification_launch me.jjolano.shadow.harness warm uninjected; then
		printf 'FAIL verification producer launch mapping\n'; failed=1
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
    printf 'PASS stealth-device selftest (fake ssh/scp/sudo; launch/report cleanup; timeout manifest; drift-safe restore; 13 refusal classes)\n'
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
emit_component ShadowCore /var/jb/Library/MobileSubstrate/DynamicLibraries/ShadowCore.dylib
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
if any(v!='absent' for v in absent.values()): raise SystemExit('unexpected device tool present')
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
