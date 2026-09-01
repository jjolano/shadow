#import <dlfcn.h>
#import <errno.h>
#import <fcntl.h>
#import <mach/exception_types.h>
#import <mach/host_special_ports.h>
#import <mach/mach.h>
#import <mach/task_special_ports.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <bootstrap.h>
#import <stdio.h>
#import <string.h>
#import <sys/stat.h>
#import <sys/wait.h>
#import <unistd.h>

const char *SHDWFreeRASPGenericProbeJSON(void) {
    static char json[1024];
    mach_port_t port = MACH_PORT_NULL;
    kern_return_t bootstrap = bootstrap_look_up(bootstrap_port, "me.jjolano.shadow.service", &port);
    unsigned bootstrapPort = port;
    if(port != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), port);

    port = MACH_PORT_NULL;
    host_t host = mach_host_self();
    kern_return_t hostPriv = host_get_special_port(host, HOST_LOCAL_NODE, HOST_PRIV_PORT, &port);
    unsigned hostPrivPort = port;
    if(port != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), port);
    if(host != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), host);

    port = MACH_PORT_NULL;
    kern_return_t taskDebug = task_get_special_port(mach_task_self(), TASK_DEBUG_CONTROL_PORT, &port);
    unsigned taskDebugPort = port;
    if(port != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), port);

    port = MACH_PORT_NULL;
    kern_return_t taskBootstrap = task_get_special_port(mach_task_self(), TASK_BOOTSTRAP_PORT, &port);
    unsigned taskBootstrapPort = port;
    if(port != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), port);

    port = MACH_PORT_NULL;
    kern_return_t foreignTask = task_for_pid(mach_task_self(), 1, &port);
    unsigned foreignTaskPort = port;
    if(port != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), port);

    struct stat status = {0};
    errno = 0;
    int prebootStat = stat("/private/preboot", &status);
    int prebootErrno = errno;
    errno = 0;
    int daemonStat = stat("/Library/LaunchDaemons", &status);
    int daemonErrno = errno;

    errno = 0;
    int prebootOpen = open("/private/preboot", O_NOFOLLOW);
    int prebootOpenErrno = errno;
    if(prebootOpen >= 0) close(prebootOpen);

    errno = 0;
    pid_t forkResult = fork();
    int forkErrno = errno;
    if(forkResult == 0) _exit(0);
    if(forkResult > 0) waitpid(forkResult, NULL, 0);

    unsigned rawSvcSites = 0;
    int talsecLoaded = 0;
    for(uint32_t image = 0; image < _dyld_image_count(); image++) {
        const char *name = _dyld_get_image_name(image);
        const struct mach_header_64 *header = (const struct mach_header_64 *)_dyld_get_image_header(image);
        if(!name || !header || !strstr(name, "/TalsecRuntime.framework/TalsecRuntime")) continue;
        talsecLoaded = 1;
        const struct load_command *command = (const struct load_command *)(header + 1);
        intptr_t slide = _dyld_get_image_vmaddr_slide(image);
        for(uint32_t commandIndex = 0; commandIndex < header->ncmds; commandIndex++) {
            if(command->cmd == LC_SEGMENT_64) {
                const struct segment_command_64 *segment = (const struct segment_command_64 *)command;
                if(!strcmp(segment->segname, "__TEXT")) {
                    const uint32_t *instructions = (const uint32_t *)(segment->vmaddr + slide);
                    for(size_t word = 0; word < segment->filesize / sizeof(*instructions); word++) {
                        if((instructions[word] & 0xFFE0001FU) == 0xD4000001U) rawSvcSites++;
                    }
                    break;
                }
            }
            command = (const struct load_command *)((const char *)command + command->cmdsize);
        }
        break;
    }

    void *forkSymbol = dlsym(RTLD_DEFAULT, "fork");
    Dl_info info = {0};
    int forkOrigin = forkSymbol && dladdr(forkSymbol, &info) != 0 && info.dli_fname
        ? (!strncmp(info.dli_fname, "/System/", 8) || !strncmp(info.dli_fname, "/usr/lib/", 9) ? 1 : 2)
        : 0;

    exception_mask_t masks[EXC_TYPES_COUNT] = {0};
    exception_handler_t handlers[EXC_TYPES_COUNT] = {0};
    exception_behavior_t behaviors[EXC_TYPES_COUNT] = {0};
    thread_state_flavor_t flavors[EXC_TYPES_COUNT] = {0};
    mach_msg_type_number_t handlerCount = EXC_TYPES_COUNT;
    kern_return_t exceptionPorts = task_get_exception_ports(
        mach_task_self(), EXC_MASK_ALL, masks, &handlerCount, handlers, behaviors, flavors);
    unsigned liveHandlers = 0;
    if(exceptionPorts == KERN_SUCCESS) {
        for(mach_msg_type_number_t i = 0; i < handlerCount && i < EXC_TYPES_COUNT; i++) {
            if(handlers[i] != MACH_PORT_NULL) {
                liveHandlers++;
                mach_port_deallocate(mach_task_self(), handlers[i]);
            }
        }
    }

    snprintf(json, sizeof(json),
        "{\"bootstrap\":{\"kr\":%d,\"port\":%u},"
        "\"hostPriv\":{\"kr\":%d,\"port\":%u},"
        "\"taskDebug\":{\"kr\":%d,\"port\":%u},"
        "\"taskBootstrap\":{\"kr\":%d,\"port\":%u},"
        "\"foreignTask\":{\"kr\":%d,\"port\":%u},"
        "\"paths\":{\"prebootStat\":%d,\"prebootErrno\":%d,\"prebootOpen\":%d,\"prebootOpenErrno\":%d,\"launchDaemonsStat\":%d,\"launchDaemonsErrno\":%d},"
        "\"forkCall\":{\"result\":%d,\"errno\":%d},"
        "\"talsecSvc\":{\"loaded\":%d,\"raw\":%u},"
        "\"fork\":{\"symbol\":%d,\"origin\":%d},"
        "\"exceptionPorts\":{\"kr\":%d,\"handlers\":%u}}",
        bootstrap, bootstrapPort, hostPriv, hostPrivPort, taskDebug, taskDebugPort,
        taskBootstrap, taskBootstrapPort, foreignTask, foreignTaskPort,
        prebootStat, prebootErrno, prebootOpen, prebootOpenErrno, daemonStat, daemonErrno,
        (int)forkResult, forkErrno,
        talsecLoaded, rawSvcSites,
        forkSymbol != NULL, forkOrigin, exceptionPorts, liveHandlers);
    return json;
}
