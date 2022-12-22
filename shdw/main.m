#include <stdio.h>
#include <unistd.h>

#import "../api/Shadow.h"

int main(int argc, char *argv[], char *envp[]) {
    @autoreleasepool {
        if(argc == 1) {
            printf("shdw - utility to test path restrictions\n");
            printf("usage: %s [-s] <path> [path [...]]\n", argv[0]);
            printf("\t-s: use Shadow Service\n");

            return 0;
        }

        bool useService = false;

        int opt;

        while((opt = getopt(argc, argv, "s")) != -1) {
            switch(opt) {
                case 's':
                    useService = true;
                    break;
            }
        }

        ShadowService* srv = [ShadowService new];

        if(!srv) {
            fprintf(stderr, "error: could not init ShadowService\n");
            return -1;
        }

        if(useService) {
            [srv connectService];
        } else {
            [srv startLocalService];
        }

        Shadow* shadow = [Shadow shadowWithService:srv];

        if(!shadow) {
            fprintf(stderr, "error: could not init Shadow\n");
            return -1;
        }

        for(int i = optind; i < argc; i++) {
            // ignore relative paths
            if(argv[i][0] != '/') {
                continue;
            }

            BOOL restricted = [shadow isCPathRestricted:argv[i]];
            printf("%s: %s\n", argv[i], restricted ? "restricted" : "allowed");
        }

        return 0;
    }
}
