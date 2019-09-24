#include <asm/unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include "common.h"
#ifndef __NR_trigger_bug
#error trigger_bug system call not defined
#endif

int main(int argc, char *argv[])
{
	int rc =0;
	int bug_code = 0;
	char *arg = NULL;

	if (argc < 2) {
		printf("Missing argument for bug type\n");
		goto out;
	}

	arg = argv[1];
	rc = atoi(arg);

       	if (rc <= 0 || rc > 13) {
        	printf("Invalid argument given for bug type\n");
                goto out;
        }

        bug_code = (uint) strtol(arg, &(arg), 0);

	if (bug_code == 0) {
		printf("Invalid bug type\n");
		goto out;
	}

	switch(bug_code) {
		case BUG_RW_SEMAPHORE:
			bug_code = BUG_RW_SEMAPHORE;
			break;
		case BUG_SLEEP_INSIDE_ATOMIC_SECTION:
			bug_code = BUG_SLEEP_INSIDE_ATOMIC_SECTION;
			break;
		case BUG_KERNEL_MEM_LEAK:
			bug_code = BUG_KERNEL_MEM_LEAK;
			break;
		case BUG_DEBUG_VM_PAGE:
			bug_code = BUG_DEBUG_VM_PAGE;
			break;
		case BUG_DEADLOCK:
			bug_code = BUG_DEADLOCK;
			break;
		case BUG_SOFT_LOCKUP:
			bug_code = BUG_SOFT_LOCKUP;
			break;
		case BUG_LINKED_LIST_CORRUPTION:
			bug_code = BUG_LINKED_LIST_CORRUPTION;
			break;
		case BUG_DMA_API:
			bug_code = BUG_DMA_API;
			break;
		case BUG_INVALID_NOTIFIER:
			bug_code = BUG_INVALID_NOTIFIER;
			break;
		case BUG_SCATTERLIST_CHAINED:
			bug_code = BUG_SCATTERLIST_CHAINED;
			break;
		case SLAB_VALIDATOR:
			bug_code = SLAB_VALIDATOR;
			break;
        case BUG_HUNG_TASK:
            bug_code = BUG_HUNG_TASK;
            break;
        case BUG_CRED_MANAGEMENT:
			bug_code = BUG_CRED_MANAGEMENT;
			break;
		default:
			printf("Invalid bug type\n");
			goto out;
	}

    	rc = syscall(__NR_trigger_bug , bug_code);

	if (rc == 0)
        	printf("syscall returned %d\n", rc);
    	else
        	printf("syscall returned %d (errno=%d)\n", rc, errno);
out:

    	exit(rc);
}

