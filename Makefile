obj-m += sys_trigger_bug.o
#CFLAGS += -O0

INC=/lib/modules/$(shell uname -r)/build/arch/x86/include

ULIBS=

all: sys_trigger_bug xtrigger_bug

xtrigger_bug: 
	gcc -Wall -Werror -I$(INC)/generated/uapi -I$(INC)/uapi xtrigger_bug.c -o xtrigger_bug $(ULIBS)

sys_trigger_bug:
	make  -Wall -Werror -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -f xtrigger_bug *.o
