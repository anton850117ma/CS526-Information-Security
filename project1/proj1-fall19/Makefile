#
#  Note: You must run ./setcookie before running make.
#

CC := gcc
CFLAGS := -m32 -static -ggdb -U_FORTIFY_SOURCE -DCOOKIE=$(shell cat cookie) -Wno-implicit-function-declaration
LDFLAGS :=
LDLIBS :=

vulnerables := vulnerable1 vulnerable2 vulnerable3 vulnerable4 vulnerable5 vulnerable6 vulnerable7

.PHONY: default clean install uninstall

default: $(vulnerables) permissions

vulnerable1: CFLAGS += -fno-stack-protector -z execstack 
vulnerable2: CFLAGS += -fno-stack-protector -z execstack 
vulnerable3: CFLAGS += -fno-stack-protector -z execstack
vulnerable4: CFLAGS += -fstack-protector -z noexecstack
vulnerable4: CFLAGS := $(filter-out -static,$(CFLAGS))	
vulnerable5: CFLAGS += -fno-stack-protector -z execstack

vulnerable6: CFLAGS += -fno-stack-protector
vulnerable7: CFLAGS += -fno-stack-protector -z execstack


vulnerable1: vulnerable1.c helper.c
vulnerable2: vulnerable2.c helper.c
vulnerable3: vulnerable3.c helper.c
vulnerable4: vulnerable4.c helper.c
vulnerable5: vulnerable5.c helper.c
vulnerable6: vulnerable6.c helper.c
vulnerable7: vulnerable7.c helper.c


clean:
	rm -f $(vulnerables)

permissions:
	sudo chown root:cs526 vulnerable[1234567]
	sudo chmod 6777 vulnerable[1234567]

