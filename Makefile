KVER   ?= $(shell uname -r)
KDIR   ?= /lib/modules/$(KVER)/build/
DEPMOD  = /sbin/depmod -a
CC     ?= gcc
obj-m   = xt_CGNAT.o
CFLAGS_xt_CGNAT.o := -DDEBUG

all: xt_CGNAT.ko libxt_CGNAT.so

xt_CGNAT.ko: xt_CGNAT.c
	# To force DWARF/debug info for the module, append CONFIG_DEBUG_INFO=y to this make invocation.
	make -C $(KDIR) M=$(CURDIR) modules
	-sync

%_sh.o: libxt_CGNAT.c
	gcc -O2 -Wall -Wunused -fPIC -o $@ -c $<

%.so: %_sh.o
	gcc -shared -o $@ $<

sparse: clean | xt_CGNAT.c xt_CGNAT.h
	make -C $(KDIR) M=$(CURDIR) modules C=1

cppcheck:
	cppcheck -I $(KDIR)/include --enable=all --inconclusive xt_CGNAT.c
	cppcheck libxt_CGNAT.c

coverity:
	coverity-submit -v

clean:
	make -C $(KDIR) M=$(CURDIR) clean
	-rm -f *.so *_sh.o *.o modules.order

install: | minstall linstall

minstall: | xt_CGNAT.ko
	make -C $(KDIR) M=$(CURDIR) modules_install INSTALL_MOD_PATH=$(DESTDIR)

linstall: libxt_CGNAT.so
	install -D $< $(DESTDIR)$(shell pkg-config --variable xtlibdir xtables)/$<

uninstall:
	-rm -f $(DESTDIR)$(shell pkg-config --variable xtlibdir xtables)/libxt_CGNAT.so
	-rm -f $(KDIR)/extra/xt_CGNAT.ko

load: all
	-sync
	-modprobe x_tables
	-mkdir -p /lib64/modules/`uname -r`/kernel/net/ipv4/
	-cp xt_CGNAT.ko /lib64/modules/`uname -r`/kernel/net/ipv4/
	-depmod `uname -r`
	-modprobe xt_CGNAT
	-iptables-restore < iptables.rules
	-conntrack -F
unload:
	-/etc/init.d/iptables restart
	-rmmod xt_CGNAT.ko
del:
	-sync
reload: unload clean load

.PHONY: all minstall linstall install uninstall clean cppcheck
