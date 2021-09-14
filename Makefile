CC = clang

BUILDDIR = build
SRCDIR = src

LIBBPFSRC = libbpf/src
LIBBPFOBJS = $(LIBBPFSRC)/staticobjs/bpf_prog_linfo.o $(LIBBPFSRC)/staticobjs/bpf.o $(LIBBPFSRC)/staticobjs/btf_dump.o
LIBBPFOBJS += $(LIBBPFSRC)/staticobjs/btf.o  $(LIBBPFSRC)/staticobjs/gen_loader.o $(LIBBPFSRC)/staticobjs/hashmap.o $(LIBBPFSRC)/staticobjs/libbpf_errno.o
LIBBPFOBJS += $(LIBBPFSRC)/staticobjs/libbpf_probes.o $(LIBBPFSRC)/staticobjs/libbpf.o $(LIBBPFSRC)/staticobjs/linker.o $(LIBBPFSRC)/staticobjs/netlink.o
LIBBPFOBJS += $(LIBBPFSRC)/staticobjs/nlattr.o $(LIBBPFSRC)/staticobjs/ringbuf.o $(LIBBPFSRC)/staticobjs/str_error.o $(LIBBPFSRC)/staticobjs/strset.o
LIBBPFOBJS += $(LIBBPFSRC)/staticobjs/xsk.o

LOADERSRC = loader.c
LOADEROUT = tcpopts
LOADERFLAGS = -lelf -lz

XDPSRC = xdp_prog.c
XDPBC = xdp.bc
XDPOBJ = xdp.o

INCS = -I $(LIBBPFSRC)

all: loader xdp
xdp:
	mkdir -p $(BUILDDIR)
	clang $(INCS) -D__BPF__ -Wall -Wextra -O2 -emit-llvm -c $(SRCDIR)/$(XDPSRC) -o $(BUILDDIR)/$(XDPBC)
	llc -march=bpf -filetype=obj $(BUILDDIR)/$(XDPBC) -o $(BUILDDIR)/$(XDPOBJ)
loader: libbpf
	mkdir -p $(BUILDDIR)
	clang $(INCS) $(LOADERFLAGS) -O3 -o $(BUILDDIR)/$(LOADEROUT) $(LIBBPFOBJS) $(SRCDIR)/$(LOADERSRC)
libbpf:
	$(MAKE) -C $(LIBBPFSRC)
install:
	mkdir -p /etc/tcpopts
	cp $(BUILDDIR)/$(XDPOBJ) /etc/tcpopts/$(XDPOBJ)
	cp $(BUILDDIR)/$(LOADEROUT) /usr/bin/$(LOADEROUT)
clean:
	$(MAKE) -C $(LIBBPFSRC) clean
	rm -f $(BUILDDIR)/*
.PHONY: libbpf xdp loader
.DEFAULT: all