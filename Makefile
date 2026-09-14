# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
# Agentmo — libbpf CO-RE build.
#
# TARGET: mdx head-node-zhang, Ubuntu 22.04 / kernel 5.15 / x86_64.
#
# Toolchain (already installed there, see MDX_DEPLOY.md 3.2):
#   clang 14, bpftool v5.15.x, libbpf 1.5.0 built from source into /usr/local
#
# !! DO NOT `apt install libbpf-dev` on 22.04 !!
#    Jammy ships libbpf 0.5; this build needs >= 0.8 (bpf_map__lookup_elem,
#    the 1.x ring_buffer API). If a 0.5 libbpf is installed it will be found
#    first via /usr/include and /usr/lib/x86_64-linux-gnu and the build will
#    either fail with missing prototypes or — worse — link against the wrong
#    .so at runtime. The explicit -I/-L below pin /usr/local ahead of both.
#
# Filenames are capitalised (Agentmo.*, Envelope.bpf.h). The 8/25 Makefile had
# APP := agentmo, which cannot work on a case-sensitive filesystem.

APP        := Agentmo
EVOP       := Envelope

ARCH       := $(shell uname -m | sed 's/x86_64/x86/;s/aarch64/arm64/')
CLANG      ?= clang
BPFTOOL    ?= bpftool

# libbpf 1.5 lives in /usr/local. Pin it ahead of any distro copy.
LIBBPF_PREFIX ?= /usr/local
LIBBPF_INC    := $(LIBBPF_PREFIX)/include
LIBBPF_LIB    := $(LIBBPF_PREFIX)/lib

# -DAM_HAVE_DPATH_PROG tells Agentmo.c that this .bpf.c provides the
# security_file_open program, which is what makes AM_DPATH=1 work. Drop it only
# if you deliberately build a no-d_path object.
CFLAGS     := -g -O2 -Wall -DAM_HAVE_DPATH_PROG
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -I. -I$(LIBBPF_INC)

# Clang's system include dirs, added with -idirafter so -target bpf still finds
# asm/types.h etc. (same trick as libbpf-bootstrap).
CLANG_SYS_INCLUDES := $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

.PHONY: all clean check-libbpf
all: $(APP)

# Fail loudly and early rather than at a confusing link error.
check-libbpf:
	@test -f $(LIBBPF_INC)/bpf/libbpf.h || { \
	  echo "ERROR: $(LIBBPF_INC)/bpf/libbpf.h missing."; \
	  echo "       Build libbpf 1.5 from source (MDX_DEPLOY.md 3.2) — do NOT apt install libbpf-dev."; \
	  exit 1; }
	@grep -q 'LIBBPF_MAJOR_VERSION 1' $(LIBBPF_INC)/bpf/libbpf_version.h 2>/dev/null || { \
	  echo "ERROR: libbpf at $(LIBBPF_PREFIX) is not 1.x."; exit 1; }

# 1) vmlinux.h from the running kernel's BTF (CO-RE)
vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

# 2) kernel BPF object
$(APP).bpf.o: $(APP).bpf.c $(APP).h $(EVOP).bpf.h vmlinux.h
	$(CLANG) $(BPF_CFLAGS) $(CLANG_SYS_INCLUDES) -c $(APP).bpf.c -o $@

# 3) skeleton header
$(APP).skel.h: $(APP).bpf.o
	$(BPFTOOL) gen skeleton $< > $@

# 4) userspace control plane
$(APP): check-libbpf $(APP).c $(APP).skel.h $(APP).h
	$(CC) $(CFLAGS) -I. -I$(LIBBPF_INC) $(APP).c -o $@ \
	      -L$(LIBBPF_LIB) -Wl,-rpath,$(LIBBPF_LIB) -lbpf -lelf -lz

clean:
	rm -f $(APP) $(APP).bpf.o $(APP).skel.h vmlinux.h
