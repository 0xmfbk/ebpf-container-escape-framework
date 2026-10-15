CLANG ?= clang
CFLAGS = -O2 -g -target bpf -D__TARGET_ARCH_x86

all: kernel/bpf_program.o

kernel/bpf_program.o: kernel/bpf_program.c common/common.h kernel/vmlinux.h
	$(CLANG) $(CFLAGS) -c kernel/bpf_program.c -o kernel/bpf_program.o

clean:
	rm -f kernel/*.o
