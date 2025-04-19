LLC ?= llc
CLANG ?= clang
CC ?= gcc

# Update includes and flags for newer kernel/libbpf versions
BPF_CFLAGS = -I. \
             -D__BPF_TRACING__ \
             -Wno-unused-value -Wno-pointer-sign \
             -Wno-compare-distinct-pointer-types \
             -Wno-gnu-variable-sized-type-not-at-end \
             -Wno-address-of-packed-member -Wno-tautological-compare \
             -Wno-unknown-warning-option \
             -g -O2

CFLAGS = -Wall -g -O2

XDP_TARGETS := xdp_port_drop.o
USER_TARGETS := xdp_loader

all: $(XDP_TARGETS) $(USER_TARGETS)

# Compile XDP program
xdp_port_drop.o: xdp_port_drop.c
	$(CLANG) -c $(BPF_CFLAGS) -target bpf -o $@ $<

# Alternative compilation method if the above fails
xdp_port_drop.o.alt: xdp_port_drop.c
	$(CLANG) -c $(BPF_CFLAGS) -o - $< | \
	$(LLC) -march=bpf -filetype=obj -o $@

# Compile user space program
xdp_loader: xdp_loader.c
	$(CC) $(CFLAGS) $< -lbpf -lelf -o $@

clean:
	rm -f $(XDP_TARGETS) $(USER_TARGETS)

.PHONY: all clean 