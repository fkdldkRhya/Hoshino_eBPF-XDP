#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>       /* 추가: IPPROTO_* 정의 */
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h> /* 추가: bpf_ntohs, bpf_htons */

#define MAX_PORTS 10  // 최대 차단할 포트 수

// Define a map to store multiple ports to block
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_PORTS);
    __type(key, __u16);
    __type(value, __u8);
} port_map SEC(".maps");

SEC("xdp")
int xdp_port_dropper(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    // Ethernet header parsing
    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > data_end)
        return XDP_PASS;
    
    // Check if it's an IP packet (we only care about IPv4 for simplicity)
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;
    
    // IP header parsing
    struct iphdr *iph = (void*)(eth + 1);
    if ((void*)(iph + 1) > data_end)
        return XDP_PASS;
    
    // Check protocol (TCP or UDP)
    if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP)
        return XDP_PASS;
    
    __u16 port = 0;
    __u8 *found;
    
    // Check port based on protocol
    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (void*)(iph + 1);
        if ((void*)(tcph + 1) > data_end)
            return XDP_PASS;
        
        // Get destination port and check if it's in our block list
        port = bpf_ntohs(tcph->dest);
        found = bpf_map_lookup_elem(&port_map, &port);
        if (found && *found == 1)
            return XDP_DROP;  // Drop packets to the target port
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph = (void*)(iph + 1);
        if ((void*)(udph + 1) > data_end)
            return XDP_PASS;
        
        // Get destination port and check if it's in our block list
        port = bpf_ntohs(udph->dest);
        found = bpf_map_lookup_elem(&port_map, &port);
        if (found && *found == 1)
            return XDP_DROP;  // Drop packets to the target port
    }
    
    return XDP_PASS;  // Allow all other packets
}

char _license[] SEC("license") = "GPL"; 