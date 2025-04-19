#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdbool.h>

#define MAX_PORTS 10  // 최대 차단할 포트 수

/* XDP 프로그램 연결/해제를 위한 함수 추가 */
int set_link_xdp_fd(int ifindex, int fd, __u32 flags) {
    struct bpf_xdp_attach_opts opts = {};
    
    // Use recent libbpf API
    opts.sz = sizeof(struct bpf_xdp_attach_opts);
    return bpf_xdp_attach(ifindex, fd, flags, &opts);
}

static const char *prog_path = "xdp_port_drop.o";

void usage(const char *prog_name) {
    fprintf(stderr, 
            "Usage: %s [OPTION]\n"
            "Options:\n"
            "  -i IFNAME   Interface to attach the XDP program\n"
            "  -p PORT     Target port to block (can be used multiple times, up to %d ports)\n"
            "  -u          Unload XDP program from the interface\n"
            "  -h          Display this help and exit\n",
            prog_name, MAX_PORTS);
}

int main(int argc, char **argv) {
    int opt;
    char ifname[IF_NAMESIZE] = "";
    bool unload = false;
    int ports[MAX_PORTS];  // 차단할 포트 목록
    int port_count = 0;    // 차단할 포트 수
    
    // 포트 배열 초기화
    memset(ports, 0, sizeof(ports));
    
    while ((opt = getopt(argc, argv, "i:p:uh")) != -1) {
        switch (opt) {
        case 'i':
            strncpy(ifname, optarg, IF_NAMESIZE - 1);
            break;
        case 'p':
            if (port_count >= MAX_PORTS) {
                fprintf(stderr, "Too many ports specified (maximum is %d)\n", MAX_PORTS);
                return EXIT_FAILURE;
            }
            ports[port_count] = atoi(optarg);
            if (ports[port_count] <= 0 || ports[port_count] > 65535) {
                fprintf(stderr, "Invalid port number: %s\n", optarg);
                return EXIT_FAILURE;
            }
            port_count++;
            break;
        case 'u':
            unload = true;
            break;
        case 'h':
            usage(argv[0]);
            return EXIT_SUCCESS;
        default:
            usage(argv[0]);
            return EXIT_FAILURE;
        }
    }
    
    // 포트가 지정되지 않은 경우 기본값 8080 사용
    if (port_count == 0 && !unload) {
        ports[0] = 8080;
        port_count = 1;
        printf("No ports specified, using default port 8080\n");
    }
    
    if (ifname[0] == '\0') {
        fprintf(stderr, "Interface name is required\n");
        usage(argv[0]);
        return EXIT_FAILURE;
    }
    
    unsigned int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        fprintf(stderr, "Interface %s does not exist\n", ifname);
        return EXIT_FAILURE;
    }
    
    if (unload) {
        // Unload XDP program
        if (set_link_xdp_fd(ifindex, -1, 0) < 0) {
            fprintf(stderr, "Error unloading XDP program: %s\n", strerror(errno));
            return EXIT_FAILURE;
        }
        printf("XDP program unloaded from interface %s\n", ifname);
        return EXIT_SUCCESS;
    }
    
    // Load BPF program
    struct bpf_object *obj;
    int prog_fd;
    
    obj = bpf_object__open_file(prog_path, NULL);
    if (!obj) {
        fprintf(stderr, "Error opening BPF object file: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }
    
    if (bpf_object__load(obj) < 0) {
        fprintf(stderr, "Error loading BPF object file: %s\n", strerror(errno));
        bpf_object__close(obj);
        return EXIT_FAILURE;
    }
    
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "xdp_port_dropper");
    if (!prog) {
        fprintf(stderr, "Error finding XDP program in BPF object file\n");
        bpf_object__close(obj);
        return EXIT_FAILURE;
    }
    
    prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        fprintf(stderr, "Error getting file descriptor for XDP program\n");
        bpf_object__close(obj);
        return EXIT_FAILURE;
    }
    
    // Set the target ports in the map
    struct bpf_map *map = bpf_object__find_map_by_name(obj, "port_map");
    if (!map) {
        fprintf(stderr, "Error finding port_map in BPF object file\n");
        bpf_object__close(obj);
        return EXIT_FAILURE;
    }
    
    int map_fd = bpf_map__fd(map);
    if (map_fd < 0) {
        fprintf(stderr, "Error getting file descriptor for port_map\n");
        bpf_object__close(obj);
        return EXIT_FAILURE;
    }
    
    // 모든 포트 항목 추가
    for (int i = 0; i < port_count; i++) {
        __u16 port = (__u16)ports[i];
        __u8 value = 1;  // 1 = block
        
        if (bpf_map_update_elem(map_fd, &port, &value, BPF_ANY) < 0) {
            fprintf(stderr, "Error updating port_map for port %d: %s\n", 
                    ports[i], strerror(errno));
            bpf_object__close(obj);
            return EXIT_FAILURE;
        }
        printf("Added port %d to block list\n", ports[i]);
    }
    
    // Attach XDP program to the interface
    if (set_link_xdp_fd(ifindex, prog_fd, 0) < 0) {
        fprintf(stderr, "Error attaching XDP program to interface %s: %s\n", 
                ifname, strerror(errno));
        bpf_object__close(obj);
        return EXIT_FAILURE;
    }
    
    printf("XDP program successfully loaded and attached to interface %s\n", ifname);
    printf("Blocking packets to %d port(s)\n", port_count);
    
    bpf_object__close(obj);
    return EXIT_SUCCESS;
} 