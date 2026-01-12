#include <arpa/inet.h>
#include <linux/filter.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>

#define SO_ATTACH_FILTER 26
#define IPV4_HEADER_LEN 20

// icmp echo requests with greater sequence than this will get dropped
const uint16_t MAX_SEQ = 100;

// compiled using `bpf_asm -c`
// read https://www.kernel.org/doc/html/v5.12/networking/filter.html#bpf-engine-and-instruction-set for more infos
struct sock_filter BPF_FILTER[] = {
    { 0x30, 0, 0, 0x00000009 },         // ldb [9]           ; protocol
    { 0x15, 0, 5, 0x00000001 },         // jneq #1, drop     ; icmp
    { 0x30, 0, 0, 0x00000014 },         // ldb [20]          ; icmp type
    { 0x15, 0, 3, 0x00000008 },         // jneq #8, drop     ; icmp echo request
    { 0x28, 0, 0, 0x0000001a },         // ldh [26]          ; icmp sequence
    { 0x25, 1, 0, (uint32_t) MAX_SEQ }, // jgt #seq, drop
    { 0x06, 0, 0, 0xffffffff },         // ret #-1
    { 0x06, 0, 0, 0000000000 },         // drop: ret #0
};

void switch_to_echo_reply(uint8_t *buffer, size_t size);
uint16_t calculate_checksum(const uint16_t *addr, int len);

int32_t main() {
    int32_t sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock == -1) {
        perror("couldn't create raw icmp socket");
        return 1;
    }

    const char *bind_addr = getenv("BIND_ADDR");
    if (bind_addr) {
        struct sockaddr_in addr = { 0 };
        addr.sin_family = AF_INET;
        if (inet_pton(AF_INET, bind_addr, &addr.sin_addr) != 1) {
            fprintf(stderr, "invalid bind address '%s'\n", bind_addr);
            return 1;
        }
        if (bind(sock, (struct sockaddr *) &addr, sizeof(addr)) == -1) {
            perror("couldn't bind socket");
            return 1;
        }
    }

    struct sock_fprog prog = {
        .filter = (struct sock_filter *) BPF_FILTER,
        .len = sizeof(BPF_FILTER) / sizeof(struct sock_filter),
    };
    if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog)) == -1) {
        perror("couldn't attach filter to socket");
        return 1;
    }

    uint8_t buffer[1500] = { 0 };
    struct sockaddr_in from_addr = { 0 };
    socklen_t addr_len = sizeof(from_addr);
    while (1) {
        ssize_t len = recvfrom(sock, &buffer, sizeof(buffer), 0, (struct sockaddr *) &from_addr, &addr_len);
        if (len == -1) {
            perror("couldn't recv packet");
            continue;
        }
        // size is already checked in bpf filter
        uint8_t *icmp_header = &buffer[IPV4_HEADER_LEN];
        size_t icmp_header_len = len - IPV4_HEADER_LEN;
        switch_to_echo_reply(icmp_header, icmp_header_len);
        if (sendto(sock, icmp_header, icmp_header_len, 0, (struct sockaddr *) &from_addr, addr_len) == -1) {
            perror("couldn't send back echo reply");
        }
    }
    return 0;
}

#define ICMP_TYPE_OFFSET 0
#define ICMP_CHECKSUM_OFFSET 2
#define ICMP_ECHO_REPLY_TYPE 0

void switch_to_echo_reply(uint8_t *buffer, size_t size) {
    buffer[ICMP_TYPE_OFFSET] = ICMP_ECHO_REPLY_TYPE;
    uint16_t *checksum_field = (uint16_t *) &buffer[ICMP_CHECKSUM_OFFSET];
    *checksum_field = 0;
    uint16_t checksum = calculate_checksum((uint16_t *) buffer, size);
    *checksum_field = ntohs(checksum);
}

// written based on https://datatracker.ietf.org/doc/html/rfc1071#section-4.1
uint16_t calculate_checksum(const uint16_t *addr, int len) {
    int32_t sum = 0;
    while (len > 1) {
        sum += htons(*addr++);
        len -= 2;
    }
    if (len > 1) {
        sum += *(uint8_t *) addr;
    }
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return ~sum;
}
