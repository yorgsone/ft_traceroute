#ifndef FT_TRACEROUTE
#define FT_TRACEROUTE

#define BUFF_SIZE 1024
#include <stdlib.h>
#include <netinet/ip_icmp.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <stdio.h>
#include "libft/include/libft.h"

#define DGRAM_SIZE 32 // 20 IP + 8 UDP + 32 DATA
#define RECV_SIZE 60
#define MAX_TTL 30
#define PROBES_NUM 3
#define UDP_PORT "33434"
#define DEFAULT_TTL 1
#define MAX_WAIT 5

#define IDENT_PORT(pid) htons((pid & 0xffff) | 0x8000)

struct rec
{
    uint16_t seq;
    uint16_t ttl;
    struct timeval tv;
};

struct tr
{
    int recvfd;
    int max_ttl;
    int n_probes;
    int max_wait;
    int got_there;
    int unreachable;
    char *host_address;
    in_addr_t last_addr;
    struct sockaddr_in sin_bind;
    struct sockaddr_in sin_send;
    struct sockaddr_in sin_recv;
};

int create_dgram_socket(int);
int create_raw_icmp_socket(int);
int bind_socket(int, struct sockaddr *, socklen_t);
int set_local_bind_addr(struct sockaddr_in *);
struct addrinfo *host_serv(const char *, const char *, int, int, int);
int sock_ntop_host(const struct sockaddr *, socklen_t, char *, size_t);
int set_host_addr(struct sockaddr_in *, const char *, const char *, int);
int send_probe(int, struct sockaddr_in *, char[DGRAM_SIZE]);
int send_n_probes(int, struct sockaddr_in *, struct sockaddr_in *, char[DGRAM_SIZE], int);
int wait_reply(int, struct sockaddr_in *, char[RECV_SIZE]);
int recv_n_packets(int, int, struct sockaddr_in *, char[RECV_SIZE]);
int process_icmp(int, char[RECV_SIZE], uint16_t, uint16_t, int verbose);
int set_ttl_sock_opt(int, int);
int trace_loop(struct tr *tr);
double deltaT(struct timeval *t1p, struct timeval *t2p);
int resolve_host(struct sockaddr *sa, socklen_t sa_len , char *host, socklen_t host_len);

#endif