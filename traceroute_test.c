#include <assert.h>
#include <stdbool.h>
#include "ft_traceroute.h"

void refactor_and_relative_waittime()
{
    assert(false && "refactor_and_relative_waittime");
}

void test_resolve_address()
{
    char host[256];
    struct sockaddr_in sin_host;
    bool err = false;

    ft_bzero(host, sizeof(host));
    err = set_host_addr(&sin_host, "8.8.8.8", UDP_PORT, AF_INET);
    assert(!err && "failed set_host_addr");

    err = resolve_host((struct sockaddr *)&sin_host, sizeof(sin_host), host, sizeof(host));
    assert(!err && "test_resolve_address");
    assert(ft_strncmp(host, "dns.google", ft_strlen("dns.google")) == 0 && "wrong host name resolved");
}

void test_time_diffs()
{
    struct timeval t1;
    struct timeval t2;

    gettimeofday(&t1, NULL);
    sleep(1);
    gettimeofday(&t2, NULL);
    int diff = deltaT(&t1, &t2);
    assert(diff == 1000 && "test_time_diffs");
}

void test_fail_trace_loop(int n_probes, int max_ttl, char *address)
{
    struct tr tr;

    ft_bzero(&tr, sizeof(tr));
    tr.last_addr = 0;
    tr.n_probes = n_probes;
    tr.max_ttl = max_ttl;
    tr.max_wait = MAX_WAIT;
    tr.host_address = address;

    assert(trace_loop(&tr) == -1 && "test_fail_trace_loop");
}

void test_trace_loop(int n_probes, int max_ttl, char *address)
{
    struct tr tr;

    ft_bzero(&tr, sizeof(tr));
    tr.n_probes = n_probes;
    tr.max_ttl = max_ttl;
    tr.max_wait = MAX_WAIT;
    tr.host_address = address;

    int tt = trace_loop(&tr);
    assert(tt == true && "test_traceroute_loop");
}

void test_process_icmp(int ttl)
{
    char packet[DGRAM_SIZE];
    ft_bzero(packet, DGRAM_SIZE);
    struct rec *rec;
    rec = (struct rec *)packet;
    rec->seq = 1;
    rec->ttl = 1;
    gettimeofday(&rec->tv, NULL);
    struct sockaddr_in sin_bind;
    struct sockaddr_in sin_send;

    set_local_bind_addr(&sin_bind, IDENT_PORT(getpid()));
    int sendfd = create_dgram_socket(AF_INET);
    bind_socket(sendfd, (struct sockaddr *)&sin_bind, sizeof(sin_bind));
    set_ttl_sock_opt(sendfd, 1);
    set_host_addr(&sin_send, "8.8.8.8", UDP_PORT, AF_INET);

    send_probe(sendfd, &sin_send, packet);

    char rcv_packet[RECV_SIZE];
    int recvfd = create_raw_icmp_socket(AF_INET);
    int bytes_recvd = -1;
    int recv_len = RECV_SIZE;
    struct sockaddr_in sin_recv;
    ft_bzero(rcv_packet, RECV_SIZE);

    int rc = wait_reply(recvfd, &sin_recv, rcv_packet, MAX_WAIT, 0);
    assert(rc != -1 && "faulty receive");
    assert(process_icmp(rc, rcv_packet, sin_bind.sin_port, sin_send.sin_port, 0) != -1 && "failed to process icmp packet");
    close(sendfd);
}

void test_wait_n_replies(int n)
{
    char packet[RECV_SIZE];
    int recvfd = create_raw_icmp_socket(AF_INET);
    int bytes_recvd = -1;
    int recv_len = RECV_SIZE;
    struct sockaddr_in sin_recv;

    ft_bzero(packet, RECV_SIZE);

    for (int i = 0; i < n; i++)
    {
        int rc = wait_reply(recvfd, &sin_recv, packet, MAX_WAIT, 0);
        assert(rc == RECV_SIZE && "test_recv_n_packets");
    }

    close(recvfd);
}

void test_wait_reply()
{
    char packet[RECV_SIZE];
    int recvfd = create_raw_icmp_socket(AF_INET);
    int bytes_recvd = -1;
    int recv_len = RECV_SIZE;
    struct sockaddr_in sin_recv;

    ft_bzero(packet, RECV_SIZE);

    int rc = wait_reply(recvfd, &sin_recv, packet, MAX_WAIT, 0);
    assert(rc == (RECV_SIZE) && "test_recv_n_packets");

    close(recvfd);
}

void test_send_n_probes(int n)
{
    char packet[DGRAM_SIZE];
    ft_bzero(packet, DGRAM_SIZE);
    struct sockaddr_in sin_bind;
    struct sockaddr_in sin_send;
    uint16_t last_port;

    set_local_bind_addr(&sin_bind, IDENT_PORT(getpid()));
    set_host_addr(&sin_send, "8.8.8.8", UDP_PORT, AF_INET);

    int sendfd;
    last_port = ntohs(sin_send.sin_port);
    int seq = 0;
    uint16_t current_sport = htons(IDENT_PORT(getpid()) + seq);

    for (int i = 0; i < n; ++i)
    {
        uint16_t current_sport = htons(IDENT_PORT(getpid()) + seq);
        sin_bind.sin_port = current_sport;
        sendfd = create_send_socket(sendfd, 30, (struct sockaddr *)&sin_bind, sizeof(sin_bind), AF_INET);
        int wc = send_probe(sendfd, &sin_send, packet);
        assert(wc == DGRAM_SIZE && "test_send_n_probes");
        seq++;
        close(sendfd);
    }
}

void test_send_probe()
{
    char packet[DGRAM_SIZE];
    ft_bzero(packet, DGRAM_SIZE);
    struct rec *rec;
    rec = (struct rec *)packet;
    rec->seq = 1;
    rec->ttl = 1;
    gettimeofday(&rec->tv, NULL);
    struct sockaddr_in sin_bind;
    struct sockaddr_in sin_send;

    int bytes_sent;
    uint16_t last_port;

    set_local_bind_addr(&sin_bind, IDENT_PORT(getpid()));
    set_host_addr(&sin_send, "8.8.8.8", UDP_PORT, AF_INET);

    int sendfd = create_dgram_socket(AF_INET);
    set_ttl_sock_opt(sendfd, 3);
    bind_socket(sendfd, (struct sockaddr *)&sin_bind, sizeof(sin_bind));
    last_port = ntohs(sin_send.sin_port);

    int wc = send_probe(sendfd, &sin_send, packet);
    assert(wc == DGRAM_SIZE && "test_send_n_probes");
    close(sendfd);
}

void test_get_send_addr()
{
    char canonname[INET_ADDRSTRLEN];
    struct sockaddr_in host;
    bool err = false;

    err = set_host_addr(&host, "8.8.8.8", UDP_PORT, AF_INET);
    assert(!err && "failed set_host_addr");
    err = sock_ntop_host((struct sockaddr *)&host, sizeof(host), canonname, sizeof(canonname));
    assert(!err && "failed sock_ntop_host");
    assert(ft_strncmp("8.8.8.8", canonname, strlen("8.8.8.8")) == 0 && "test_get_host_addr");
}

void test_bind_socket()
{
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in local, sa;
    socklen_t len = sizeof(sa);
    uint16_t local_port;

    set_local_bind_addr(&sa, IDENT_PORT(getpid()));
    bind_socket(sockfd, (struct sockaddr *)&sa, sizeof(sa));
    ft_bzero(&local, sizeof(local));
    if (getsockname(sockfd, (struct sockaddr *)&local, &len) == -1)
    {
        ft_printf("ft_traceroute: %s\n", strerror(errno));
    }
    assert(len > 0 && "test_bind_socket");
    local_port = local.sin_port;
    assert(local_port == htons(IDENT_PORT(getpid())) && "test_bind_socket");
    close(sockfd);
}

void test_set_ttl_sock_opt(int (*create_socket)(int), int ttl)
{
    int sockfd = create_socket(AF_INET);

    assert(sockfd > 0 && "test_set_ttl_sock_opt failed to create socket");
    assert(set_ttl_sock_opt(sockfd, ttl) != -1 && "test_set_ttl_sock_opt");

    close(sockfd);
}

void test_create_socket(int (*create_socket)(int))
{
    int sockfd = create_socket(AF_INET);
    assert(sockfd > 0 && "test_create_socket");

    close(sockfd);
}

int main()
{
    // INIT

    // TESTS
    test_create_socket(&create_dgram_socket);
    test_create_socket(&create_raw_icmp_socket);
    test_set_ttl_sock_opt(&create_dgram_socket, 30);
    test_bind_socket();
    test_get_send_addr();
    //
    test_send_probe();
    test_wait_reply();
    //
    test_send_n_probes(3);
    test_wait_n_replies(3);
    //
    test_process_icmp(11);
    test_time_diffs();
    test_resolve_address();
    test_trace_loop(3, 3, "8.8.8.8");
    test_fail_trace_loop(1, 1, "adf");
    test_trace_loop(3, 12, "dns.google");

    // CLEAN
}
