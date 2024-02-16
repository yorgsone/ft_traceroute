#include "ft_traceroute.h"

int create_dgram_socket(int domain)
{
    int sockfd;

    if (domain != AF_INET && domain != AF_INET6)
        return -1;

    sockfd = socket(domain, SOCK_DGRAM, 0);
    if (sockfd == -1)
    {
        printf("ft_traceroute: udp dgram socket: %s\n", strerror(errno));
        return (-1);
    }
    return sockfd;
}

int create_raw_icmp_socket(int domain)
{
    int sockfd;

    if (domain != AF_INET && domain != AF_INET6)
        return -1;

    sockfd = socket(domain, SOCK_RAW, domain == AF_INET ? IPPROTO_ICMP : IPPROTO_ICMPV6);
    if (sockfd == -1)
    {
        printf("ft_traceroute: raw icmp socket: %s\n", strerror(errno));
        return (-1);
    }
    return sockfd;
}

int bind_socket(int sockfd, struct sockaddr *sa, socklen_t len)
{
    if (bind(sockfd, sa, len) == -1)
    {
        printf("ft_traceroute: bind_socket: %s\n", strerror(errno));
        return (-1);
    }
    return (0);
}

int set_local_bind_addr(struct sockaddr_in *sa, uint16_t bind_port)
{
    if (!sa)
        return (-1);

    ft_bzero(sa, sizeof(struct sockaddr_in));
    sa->sin_family = AF_INET;
    sa->sin_port = htons(bind_port);
    sa->sin_addr.s_addr = INADDR_ANY;
    return (0);
}

struct addrinfo *host_serv(const char *addr, const char *port, int flags, int family, int socktype)
{
    int err;
    struct addrinfo *res;
    struct addrinfo hints;

    ft_memset(&hints, 0, sizeof(hints));
    hints.ai_flags = flags;
    hints.ai_family = family;
    hints.ai_socktype = socktype;
    if ((err = getaddrinfo(addr, port, &hints, &res)) != 0)
    {
        printf("ft_traceroute: %s: %s\n", addr, gai_strerror(err));
        return (NULL);
    }

    return res;
}

/*
fills HOST buffer with presentational form of a sockaddr.
*/
int sock_ntop_host(const struct sockaddr *sa, socklen_t salen, char *host, size_t hostlen)
{
    if (sa->sa_family == AF_INET)
    {
        struct sockaddr_in *sin = (struct sockaddr_in *)sa;

        if (inet_ntop(AF_INET, &sin->sin_addr, host, hostlen) != NULL)
        {
            return (0);
        }
    }
    return (-1);
}

int set_host_addr(struct sockaddr_in *sa, const char *addr, const char *port, int family)
{
    struct addrinfo *ai;
    if (!sa)
        return (-1);
    if (family != AF_INET)
        return (-1);
    ft_bzero(sa, sizeof(struct sockaddr_in));
    ai = host_serv(addr, port, AI_CANONNAME, family, SOCK_DGRAM);
    if (!ai)
        return (-1);
    ft_memcpy(sa, ai->ai_addr, sizeof(struct sockaddr_in));
    freeaddrinfo(ai);
    return (0);
}

double deltaT(struct timeval *t1p, struct timeval *t2p)
{
    register double dt;

    dt = (double)(t2p->tv_sec - t1p->tv_sec) * 1000.0 +
         (double)(t2p->tv_usec - t1p->tv_usec) / 1000.0;
    return (dt);
}

int resolve_host(struct sockaddr *sa, socklen_t sa_len, char *host, socklen_t host_len)
{
    if (getnameinfo(sa, sa_len, host, host_len, NULL, 0, 0) != 0)
    {
        printf("ft_traceroute: getnameinfo: %s\n", strerror(errno));
        return (-1);
    }
    return (0);
}

int create_send_socket(int sendfd, int ttl, const struct sockaddr *sa_bind, socklen_t sa_len, int family)
{
    sendfd = create_dgram_socket(family);
    if (sendfd == -1)
        return (-1);
    if (set_ttl_sock_opt(sendfd, ttl) == -1)
        return (-1);
    if (bind_socket(sendfd, (struct sockaddr *)sa_bind, sa_len) == -1)
        return (-1);
    return sendfd;
}

static int num_places(int n)
{
    if (n < 0)
        n = (n == INT_MIN) ? INT_MAX : -n;
    if (n < 10)
        return 1;
    if (n < 100)
        return 2;
    if (n < 1000)
        return 3;
    if (n < 10000)
        return 4;
    if (n < 100000)
        return 5;
    if (n < 1000000)
        return 6;
    if (n < 10000000)
        return 7;
    if (n < 100000000)
        return 8;
    if (n < 1000000000)
        return 9;
    /*      2147483647 is 2^31-1 - add more ifs as needed
       and adjust this final return as well. */
    return 10;
}

static int send_recv_n(struct tr *tr, char send_packet[DGRAM_SIZE], char rcv_packet[RECV_SIZE], int ttl)
{
    char host[256];
    int rc = 0;
    int code = -1;
    int sendfd;
    char canonname[INET_ADDRSTRLEN];
    struct ip *ip;
    struct timeval send_t, reply_t;
    int unreachable = 0;
    int got_there = 0;
    uint16_t current_sport;

    printf("%*d ", num_places(ttl) == 1 ? 2 : num_places(ttl), ttl);
    for (int i = 0; i < tr->n_probes; ++i)
    {
        current_sport = htons(tr->ident_port + tr->seq);
        tr->sin_bind.sin_port = current_sport;
        sendfd = create_send_socket(sendfd, ttl, (struct sockaddr *)&tr->sin_bind, sizeof(tr->sin_bind), AF_INET);
        if (sendfd == -1)
            return (-1);
        gettimeofday(&send_t, NULL);
        if (send_probe(sendfd, &tr->sin_send, send_packet) == -1)
            return (-1);
        rc = wait_reply(tr->recvfd, &tr->sin_recv, rcv_packet, MAX_WAIT, 0);
        gettimeofday(&reply_t, NULL);
        if (rc == -1)
            return (-1);
        while ((code = process_icmp(rc, rcv_packet, current_sport, tr->sin_send.sin_port, 0)) == -3)
        {
            rc = wait_reply(tr->recvfd, &tr->sin_recv, rcv_packet, MAX_WAIT, 0);
            gettimeofday(&reply_t, NULL);
        }
        if (rc == 0)
        {
            printf(" *");
            goto update_continue;
        }
        if (tr->last_addr != tr->sin_recv.sin_addr.s_addr)
        {
            tr->last_addr = tr->sin_recv.sin_addr.s_addr;
            if (sock_ntop_host((struct sockaddr *)&tr->sin_recv, sizeof(tr->sin_recv), canonname, sizeof(canonname)) == -1)
                return (-1);
            if (resolve_host((struct sockaddr *)&tr->sin_recv, sizeof(tr->sin_recv), host, sizeof(host)) == -1)
                return (-1);
            printf(" %s (%s)", host, canonname);
        }
        printf("  %.3f ms", deltaT(&send_t, &reply_t));
        if (code == ICMP_UNREACH_PORT)
        {
            ++got_there;
            ip = (struct ip *)rcv_packet;
            if (ip->ip_ttl <= 1)
                printf(" !");
        }
        else if (code == ICMP_UNREACH_NET)
        {
            ++unreachable;
            printf(" !N");
        }
        else if (code == ICMP_UNREACH_HOST)
        {
            ++unreachable;
            printf(" !H");
        }
        else if (code == ICMP_UNREACH_PROTOCOL)
        {
            ++unreachable;
            printf(" !P");
        }
        else if (code == ICMP_UNREACH_NEEDFRAG)
        {
            ++unreachable;
            printf(" !F");
        }
        else if (code == ICMP_UNREACH_SRCFAIL)
        {
            ++unreachable;
            printf(" !S");
        }
        else if (code == ICMP_UNREACH_FILTER_PROHIB)
        {
            ++unreachable;
            printf(" !X");
        }
        else if (code > 0)
        {
            ++unreachable;
            printf(" !%d", code);
        }

    update_continue:
        ft_bzero(rcv_packet, RECV_SIZE);
        tr->seq++;
        tr->sin_send.sin_port = htons(ntohs(tr->sin_send.sin_port) + 1);
        close(sendfd);
    }
    printf("\n");
    if (got_there || unreachable >= tr->n_probes - 1)
        exit(0);

    return (1);
}

int trace_loop(struct tr *tr)
{
    tr->ident_port = IDENT_PORT(getpid());
    char presentational_address[INET_ADDRSTRLEN];
    char packet[DGRAM_SIZE];
    ft_bzero(packet, DGRAM_SIZE);

    char rcv_packet[RECV_SIZE];
    int recvfd = create_raw_icmp_socket(AF_INET);
    if (recvfd == -1)
        return (-1);
    tr->recvfd = recvfd;
    int recv_len = RECV_SIZE;
    ft_bzero(rcv_packet, RECV_SIZE);

    if (set_local_bind_addr(&tr->sin_bind, tr->ident_port) == -1)
        return (-1);
    if (set_host_addr(&tr->sin_send, tr->host_address, UDP_PORT, AF_INET) == -1)
        return (-1);
    if (sock_ntop_host((struct sockaddr *)&tr->sin_send, sizeof(tr->sin_send), presentational_address, sizeof(presentational_address)) == -1)
        return (-1);

    printf("traceroute to %s (%s), %d hops max, %ld byte packets\n", tr->host_address, presentational_address, tr->max_ttl, DGRAM_SIZE + sizeof(struct ip) + sizeof(struct udphdr));
    for (int i = 1; i <= tr->max_ttl; ++i)
    {
        if (send_recv_n(tr, packet, rcv_packet, i) == -1)
            return (-1);
    }
    return 1;
}

int send_probe(int sendfd, struct sockaddr_in *sin_send, char packet[DGRAM_SIZE])
{
    int wc = 0;

    if ((wc = sendto(sendfd, packet, DGRAM_SIZE, 0, (struct sockaddr *)sin_send, sizeof(struct sockaddr_in))) == -1)
    {
        printf("ft_traceroute: sendto: %s\n", strerror(errno));
        return (-1);
    }

    return (wc);
}

int wait_reply(int recvfd, struct sockaddr_in *sin_recv, char packet[RECV_SIZE], long wait_s, long wait_ms)
{
    int rc = 0;
    int recv_len = DGRAM_SIZE;
    fd_set fds;
    struct timeval wait;
    int cc = 0;
    int fromlen = sizeof(*sin_recv);

    FD_ZERO(&fds);
    FD_SET(recvfd, &fds);
    wait.tv_sec = wait_s;
    wait.tv_usec = wait_ms;

    if (select(recvfd + 1, &fds, (fd_set *)0, (fd_set *)0, &wait) > 0)
    {
        if ((rc = recvfrom(recvfd, packet, RECV_SIZE, 0, (struct sockaddr *)sin_recv, &recv_len)) == -1)
        {
            printf("ft_traceroute: recvfrom: %s\n", strerror(errno));
            return (-1);
        }
    }

    return (rc);
}

int process_icmp(int rc, char packet[RECV_SIZE], uint16_t sport, uint16_t dport, int verbose)
{
    int hlen1, hlen2, icmplen, ret;
    struct ip *ip, *hip;
    struct icmp *icmp;
    struct udphdr *udp;

    ip = (struct ip *)packet;
    hlen1 = ip->ip_hl << 2;
    icmp = (struct icmp *)(packet + hlen1);
    if ((icmplen = rc - hlen1) < 8)
    {
        if (verbose)
            printf("not enough data to look for ICMP header\n");
        return (-1);
    }

    if ((icmp->icmp_type == ICMP_TIMXCEED &&
         icmp->icmp_code == ICMP_TIMXCEED_INTRANS) ||
        icmp->icmp_type == ICMP_UNREACH)
    {
        if (icmplen < 8 + sizeof(struct ip))
        {
            if (verbose)
                printf("not enough data to look at inner ip\n");
            return (-1);
        }
        hip = (struct ip *)(packet + hlen1 + 8);
        hlen2 = hip->ip_hl << 2;
        if (icmplen < 8 + hlen2 + 4)
        {
            if (verbose)
                printf("not enough data to look for UDP port\n");
            return (-1);
        }

        udp = (struct udphdr *)(packet + hlen1 + 8 + hlen2);
        if (hip->ip_p == IPPROTO_UDP)
        {
            if (udp->uh_sport == sport &&
                udp->uh_dport == dport)
            {
                if (icmp->icmp_type != ICMP_UNREACH)
                    return (-2);
                return (icmp->icmp_code);
            }
            else
            {
                return -3;
            }
        }
    }
    return -1;
}

int set_ttl_sock_opt(int sockfd, int ttl)
{
    const int val = ttl;

    if (setsockopt(sockfd, SOL_IP, IP_TTL, &val, sizeof(val)) != 0)
    {
        printf("ft_traceroute: setsockopt: %s\n", strerror(errno));
        return (-1);
    }
    return (0);
}
