#include "ft_traceroute.h"

int create_dgram_socket(int domain)
{
    int sockfd;

    if (domain != AF_INET && domain != AF_INET6)
        return -1;

    sockfd = socket(domain, SOCK_DGRAM, 0);
    if (sockfd == -1)
    {
        ft_printf("ft_traceroute: socket: %s\n", strerror(errno));
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
        ft_printf("ft_traceroute: socket: %s\n", strerror(errno));
        return (-1);
    }
    return sockfd;
}

int bind_socket(int sockfd, struct sockaddr *sa, socklen_t len)
{
    if (bind(sockfd, sa, len) == -1)
    {
        ft_printf("ft_traceroute: bind_socket: %s\n", strerror(errno));
        return (-1);
    }
    return (0);
}

int set_local_bind_addr(struct sockaddr_in *sa)
{
    if (!sa)
        return (-1);

    ft_bzero(sa, sizeof(struct sockaddr_in));
    sa->sin_family = AF_INET;
    sa->sin_port = htons(IDENT_PORT(getpid()));
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
        ft_printf("ft_traceroute: %s: %s\n", addr, gai_strerror(err));
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

static void update_packet(char packet[DGRAM_SIZE])
{
    struct rec *rec;

    rec = (struct rec *)packet;
    rec->seq += 1;
    rec->ttl += 1;
    gettimeofday(&rec->tv, NULL);
}

int trace_loop(int n_probes, int max_ttl)
{
    char packet[DGRAM_SIZE];
    ft_bzero(packet, DGRAM_SIZE);
    struct rec *rec;
    rec = (struct rec *)packet;
    rec->seq = 1;
    rec->ttl = 1;
    gettimeofday(&rec->tv, NULL);

    for (int i = 0; i < max_ttl; ++i)
    {
        ;
    }
    return 1;
}

int send_n_probes(int n, struct sockaddr_in *sin_send, char packet[DGRAM_SIZE])
{
    int wc = 0;
    int sendfd;
    struct sockaddr_in sin_bind;

    set_local_bind_addr(&sin_bind);

    for (int i = 0; i < n; ++i)
    {
        sendfd = create_dgram_socket(AF_INET);
        sin_bind.sin_port = htons(ntohs(sin_bind.sin_port) + 1);
        bind_socket(sendfd, (struct sockaddr *)&sin_bind, sizeof(sin_bind));
        if (send_probe(sendfd, sin_send, packet) == -1)
            return (-1);
        wc += DGRAM_SIZE;
        ft_printf("%d %d\n", ((struct rec *)packet)->seq, ((struct rec *)packet)->ttl);
        update_packet(packet);
        sin_send->sin_port = htons(ntohs(sin_send->sin_port) + 1);
        close(sendfd);
    }

    return (wc);
}

int send_probe(int sendfd, struct sockaddr_in *sin_send, char packet[DGRAM_SIZE])
{
    int wc = 0;

    if ((wc = sendto(sendfd, packet, DGRAM_SIZE, 0, (struct sockaddr *)sin_send, sizeof(struct sockaddr_in))) == -1)
    {
        ft_printf("ft_traceroute: sendto: %s\n", strerror(errno));
        return (-1);
    }

    return (wc);
}

int recv_n_packets(int n, int recvfd, struct sockaddr_in *sin_recv, char packet[DGRAM_SIZE + 1])
{
    int rc = 0;

    for (int i = 0; i < n; ++i)
    {
        if (recv_packet(recvfd, sin_recv, packet) == -1)
            return (-1);
        rc += DGRAM_SIZE + 1;
    }

    return (rc);
}

int recv_packet(int recvfd, struct sockaddr_in *sin_recv, char packet[DGRAM_SIZE + 1])
{
    int rc = 0;
    int recv_len = DGRAM_SIZE;
    fd_set fds;
    struct timeval wait;
    int cc = 0;
    int fromlen = sizeof(*sin_recv);

    FD_ZERO(&fds);
    FD_SET(recvfd, &fds);
    wait.tv_sec = MAX_WAIT;
    wait.tv_usec = 0;

    if (select(recvfd + 1, &fds, (fd_set *)0, (fd_set *)0, &wait) > 0)
    {
        if ((rc = recvfrom(recvfd, packet, DGRAM_SIZE + 1, 0, (struct sockaddr *)sin_recv, &recv_len)) == -1)
        {
            ft_printf("ft_traceroute: recvfrom: %s\n", strerror(errno));
            return (-1);
        }
    }

    return (rc);
}

int process_icmp(int rc, char packet[DGRAM_SIZE + 1], uint16_t sport, uint16_t dport)
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
        ft_printf("not enough to look for ICMP header");
        return (-1);
    }

    if (icmp->icmp_type == ICMP_TIMXCEED &&
        icmp->icmp_code == ICMP_TIMXCEED_INTRANS)
    {
        if (icmplen < 8 + sizeof(struct ip))
        {
            ft_printf("not enought data to look at inner ip");
            return (-1);
        }

        hip = (struct ip *)(packet + hlen1 + 8);
        hlen2 = hip->ip_hl << 2;
        if (icmplen < 8 + hlen2 + 4)
        {
            ft_printf("not enough data to look for UDP port");
            return (-1);
        }
        udp = (struct udphdr *)(packet + hlen1 + 8 + hlen2);
        if (hip->ip_p == IPPROTO_UDP &&
            udp->uh_sport == sport &&
            udp->uh_dport == dport)
        {
            ft_printf("we hit an intermediate router");
            return (-2);
        }
    }
    else if (icmp->icmp_type == ICMP_UNREACH)
    {
        if (icmplen < 8 + sizeof(struct ip))
        {
            ft_printf("not enought data to look at inner IP");
            return (-1);
        }

        hip = (struct ip *)(packet + hlen1 + 8);
        hlen2 = hip->ip_hl << 2;
        if (icmplen < 8 + hlen2 + 4)
        {
            ft_printf("not enough data to look for UDP port");
            return (-1);
        }
        udp = (struct udphdr *)(packet + hlen1 + 8 + hlen2);
        if (hip->ip_p == IPPROTO_UDP &&
            udp->uh_sport == sport &&
            udp->uh_dport == dport)
        {
            if (icmp->icmp_code == ICMP_UNREACH_PORT){
                return (1);
            }  
            return (icmp->icmp_code);
        }
    }

    return -1;
}
