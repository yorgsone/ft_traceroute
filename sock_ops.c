#include "ft_traceroute.h"


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
