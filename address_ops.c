#include "ft_traceroute.h"

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

int resolve_host(struct sockaddr *sa, socklen_t sa_len, char *host, socklen_t host_len)
{
    if (getnameinfo(sa, sa_len, host, host_len, NULL, 0, 0) != 0)
    {
        printf("ft_traceroute: getnameinfo: %s\n", strerror(errno));
        return (-1);
    }
    return (0);
}
