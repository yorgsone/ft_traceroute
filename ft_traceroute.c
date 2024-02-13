#include "ft_traceroute.h"

int create_dgram_socket(int domain){
    if (domain != AF_INET && domain != AF_INET6)
        return -1;
    return socket(domain, SOCK_DGRAM, 0);
}

int create_raw_icmp_socket(int domain){
    if (domain != AF_INET && domain != AF_INET6)
        return -1;
    return socket(domain, SOCK_RAW, domain == AF_INET ? IPPROTO_ICMP: IPPROTO_ICMPV6);
}

int bind_socket(int sockfd, struct sockaddr *sa, socklen_t len){
    if (bind(sockfd, sa, len) == -1){
        ft_printf( "ft_traceroute: %s\n", strerror(errno));
        return (-1);
    }
    return (0);
}

int set_local_bind_addr(struct sockaddr_in *sa){
    if (!sa)
        return (-1);

    ft_bzero(sa, sizeof(struct sockaddr_in));
    sa->sin_family = AF_INET;
    sa->sin_port = htons(IDENT_PORT(getpid()));
    sa->sin_addr.s_addr = INADDR_ANY;
    return (0);
}

struct addrinfo *host_serv(const char *addr, const char *port, int flags, int family, int socktype){
    int err;
    struct addrinfo *res;
    struct addrinfo hints;

    ft_memset(&hints, 0, sizeof(hints));
    hints.ai_flags = flags;
    hints.ai_family = family;
    hints.ai_socktype = socktype;
    if ((err = getaddrinfo(addr, port, &hints, &res)) != 0){
        ft_printf( "ft_traceroute: %s: %s\n", addr, gai_strerror(err));
        return(NULL);
    }

    return res;
}

/*
fills HOST buffer with presentational form of a sockaddr.
*/
int sock_ntop_host(const struct sockaddr *sa, socklen_t salen, char *host, size_t hostlen){
	if  (sa->sa_family == AF_INET) {
		struct sockaddr_in	*sin = (struct sockaddr_in *) sa;

		if (inet_ntop(AF_INET, &sin->sin_addr, host, hostlen) != NULL){
		    return(0);
        }
	}
    return (-1);
}

int set_host_addr(struct sockaddr_in *sa, const char *addr, const char *port, int family){
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


int send_probe(int sendfd, struct sockaddr_in *sin_send, char packet[DGRAM_SIZE]){
    int wc = 0;

    if ((wc = sendto(sendfd, packet, DGRAM_SIZE, 0, (struct sockaddr *)sin_send, sizeof(struct sockaddr_in))) == -1){
        ft_printf( "ft_traceroute: sendto: %s\n", strerror(errno));
        return(-1);
    }

    return (wc);
}

int recv_packet(int recvfd, struct sockaddr_in *sin_recv, char packet[DGRAM_SIZE + 1]){
    int rc = 0;
    int recv_len = DGRAM_SIZE;

    if ((rc = recvfrom(recvfd, packet, DGRAM_SIZE + 1, 0, (struct sockaddr *)sin_recv, &recv_len)) == -1){
        ft_printf( "ft_traceroute: recvfrom: %s\n", strerror(errno));
        return(-1);
    }

    return (rc);
}

