#include "../ft_traceroute.h"

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
    return 10;
}

static int send_recv_n(struct tr *tr, char send_packet[DGRAM_SIZE], char rcv_packet[RECV_SIZE], int ttl)
{
    char host[256];
    int rc = 0;
    int code = -1;
    int unreachable = 0;
    int got_there = 0;
    int sendfd;
    char canonname[INET_ADDRSTRLEN];
    struct ip *ip;
    struct timeval send_t;
    struct timeval reply_t;
    uint16_t current_sport;
    int current_wait = MAX_WAIT;

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

        while (1){
            rc = wait_reply(tr->recvfd, &tr->sin_recv, rcv_packet, current_wait, 0);
            gettimeofday(&reply_t, NULL);
            if (rc == -1)
                return (-1);
            else if (rc == 0)
            {
                printf(" *");
                goto update_continue;
            }
            code = process_icmp(rc, rcv_packet, current_sport, tr->sin_send.sin_port, 0);
            if (code == -3)
                continue;
            break;
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
        else if (code == ICMP_UNREACH_HOST_PROHIB)
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
        current_wait = MAX_WAIT;
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
