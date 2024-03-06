#include "../inc/ft_traceroute.h"


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
    int fromlen = sizeof(*sin_recv);
    int recv_len = DGRAM_SIZE;
    fd_set fds;
    struct timeval wait;

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
