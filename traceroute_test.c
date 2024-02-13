#include <assert.h>
#include <stdbool.h>
#include "ft_traceroute.h"

void test_recv_packet(){
    char packet[DGRAM_SIZE + 1];
    int recvfd = create_raw_icmp_socket(AF_INET);
    int bytes_recvd = -1;
    int recv_len= DGRAM_SIZE  + 1;
    struct sockaddr_in sin_recv;

    ft_bzero(packet, DGRAM_SIZE + 1);

    bytes_recvd = recv_packet(recvfd, &sin_recv, packet);
    ft_printf("%d\n", bytes_recvd);
    assert(bytes_recvd != -1 && "test_recv_packet");
    close(recvfd);
}

void test_send_probe(){
    char packet[DGRAM_SIZE];
    ft_bzero(packet, DGRAM_SIZE);
    struct rec  *rec;
    rec = (struct rec *)packet;
    rec->seq = 1;
    rec->ttl = 1;
    gettimeofday(&rec->tv, NULL);
    struct sockaddr_in sin_bind;
    struct sockaddr_in sin_send;
    int sendfd = create_dgram_socket(AF_INET);

    int bytes_sent = -1;

    set_local_bind_addr(&sin_bind);
    set_host_addr(&sin_send, "8.8.8.8", UDP_PORT, AF_INET);
    bind_socket(sendfd, (struct sockaddr *)&sin_bind, sizeof(sin_bind));
    bytes_sent = send_probe(sendfd, &sin_send, packet);
    assert(bytes_sent == DGRAM_SIZE && "test_send_probe");
    close(sendfd);
}

void test_get_send_addr()
{
    char canonname[INET_ADDRSTRLEN];
    struct sockaddr_in host;
    bool err = false;

    err = set_host_addr(&host, "8.8.8.8", UDP_PORT, AF_INET);
    assert(!err && "failed set_host_addr" );
    err = sock_ntop_host((struct sockaddr *)&host, sizeof(host), canonname, sizeof(canonname));
    assert(!err && "failed sock_ntop_host");
    assert (ft_strncmp("8.8.8.8", canonname, strlen("8.8.8.8")) == 0 && "test_get_host_addr");
}

void test_bind_socket(){
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in local, sa;
    socklen_t len = sizeof(sa);
    uint16_t local_port;

    set_local_bind_addr(&sa);
    bind_socket(sockfd, (struct sockaddr*)&sa, sizeof(sa));
    ft_bzero(&local, sizeof(local));
    if (getsockname(sockfd, (struct sockaddr *)&local, &len) == -1){
        ft_printf( "ft_traceroute: %s\n", strerror(errno));
    }
    assert(len > 0 && "test_bind_socket");
    local_port = local.sin_port;
    assert(local_port == htons(IDENT_PORT(getpid())) && "test_bind_socket");
    close(sockfd);
}

void test_create_socket(int (*create_socket)(int)){
    int sockfd = create_socket(AF_INET);
    assert(sockfd > 0 && "test_create_socket");
    
    close(sockfd);
}

int main(){
    //INIT

    //TESTS
    test_create_socket(&create_dgram_socket);
    test_create_socket(&create_raw_icmp_socket);
    test_bind_socket();
    test_get_send_addr();
    test_send_probe();
    test_recv_packet();

    //CLEAN
    
} 
