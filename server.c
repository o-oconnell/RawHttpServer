#include <netinet/in.h> 
#include <stdio.h> 
#include <stdlib.h> 
#include <string.h>
#include <sys/socket.h> 
#include <sys/types.h> 
#include <asm-generic/mman.h>
#include <sys/mman.h>

#define ADDR_TO_BIND "0.0.0.0"
#define SERVER_PORT 8080
#define MSG_SIZE 1000

struct ip {
  uint8_t ver;    // Version
  uint8_t tos;    // Unused
  uint16_t len;   // Length
  uint16_t id;    // Unused
  uint16_t frag;  // Fragmentation
#define IP_FRAG_OFFSET_MSK 0x1fff
#define IP_MORE_FRAGS_MSK 0x2000
  uint8_t ttl;    // Time to live
  uint8_t proto;  // Upper level protocol
  uint16_t csum;  // Checksum
  uint32_t src;   // Source IP
  uint32_t dst;   // Destination IP
};

struct tcp {
  uint16_t sport;  // Source port
  uint16_t dport;  // Destination port
  uint32_t seq;    // Sequence number
  uint32_t ack;    // Acknowledgement number
  uint8_t off;     // Data offset
  uint8_t flags;   // TCP flags
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
  uint16_t win;   // Window
  uint16_t csum;  // Checksum
  uint16_t urp;   // Urgent pointer
};

// https://datatracker.ietf.org/doc/html/rfc9293#name-state-machine-overview
enum server_tcp_state {
    LISTEN,
    SYN_RECEIVED,
    ESTABLISHED
};

typedef struct Arena Arena;
struct Arena {
    uint64_t pos;
    void* block;
};

Arena *arenaAlloc(size_t size) {
    void *block = mmap(NULL, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (block == MAP_FAILED) {
        perror("mmap: ");
        exit(1);
    }

    Arena *arena = (Arena*) block;
    arena->pos = sizeof(Arena);
    arena->block = block;
    return arena;
}

void* pushArray(Arena *arena, size_t size) {
    void *result = (arena->block + arena->pos);
    arena->pos = arena->pos + size;

    return result;
}

unsigned short csum(unsigned short *buf, int len)
{
        unsigned long sum;
        for(sum=0; len>0; len--)
                sum += *buf++;

        sum = (sum >> 16) + (sum &0xffff);
        sum += (sum >> 16);

        return (unsigned short)(~sum);
}

static uint32_t csumup(uint32_t sum, const void *buf, size_t len) {
  size_t i;
  const uint8_t *p = (const uint8_t *) buf;
  for (i = 0; i < len; i++) sum += i & 1 ? p[i] : ((uint32_t) p[i]) << 8;
  return sum;
}

static uint16_t csumfin(uint32_t sum) {
  while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
  return htons(~sum & 0xffff);
}

static uint16_t ipcsum(const void *buf, size_t len) {
  uint32_t sum = csumup(0, buf, len);
  return csumfin(sum);
}

void print_byte_in_binary(unsigned char byte) {
    for (int i = 7; i >= 0; i--) {
        printf("%d", (byte >> i) & 1);
    }
    printf(" ");
}

void gen_http_response(Arena *arena, struct tcp *tcp_hdr, int raw_socket, char* html_response_buf, int html_response_buf_len) {
    
    int PCKT_LEN = sizeof(struct tcp) + html_response_buf_len;
    char *responseBuffer = pushArray(arena, PCKT_LEN);

    struct tcp *tcp = (struct tcp *) (responseBuffer);
    struct sockaddr_in sin, din;

    strncpy((responseBuffer + sizeof(struct tcp)), html_response_buf, html_response_buf_len);

    {
        uint16_t server_port =  SERVER_PORT;
        tcp->sport = htons(server_port);
        tcp->dport = tcp_hdr->sport;

        uint32_t isn = htonl((uint32_t) ntohs(tcp_hdr->sport));
        tcp->seq = isn; 
        tcp->ack = htonl(ntohl(tcp_hdr->seq) + 1);
        tcp->flags = TH_ACK;
        tcp->win = htons(32767);
        tcp->off = (uint8_t) (sizeof(*tcp) / 4 << 4); 


        size_t len = html_response_buf_len;
        uint8_t proto = 6;
        uint32_t cs = 0;
        uint16_t n = (uint16_t) (sizeof(*tcp) + len);
        uint8_t pseudo[] = {0, proto, (uint8_t) (n >> 8), (uint8_t) (n & 255)};

        cs = csumup(cs, tcp, n);
        uint32_t srcIp = inet_addr("127.0.0.1");
        uint32_t dstIp = inet_addr("127.0.0.1");
        cs = csumup(cs, &srcIp, sizeof(srcIp));
        cs = csumup(cs, &dstIp, sizeof(dstIp));
        cs = csumup(cs, pseudo, sizeof(pseudo));
        tcp->csum = csumfin(cs);
    }

    struct sockaddr_in dest;
    {    
        dest.sin_family = AF_INET;
        dest.sin_addr.s_addr = inet_addr(ADDR_TO_BIND);
        dest.sin_port = htons(SERVER_PORT);
    }

    if(sendto(raw_socket, responseBuffer, PCKT_LEN, 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        perror("sendto() error");
        exit(-1);
    } else 
        printf("sendto ok\n");
}

void standardServer(char* html_response_buf) {

    int servSockD = socket(AF_INET, SOCK_STREAM, 0); 
    struct sockaddr_in servAddr; 

	servAddr.sin_family = AF_INET; 
	servAddr.sin_port = htons(SERVER_PORT); 
	servAddr.sin_addr.s_addr = INADDR_ANY; 


    bind(servSockD, (struct sockaddr*)&servAddr, 
		sizeof(servAddr)); 

	listen(servSockD, 1); 


    int new_socket;
    while (1) {
        printf("Waiting for new connection...\n");
        if (new_socket = accept(servSockD, NULL, NULL)) {

            send(new_socket, html_response_buf, strlen(html_response_buf), 0);
            // printf("Hello message sent\n");

            // close(new_socket);
        }
    }
}



int main(int argc, char const* argv[]) 
{ 
    size_t arena_size = (1 << 30); // 1 GB
    Arena *arena = arenaAlloc(arena_size);

    int sd = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
    if(sd < 0)
    {
        perror("socket() error");
        exit(-1);
    } else
        printf("socket()-SOCK_RAW and tcp protocol is OK.\n");

    int html_response_buf_len = 1000;
    char *html_response_buf = pushArray(arena, 1000 * sizeof(char)); 
    { 
        FILE *fptr = fopen("test.html", "r");
        int HTML_FILESIZE = 1000;
        char *serMsg = pushArray(arena, HTML_FILESIZE);

        int bytesRead = 0;
        while ((bytesRead = fread(serMsg, 1, HTML_FILESIZE, fptr)) > 0) {
            serMsg[bytesRead] = '\0'; 
        }
        fclose(fptr); 

        int num_chars = sprintf(html_response_buf, "HHTTP/1.1 200 OK\r\n"
                                    "Content-Type: text/html; charset=UTF-8\r\n"
                                    "Content-Length: %lu\r\n"
                                    "Accept-Ranges: bytes\r\n"
                                    "Connection: close\r\n\r\n"
                                    "%s\r\n\0", 
                                    strlen(serMsg), (char*)serMsg);

        printf("Html response len %d, html response: \n%s\n", strlen(html_response_buf), html_response_buf);
    }

    // HTTP server using kernel tcp stack:
    // standardServer(html_response_buf);

    int raw_socket;
    
    struct sockaddr_in sockstr;
    socklen_t socklen;
    ssize_t msglen; 

    if ((raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1) {
        perror("socket");
        return 1;
    }

    sockstr.sin_family = AF_INET;
    sockstr.sin_port = htons(SERVER_PORT);
    sockstr.sin_addr.s_addr = inet_addr(ADDR_TO_BIND);
    socklen = (socklen_t) sizeof(sockstr);

    if (bind(raw_socket, (struct sockaddr*) &sockstr, socklen) == -1) {
        perror("bind");
        return;
    }

    struct ip* ip_hdr; 
    struct tcp* tcp_hdr; 
    enum server_tcp_state tcp_state = LISTEN;

    // TODO: why this need to be big enough for more than just headers
    char *incoming_packet = pushArray(arena, MSG_SIZE); 
    
    for (;;) {
        if (tcp_state == LISTEN) {

            if ((msglen = recvfrom(raw_socket, incoming_packet, 65536, 0, NULL, NULL)) < 0) {
                perror("recv");
                exit(1);
            }

            ip_hdr = incoming_packet;
            tcp_hdr = incoming_packet + sizeof(struct ip);

            // printf("Source ip is %d\n", ntohs(ip_hdr->src));
            // printf("Dest ip is %d\n", ntohs(ip_hdr->dst));
            // printf("Source port is %d\n", ntohs(tcp_hdr->sport));
            // printf("Dest port is %d\n", ntohs(tcp_hdr->dport));

            if ((tcp_hdr->flags & TH_SYN) && ntohs(tcp_hdr->dport) == SERVER_PORT) {
                printf("Received SYN\n");

                struct tcp *tcp = pushArray(arena, (sizeof(struct tcp)));
                struct sockaddr_in sin, din;

                tcp->sport = htons(SERVER_PORT);
                tcp->dport = tcp_hdr->sport;

                // https://community.infosecinstitute.com/discussion/73516/calculating-seq-ack-number
                uint32_t isn = htonl((uint32_t) ntohs(tcp_hdr->sport));
                tcp->seq = isn; 
                tcp->ack = htonl(ntohl(tcp_hdr->seq) + 1);
                tcp->flags = TH_SYN | TH_ACK;
                tcp->win = htons(32767); // 6000 in mongoose
                tcp->off = (uint8_t) (sizeof(*tcp) / 4 << 4);

                struct sockaddr_in dest;
                dest.sin_family = AF_INET;
                dest.sin_addr.s_addr = inet_addr(ADDR_TO_BIND);
                dest.sin_port = htons(SERVER_PORT);

                size_t len = 0;
                uint8_t proto = 6;
                uint32_t cs = 0;
                uint16_t n = (uint16_t) (sizeof(*tcp) + len);
                uint8_t pseudo[] = {0, proto, (uint8_t) (n >> 8), (uint8_t) (n & 255)};
                cs = csumup(cs, tcp, n);

                // TODO: hardcoded
                uint32_t srcIp = inet_addr("127.0.0.1");
                uint32_t dstIp = inet_addr("127.0.0.1");

                cs = csumup(cs, &srcIp, sizeof(srcIp));
                cs = csumup(cs, &dstIp, sizeof(dstIp));
                cs = csumup(cs, pseudo, sizeof(pseudo));
                tcp->csum = csumfin(cs);

                if(sendto(raw_socket, tcp, sizeof(struct tcp), 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
                    perror("sendto() error");
                    exit(-1);
                } else 
                    printf("sendto ok\n");

                fflush(stdout);
                printf("WAITNG FOR AN ACK\n");
                tcp_state = SYN_RECEIVED;
            }

             
        } else if (tcp_state == SYN_RECEIVED) {
            printf("SYN-RECEIVED\n");

            if ((msglen = recvfrom(raw_socket, incoming_packet, 65536 , 0 , NULL, NULL)) < 0) {
                perror("recv");
            }

            ip_hdr = incoming_packet;
            tcp_hdr = incoming_packet + sizeof(struct ip);

            // printf("Source ip is %d\n", ntohs(ip_hdr->src));
            // printf("Dest ip is %d\n", ntohs(ip_hdr->dst));
            // printf("Source port is %d\n", ntohs(tcp_hdr->sport));
            // printf("Dest port is %d\n", ntohs(tcp_hdr->dport));

            if (tcp_hdr->flags & (TH_ACK)) {
                printf("RECEIVED AN ACK\n");
                fflush(stdout);
                tcp_state = ESTABLISHED;
            }
        } else if (tcp_state == ESTABLISHED) {

            char *incoming_http_req = pushArray(arena, MSG_SIZE);
            // memset(incoming_http_req, 0, MSG_SIZE);

            // formerly passed 65536 instead of MSG_SIZE
            if ((msglen = recvfrom(raw_socket, incoming_http_req, MSG_SIZE, 0, NULL, NULL)) < 0) {
                perror("recv");
                exit(1);
            }

            struct ip *ip =  (struct ip*) incoming_http_req;
            struct tcp *tcp = (struct tcp*) (incoming_http_req + sizeof(struct ip));

            if (ntohs(tcp->dport) == SERVER_PORT) {
                char* payload = incoming_http_req + (sizeof(struct ip) + sizeof(struct tcp));

                if (payload[0] == 'G' && payload[1] == 'E' && payload[2] == 'T') {
                    printf("RECEIVED GET REQUEST\n");
                    payload[100] = '\0';
                    printf("GET payload is %s\n", payload);

                    gen_http_response(arena, tcp, raw_socket, html_response_buf, html_response_buf_len);
                }
            }

            printf("ESTABLISHED\n");
            fflush(stdout);
        } else {
            printf(stderr, "Unrecognized state \n");
            exit(1);
        }
    }

	return 0; 
}
