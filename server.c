#include <netinet/in.h> //structure for storing address information 
#include <stdio.h> 
#include <stdlib.h> 
#include <string.h>
#include <sys/socket.h> //for socket APIs 
#include <sys/types.h> 

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

unsigned short csum(unsigned short *buf, int len)
{
        unsigned long sum;
        for(sum=0; len>0; len--)
                sum += *buf++;

        sum = (sum >> 16) + (sum &0xffff);
        sum += (sum >> 16);

        return (unsigned short)(~sum);
}


#include <linux/ip.h> /* for ipv4 header */
#include <linux/udp.h> /* for udp header */



#define ADDR_TO_BIND "0.0.0.0"
#define SERVER_PORT 8080

#define MSG_SIZE 1000
#define HEADER_SIZE (sizeof(struct iphdr) + sizeof(struct udphdr))


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

void genpacket(struct tcp *tcp_hdr, int raw_socket, char* html_response_buf, int html_response_buf_len) {
    
    int PCKT_LEN = sizeof(struct tcp) + html_response_buf_len;
    char responseBuffer[PCKT_LEN];

    // The size of the headers
    // struct ip *ip = (struct ip *) responseBuffer;
    struct tcp *tcp = (struct tcp *) (responseBuffer);
    struct sockaddr_in sin, din;

    int one = 1;
    const int *val = &one;

    memset(responseBuffer, 0, PCKT_LEN);

    strncpy((responseBuffer + sizeof(struct tcp)), html_response_buf, html_response_buf_len);

    // // IP structure
    // ip->ver = 0x45;               // Version 4, header length 5 words
    // ip->frag = htons(0x4000);  // Don't fragment
    // printf("Sizeof struct tcp is %ld\n", sizeof(struct tcp));
    // // printf("Sizeof struct tcp converted to a uint16 is ", ((uint16_t)))
    
    // ip->len = htons((uint16_t) (sizeof(struct tcp)));
    // ip->ttl = 64;
    // ip->proto = 6;
    // ip->src = inet_addr("127.0.0.1");
    // ip->dst = inet_addr("127.0.0.1");
    // printf("Source IP %u\n", ntohl(ip->src));
    // printf("Dest IP %u\n", ntohl(ip->dst));

    // ip->csum = csum((unsigned short *) responseBuffer, (sizeof(struct ip) + sizeof(struct tcp)));

    uint16_t server_port =  SERVER_PORT;
    printf("Server port is %x\n", server_port);
    printf("Htons server port is %x\n", htons(server_port));

    tcp->sport = htons(server_port);
    printf("Sport hex: %x\n", tcp->sport);


    tcp->dport = tcp_hdr->sport;
    printf("Dport hex: %x\n", tcp->dport);

    uint32_t isn = htonl((uint32_t) ntohs(tcp_hdr->sport));

    tcp->seq = isn; // this can just be a random value so should

    printf("Setting the sequence number for the synACK to %u\n", (tcp->seq));

    // be fine to just copy the incoming seq number right.? https://community.infosecinstitute.com/discussion/73516/calculating-seq-ack-number

    // uint32_t cs = 0;
    // size_t len = 0;
    // uint16_t n = (uint16_t) (sizeof(*tcp) + len);
    // uint8_t pseudo[] = {0, ip->proto, (uint8_t) (n >> 8), (uint8_t) (n & 255)};
    // cs = csumup(cs, tcp, n);
    // cs = csumup(cs, &ip->src, sizeof(ip->src));
    // cs = csumup(cs, &ip->dst, sizeof(ip->dst));
    // cs = csumup(cs, pseudo, sizeof(pseudo));


    // tcp->csum = 0; // csumfin(cs);
    // printf("INCOMING SEQUENCE NUMBER %u, INCOMING LEN %u, added we get %u\n", ntohl(tcp_hdr->seq), ntohl(ip->len), ntohl(tcp_hdr->seq) + ntohl(ip->len));
    
    tcp->ack = htonl(ntohl(tcp_hdr->seq) + 1);
 
    tcp->flags = TH_ACK;

    tcp->win = htons(32767);
    tcp->off = (uint8_t) (sizeof(*tcp) / 4 << 4); // data offset? 

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = inet_addr(ADDR_TO_BIND);
    dest.sin_port = htons(SERVER_PORT);

    size_t len = html_response_buf_len;
    uint8_t proto = 6;
    uint32_t cs = 0;
    uint16_t n = (uint16_t) (sizeof(*tcp) + len);
    uint8_t pseudo[] = {0, proto, (uint8_t) (n >> 8), (uint8_t) (n & 255)};

    // printf("Cs is %d (%x)\n", cs, cs);
    cs = csumup(cs, tcp, n);
    // printf("Cs is %d (%x)\n", cs, cs);

    uint32_t srcIp = inet_addr("127.0.0.1");
    // printf("Src ip is %x\n", srcIp);

    uint32_t dstIp = inet_addr("127.0.0.1");
    // printf("Dest ip is %x\n", dstIp);


    cs = csumup(cs, &srcIp, sizeof(srcIp));
    // printf("Cs is %d (%x)\n", cs, cs);

    cs = csumup(cs, &dstIp, sizeof(dstIp));
    // printf("Cs is %d (%x)\n", cs, cs);

    cs = csumup(cs, pseudo, sizeof(pseudo));
    // printf("Cs is %d (%x)\n", cs, cs);

    tcp->csum = csumfin(cs);


    printf("SENDING THE SAME PACKET AGAIN TO SEE WHAT HAPPENS \n");
        if(sendto(raw_socket, responseBuffer, sizeof(responseBuffer), 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        perror("sendto() error");
        exit(-1);
    } else 
        printf("sendto ok");


    // return responseBuffer;

    // int packetlen = sizeof(struct tcp);
    // char *responseBuffer = (char*) malloc(sizeof(char) * packetlen);




    // struct tcp *tcp = (struct tcp *) (responseBuffer);
    // struct sockaddr_in sin, din;

    // int one = 1;
    // const int *val = &one;

    // memset(responseBuffer, 0, packetlen);


    // // strncpy((responseBuffer + sizeof(struct tcp)), payload, payload_len);


    // uint16_t server_port = SERVER_PORT;
    // printf("Server port is %x\n", server_port);
    // printf("Htons server port is %x\n", htons(server_port));

    // tcp->sport = htons(server_port);
    // printf("Sport hex: %x\n", tcp->sport);


    // tcp->dport = sport_networkorder;
    // printf("Dport hex: %x\n", tcp->dport);

    // uint32_t isn = htonl((uint32_t) ntohs(sport_networkorder));

    // tcp->seq = isn; // this can just be a random value so should

    // printf("Setting the sequence number for the GENPACKET to %u\n", ntohl(tcp->seq));

    //             // be fine to just copy the incoming seq number right.? https://community.infosecinstitute.com/discussion/73516/calculating-seq-ack-number

    //             // uint32_t cs = 0;
    //             // size_t len = 0;
    //             // uint16_t n = (uint16_t) (sizeof(*tcp) + len);
    //             // uint8_t pseudo[] = {0, ip->proto, (uint8_t) (n >> 8), (uint8_t) (n & 255)};
    //             // cs = csumup(cs, tcp, n);
    //             // cs = csumup(cs, &ip->src, sizeof(ip->src));
    //             // cs = csumup(cs, &ip->dst, sizeof(ip->dst));
    //             // cs = csumup(cs, pseudo, sizeof(pseudo));


    // // tcp->csum = 0; // csumfin(cs);

                

    //             // printf("INCOMING SEQUENCE NUMBER %u, INCOMING LEN %u, added we get %u\n", ntohl(tcp_hdr->seq), ntohl(ip->len), ntohl(tcp_hdr->seq) + ntohl(ip->len));
    
    // tcp->ack = htonl(ntohl(previous_seqnum_networkorder) + 1);
    // printf("Set the sequence number for the ACK to %u\n", ntohl(tcp->ack));
 
    // tcp->flags = TH_ACK;

    // // 6000 in mongoose
    // tcp->win = htons(32767);
    // tcp->off = (uint8_t) (sizeof(*tcp) / 4 << 4); // data offset? 

    // // struct sockaddr_in dest;
    // // dest.sin_family = AF_INET;
    // // dest.sin_addr.s_addr = inet_addr(ADDR_TO_BIND);
    // // dest.sin_port = htons(SERVER_PORT);

    // size_t len = 0;
    // uint8_t proto = 6;
    // uint32_t cs = 0;
    // uint16_t n = (uint16_t) (sizeof(*tcp) + len);
    // uint8_t pseudo[] = {0, proto, (uint8_t) (n >> 8), (uint8_t) (n & 255)};

    // printf("Cs is %d (%x)\n", cs, cs);
    // cs = csumup(cs, tcp, n);



    // printf("Cs is %d (%x)\n", cs, cs);

    // uint32_t srcIp = inet_addr("127.0.0.1");
    // printf("Src ip is %x\n", srcIp);

    // uint32_t dstIp = inet_addr("127.0.0.1");
    // printf("Dest ip is %x\n", dstIp);


    // cs = csumup(cs, &srcIp, sizeof(srcIp));
    // printf("Cs is %d (%x)\n", cs, cs);

    // cs = csumup(cs, &dstIp, sizeof(dstIp));
    // printf("Cs is %d (%x)\n", cs, cs);

    // cs = csumup(cs, pseudo, sizeof(pseudo));
    // printf("Cs is %d (%x)\n", cs, cs);

    // tcp->csum = csumfin(cs);

    // // for (int i = 0; i < packetlen; ++i) {

    // //     print_byte_in_binary(responseBuffer[i]);
        
    // // }

    // // tcp->csum = htons(ntohs(tcp->csum) - 1000);
    // printf("Final csum is %d (0x%x), htonl of the csum is 0x%x\n", tcp->csum, tcp->csum, htonl(tcp->csum));

    // return responseBuffer;
}


// #define PushArrayNoZero(arena, type, count) (type *)ArenaPushNoZero((arena), sizeof(type)*(count))
// #define PushArray(arena, type, count)       (type *)ArenaPush((arena), sizeof(type)*(count))
// root_function void *ArenaPushNoZero(Arena *arena, U64 size);
// root_function void *ArenaPush(Arena *arena, U64 size);


// root_function void *
// ArenaPushNoZero(Arena *arena, U64 size)
// {
//  void *result = 0;
//  if(arena->pos + size <= arena->size)
//  {
//   U8 *base = (U8 *)arena;
//   U64 post_align_pos = (arena->pos + (arena->align-1));
//   post_align_pos -= post_align_pos%arena->align;
//   U64 align = post_align_pos - arena->pos;
//   result = base + arena->pos + align;
//   arena->pos += size + align;
//   if(arena->commit_pos < arena->pos)
//   {
//    U64 size_to_commit = arena->pos - arena->commit_pos;
//    size_to_commit += ARENA_COMMIT_GRANULARITY - 1;
//    size_to_commit -= size_to_commit%ARENA_COMMIT_GRANULARITY;
//    OS_Commit(base + arena->commit_pos, size_to_commit);
//    arena->commit_pos += size_to_commit;
//   }
//  }
//  else
//  {
//   // NOTE(rjf): fallback strategy. right now, just fail.
//  }
//  return result;
// }

// root_function void
// OS_Commit(void *ptr, U64 size)
// {
//  U64 page_snapped_size = size;
//  page_snapped_size += OS_PageSize() - 1;
//  page_snapped_size -= page_snapped_size%OS_PageSize();
//  VirtualAlloc(ptr, page_snapped_size, MEM_COMMIT, PAGE_READWRITE);
// }

// root_function Arena *
// ArenaAlloc(U64 size)
// {
//  U64 size_roundup_granularity = Megabytes(64);
//  size += size_roundup_granularity-1;
//  size -= size%size_roundup_granularity;
//  void *block = ArenaImpl_Reserve(size);
//  U64 initial_commit_size = ARENA_COMMIT_GRANULARITY;
//  Assert(initial_commit_size >= sizeof(Arena));
//  ArenaImpl_Commit(block, initial_commit_size);
//  Arena *arena = (Arena *)block;
//  arena->pos = sizeof(Arena);
//  arena->commit_pos = initial_commit_size;
//  arena->align = 8;
//  arena->size = size;
//  return arena;
// }

// root_function void *
// OS_Reserve(U64 size)
// {
//  U64 gb_snapped_size = size;
//  gb_snapped_size += Gigabytes(1) - 1;
//  gb_snapped_size -= gb_snapped_size%Gigabytes(1);
//  void *ptr = VirtualAlloc(0, gb_snapped_size, MEM_RESERVE, PAGE_NOACCESS);
//  return ptr;
// }


// #define ARENA_COMMIT_GRANULARITY Kilobytes(4)

// #define Bytes(n)      (n)
// #define Kilobytes(n)  (n << 10)
// #define Megabytes(n)  (n << 20)
// #define Gigabytes(n)  (((U64)n) << 30)
// #define Terabytes(n)  (((U64)n) << 40)



// typedef int8_t   S8;
// typedef int16_t  S16;
// typedef int32_t  S32;
// typedef int64_t  S64;
// typedef uint8_t  U8;
// typedef uint16_t U16;
// typedef uint32_t U32;
// typedef uint64_t U64;
// typedef S8       B8;
// typedef S16      B16;
// typedef S32      B32;
// typedef S64      B64;
// typedef float    F32;
// typedef double   F64;
// typedef void VoidFunction(void);
// typedef struct U128 U128;
// struct U128 {U64 u64[2];};

// inline_function U128 U128Zero(void) {U128 v = {0}; return v;}
// inline_function B32 U128Match(U128 a, U128 b) {return a.u64[0] == b.u64[0] && a.u64[1] == b.u64[1];}



// // String shit from base_strings.c:
// root_function String8
// PushStr8Copy(Arena *arena, String8 string)
// {
//  String8 res;
//  res.size = string.size;
//  res.str = PushArrayNoZero(arena, U8, string.size + 1);
//  MemoryCopy(res.str, string.str, string.size);
//  res.str[string.size] = 0;
//  return res;
// }

// root_function String8
// PushStr8FV(Arena *arena, char *fmt, va_list args)
// {
//  String8 result = {0};
//  va_list args2;
//  va_copy(args2, args);
//  U64 needed_bytes = ts_stbsp_vsnprintf(0, 0, fmt, args)+1;


///// NOTE: #define PushArrayNoZero(arena, type, count) (type *)ArenaPushNoZero((arena), sizeof(type)*(count))


// so basically this pushes a string of size needed_bytes. Since each 
// char in the string is one u8


//  result.str = PushArrayNoZero(arena, U8, needed_bytes);  //HERE'S WHERE THE STRING ALLOCATION HAPPENS
//  result.size = needed_bytes - 1;
//  ts_stbsp_vsnprintf((char*)result.str, needed_bytes, fmt, args2);
//  return result;
// }

// root_function String8
// PushStr8F(Arena *arena, char *fmt, ...)
// {
//  String8 result = {0};
//  va_list args;
//  va_start(args, fmt);
//  result = PushStr8FV(arena, fmt, args);
//  va_end(args);
//  return result;
// }

void standardServer(char* html_response_buf) {

    int servSockD = socket(AF_INET, SOCK_STREAM, 0); 

    struct sockaddr_in servAddr; 

	servAddr.sin_family = AF_INET; 
	servAddr.sin_port = htons(SERVER_PORT); 
	servAddr.sin_addr.s_addr = INADDR_ANY; 


    bind(servSockD, (struct sockaddr*)&servAddr, 
		sizeof(servAddr)); 

	// listen for connections 
	listen(servSockD, 1); 


    int new_socket;
    while (1) {
        printf("Waiting for new connection...\n");
        // if ((new_socket = accept(servSockD, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
        if (new_socket = accept(servSockD, NULL, NULL)) {
            // perror("accept");
            // exit(EXIT_FAILURE);
            // Send message to the newly connected client

            // using strlen instead of sizeof here gets rid of the garbage at the end of the response
            send(new_socket, html_response_buf, strlen(html_response_buf), 0);
            // printf("Hello message sent\n");

            // Close the connection
            // close(new_socket);
        }
    }
}

// https://datatracker.ietf.org/doc/html/rfc9293#name-state-machine-overview
enum server_tcp_state {
    LISTEN,
    SYN_RECEIVED,
    ESTABLISHED
};


int main(int argc, char const* argv[]) 
{ 

    // Arena *arena = ArenaAlloc(Gigabytes(64));
    // Temp scratch = ScratchBegin(0, 0);
    // String8 local_data_path = PushStr8F(scratch.arena, "%S/data", binary_path);

    // static Shared * shared = PushArray(arena, Shared, 1);
    // U8 *i2u_ring_base = PushArrayNoZero(arena, U8, shared->i2u_ring_size);


    // ScratchEnd(scratch);

    int PCKT_LEN = sizeof(struct tcp); // sizeof(struct ip) + sizeof(struct tcp);
    printf("PCKT LEN IS %d\n", PCKT_LEN);

    char rawBuffer[PCKT_LEN];
    memset(rawBuffer, 0, PCKT_LEN);

    int sd = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);

    if(sd < 0)
    {
        perror("socket() error");
        exit(-1);
    } else
        printf("socket()-SOCK_RAW and tcp protocol is OK.\n");

    FILE *fptr = fopen("test.html", "r");
    char serMsg[1000];

    int bytesRead = 0;
    while ((bytesRead = fread(serMsg, 1, sizeof(serMsg) - 1, fptr)) > 0){
        
        printf("BytesRead is %d\n", bytesRead);
        printf("Sizeof serMsg is %lu\n", sizeof(serMsg));
        serMsg[bytesRead] = '\0'; 
      
        // printf("%s", serMsg);
    }

    fclose(fptr); 


    int html_response_buf_len = 1000;
    char html_response_buf[html_response_buf_len];
    char *tmp = html_response_buf;

    int num_chars = sprintf(tmp, "HHTTP/1.1 200 OK\r\n"
                                 "Content-Type: text/html; charset=UTF-8\r\n"
                                 "Content-Length: %lu\r\n"
                                 "Accept-Ranges: bytes\r\n"
                                 "Connection: close\r\n\r\n"
                                 "%s\r\n\0", 
                                 strlen(serMsg), (char*)serMsg);

    printf("Html response len %d, html response: \n%s\n", strlen(html_response_buf), html_response_buf);

    // HTTP server using kernel tcp stack
    // standardServer(html_response_buf);

    int raw_socket;
    struct sockaddr_in sockstr;
    socklen_t socklen;

    int retval = 0; 
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
        retval = 1; 
        return;
    }

    struct ip* ip_hdr; // = msg;
    struct tcp* tcp_hdr; //  = msg + sizeof(struct ip);
    char msg[MSG_SIZE];

    enum server_tcp_state tcp_state = LISTEN;

    for (;;) {
        if (tcp_state == LISTEN) {
            if ((msglen = recvfrom(raw_socket, msg, 65536 , 0 , NULL, NULL)) < 0) {
                perror("recv");
                exit(1);
            }

            ip_hdr = msg;
            tcp_hdr = msg + sizeof(struct ip);

            // printf("Source ip is %d\n", ntohs(ip_hdr->src));
            // printf("Dest ip is %d\n", ntohs(ip_hdr->dst));
            // printf("Source port is %d\n", ntohs(tcp_hdr->sport));
            // printf("Dest port is %d\n", ntohs(tcp_hdr->dport));

            if ((tcp_hdr->flags & TH_SYN) && ntohs(tcp_hdr->dport) == SERVER_PORT) {
                // send back a syn-ack, transfer to syn-received state.
                printf("Received a SYN!\n");

                            // if (tcp_hdr->flags & TH_ACK) {
            //     printf("Received an ACK!\n");
            // }

            char responseBuffer[PCKT_LEN];

            // The size of the headers

            // struct ip *ip = (struct ip *) responseBuffer;
            struct tcp *tcp = (struct tcp *) (responseBuffer);
            struct sockaddr_in sin, din;

            // int one = 1;
            // const int *val = &one;

            memset(responseBuffer, 0, PCKT_LEN);

            // // IP structure
            // ip->ver = 0x45;               // Version 4, header length 5 words
            // ip->frag = htons(0x4000);  // Don't fragment
            // printf("Sizeof struct tcp is %ld\n", sizeof(struct tcp));
            // // printf("Sizeof struct tcp converted to a uint16 is ", ((uint16_t)))
            
            // ip->len = htons((uint16_t) (sizeof(struct tcp)));
            // ip->ttl = 64;
            // ip->proto = 6;
            // ip->src = inet_addr("127.0.0.1");
            // ip->dst = inet_addr("127.0.0.1");
            // printf("Source IP %u\n", ntohl(ip->src));
            // printf("Dest IP %u\n", ntohl(ip->dst));

            // ip->csum = csum((unsigned short *) responseBuffer, (sizeof(struct ip) + sizeof(struct tcp)));

                uint16_t server_port =  SERVER_PORT;
                printf("Server port is %x\n", server_port);
                printf("Htons server port is %x\n", htons(server_port));

                tcp->sport = htons(server_port);
                printf("Sport hex: %x\n", tcp->sport);


                tcp->dport = tcp_hdr->sport;
                printf("Dport hex: %x\n", tcp->dport);

                uint32_t isn = htonl((uint32_t) ntohs(tcp_hdr->sport));

                tcp->seq = isn; // this can just be a random value so should

                printf("Setting the sequence number for the synACK to %u\n", (tcp->seq));

                // be fine to just copy the incoming seq number right.? https://community.infosecinstitute.com/discussion/73516/calculating-seq-ack-number

                // uint32_t cs = 0;
                // size_t len = 0;
                // uint16_t n = (uint16_t) (sizeof(*tcp) + len);
                // uint8_t pseudo[] = {0, ip->proto, (uint8_t) (n >> 8), (uint8_t) (n & 255)};
                // cs = csumup(cs, tcp, n);
                // cs = csumup(cs, &ip->src, sizeof(ip->src));
                // cs = csumup(cs, &ip->dst, sizeof(ip->dst));
                // cs = csumup(cs, pseudo, sizeof(pseudo));


                // tcp->csum = 0; // csumfin(cs);
                // printf("INCOMING SEQUENCE NUMBER %u, INCOMING LEN %u, added we get %u\n", ntohl(tcp_hdr->seq), ntohl(ip->len), ntohl(tcp_hdr->seq) + ntohl(ip->len));

                tcp->ack = htonl(ntohl(tcp_hdr->seq) + 1);
                tcp->flags = TH_SYN | TH_ACK;

                // 6000 in mongoose
                tcp->win = htons(32767);
                tcp->off = (uint8_t) (sizeof(*tcp) / 4 << 4); // data offset? 

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
                uint32_t srcIp = inet_addr("127.0.0.1");
                uint32_t dstIp = inet_addr("127.0.0.1");

                cs = csumup(cs, &srcIp, sizeof(srcIp));
                cs = csumup(cs, &dstIp, sizeof(dstIp));
                cs = csumup(cs, pseudo, sizeof(pseudo));
                tcp->csum = csumfin(cs);
                // printf("Cs is %d (%x)\n", cs, cs);
                // printf("CHECKSUM IS %x\n", tcp->csum);

                if(sendto(raw_socket, responseBuffer, sizeof(responseBuffer), 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
                    perror("sendto() error");
                    exit(-1);
                } else 
                    printf("sendto ok");
                // printf("SENDING THE SAME PACKET AGAIN TO SEE WHAT HAPPENS \n");
                //     if(sendto(raw_socket, responseBuffer, sizeof(responseBuffer), 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
                //     perror("sendto() error");
                //     exit(-1);
                // } else 
                //     printf("sendto ok");

                fflush(stdout);
                printf("WAITNG FOR AN ACK\n");


                tcp_state = SYN_RECEIVED;
            }

             
        } else if (tcp_state == SYN_RECEIVED) {
            printf("ENTERED SYN-RECEIVED\n");

            if ((msglen = recvfrom(raw_socket, msg, 65536 , 0 , NULL, NULL)) < 0) {
                perror("recv");
                retval = 1;
            }

            ip_hdr = msg;
            tcp_hdr = msg + sizeof(struct ip);


            printf("Source ip is %d\n", ntohs(ip_hdr->src));
            printf("Dest ip is %d\n", ntohs(ip_hdr->dst));
            printf("Source port is %d\n", ntohs(tcp_hdr->sport));
            printf("Dest port is %d\n", ntohs(tcp_hdr->dport));

            if (tcp_hdr->flags & (TH_ACK)) {
                printf("RECEIVED AN ACK\n");
                fflush(stdout);
                tcp_state = ESTABLISHED;
            }

            // wait for an ack, when we receive it then transfer to tcp state established
            // in tcp state established we're basically gonna check if what's coming in is a get or not
        } else if (tcp_state == ESTABLISHED) {

            char incoming_http_req[MSG_SIZE];
            if ((msglen = recvfrom(raw_socket, incoming_http_req, 65536 , 0 , NULL, NULL)) < 0) {
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

                        printf("SENDING SAME PACKET AGAIN, CHECKSUM SHOULD BE GOOD!!!\n");
                        genpacket(tcp, raw_socket, html_response_buf, html_response_buf_len);
                    }
            }
            

            printf("ENTERED ESTABLISHED\n");
            fflush(stdout);

            // temporary hack to keep accepting requests
            // tcp_state = LISTEN;
            // continue;
            

        } else {
            printf(stderr, "Unrecognized state \n");
            exit(1);
        }
        continue;

        if ((msglen = recvfrom(raw_socket, msg, 65536 , 0 , NULL, NULL))) {
            perror("recv");
            retval = 1;
        }

        ip_hdr = msg;
        tcp_hdr = msg + sizeof(struct ip);

        // printf("Source ip is %d\n", ntohs(ip_hdr->src));
        // printf("Dest ip is %d\n", ntohs(ip_hdr->dst));
        // printf("Source port is %d\n", ntohs(tcp_hdr->sport));
        // printf("Dest port is %d\n", ntohs(tcp_hdr->dport));

        if ((tcp_hdr->flags & TH_SYN) && ntohs(tcp_hdr->dport) == SERVER_PORT) {
            printf("Received a SYN!\n");

            // if (tcp_hdr->flags & TH_ACK) {
            //     printf("Received an ACK!\n");
            // }

            char responseBuffer[PCKT_LEN];

            // The size of the headers

            // struct ip *ip = (struct ip *) responseBuffer;
            struct tcp *tcp = (struct tcp *) (responseBuffer);
            struct sockaddr_in sin, din;

            // int one = 1;
            // const int *val = &one;

            memset(responseBuffer, 0, PCKT_LEN);

            // // IP structure
            // ip->ver = 0x45;               // Version 4, header length 5 words
            // ip->frag = htons(0x4000);  // Don't fragment
            // printf("Sizeof struct tcp is %ld\n", sizeof(struct tcp));
            // // printf("Sizeof struct tcp converted to a uint16 is ", ((uint16_t)))
            
            // ip->len = htons((uint16_t) (sizeof(struct tcp)));
            // ip->ttl = 64;
            // ip->proto = 6;
            // ip->src = inet_addr("127.0.0.1");
            // ip->dst = inet_addr("127.0.0.1");
            // printf("Source IP %u\n", ntohl(ip->src));
            // printf("Dest IP %u\n", ntohl(ip->dst));

            // ip->csum = csum((unsigned short *) responseBuffer, (sizeof(struct ip) + sizeof(struct tcp)));

            uint16_t server_port =  SERVER_PORT;
            printf("Server port is %x\n", server_port);
            printf("Htons server port is %x\n", htons(server_port));

            tcp->sport = htons(server_port);
            printf("Sport hex: %x\n", tcp->sport);


            tcp->dport = tcp_hdr->sport;
            printf("Dport hex: %x\n", tcp->dport);

            uint32_t isn = htonl((uint32_t) ntohs(tcp_hdr->sport));

            tcp->seq = isn; // this can just be a random value so should

            printf("Setting the sequence number for the synACK to %u\n", (tcp->seq));

                // be fine to just copy the incoming seq number right.? https://community.infosecinstitute.com/discussion/73516/calculating-seq-ack-number

                // uint32_t cs = 0;
                // size_t len = 0;
                // uint16_t n = (uint16_t) (sizeof(*tcp) + len);
                // uint8_t pseudo[] = {0, ip->proto, (uint8_t) (n >> 8), (uint8_t) (n & 255)};
                // cs = csumup(cs, tcp, n);
                // cs = csumup(cs, &ip->src, sizeof(ip->src));
                // cs = csumup(cs, &ip->dst, sizeof(ip->dst));
                // cs = csumup(cs, pseudo, sizeof(pseudo));


    // tcp->csum = 0; // csumfin(cs);

                

                // printf("INCOMING SEQUENCE NUMBER %u, INCOMING LEN %u, added we get %u\n", ntohl(tcp_hdr->seq), ntohl(ip->len), ntohl(tcp_hdr->seq) + ntohl(ip->len));
    
        tcp->ack = htonl(ntohl(tcp_hdr->seq) + 1);
    
        tcp->flags = TH_SYN | TH_ACK;

        // 6000 in mongoose
        tcp->win = htons(32767);
        tcp->off = (uint8_t) (sizeof(*tcp) / 4 << 4); // data offset? 

        struct sockaddr_in dest;
        dest.sin_family = AF_INET;
        dest.sin_addr.s_addr = inet_addr(ADDR_TO_BIND);
        dest.sin_port = htons(SERVER_PORT);

        size_t len = 0;
        uint8_t proto = 6;
        uint32_t cs = 0;
        uint16_t n = (uint16_t) (sizeof(*tcp) + len);
        uint8_t pseudo[] = {0, proto, (uint8_t) (n >> 8), (uint8_t) (n & 255)};

        // printf("Cs is %d (%x)\n", cs, cs);
        cs = csumup(cs, tcp, n);
        // printf("Cs is %d (%x)\n", cs, cs);

        uint32_t srcIp = inet_addr("127.0.0.1");
        // printf("Src ip is %x\n", srcIp);

        uint32_t dstIp = inet_addr("127.0.0.1");
        // printf("Dest ip is %x\n", dstIp);


        cs = csumup(cs, &srcIp, sizeof(srcIp));
        // printf("Cs is %d (%x)\n", cs, cs);

        cs = csumup(cs, &dstIp, sizeof(dstIp));
        // printf("Cs is %d (%x)\n", cs, cs);

        cs = csumup(cs, pseudo, sizeof(pseudo));
        // printf("Cs is %d (%x)\n", cs, cs);

        tcp->csum = csumfin(cs);
        // printf("Cs is %d (%x)\n", cs, cs);
        // printf("CHECKSUM IS %x\n", tcp->csum);

        if(sendto(raw_socket, responseBuffer, sizeof(responseBuffer), 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
            perror("sendto() error");
            exit(-1);
        } else 
            printf("sendto ok");


    
    // printf("SENDING THE SAME PACKET AGAIN TO SEE WHAT HAPPENS \n");
    //     if(sendto(raw_socket, responseBuffer, sizeof(responseBuffer), 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
    //     perror("sendto() error");
    //     exit(-1);
    // } else 
    //     printf("sendto ok");




    fflush(stdout);

    printf("WAITNG FOR AN ACK\n");
    for (;;) {
        if ((msglen = recvfrom(raw_socket, msg, 65536 , 0 , NULL, NULL)) < 0) {
            perror("recv");
            retval = 1;
            // goto _go_close_socket;
        }


        ip_hdr = msg;
        tcp_hdr = msg + sizeof(struct ip);


        printf("Source ip is %d\n", ntohs(ip_hdr->src));
        printf("Dest ip is %d\n", ntohs(ip_hdr->dst));
        printf("Source port is %d\n", ntohs(tcp_hdr->sport));
        printf("Dest port is %d\n", ntohs(tcp_hdr->dport));

        if (tcp_hdr->flags & (TH_ACK)) {
            printf("RECEIVED AN ACK\n");
        
            char* payload = msg + (sizeof(struct ip) + sizeof(struct tcp));
            printf("ACK payload is %s\n", payload);

            // receive http GET
            for (;;) {

                char incoming_http_req[MSG_SIZE];
                if ((msglen = recvfrom(raw_socket, incoming_http_req, 65536 , 0 , NULL, NULL)) < 0) {
                    perror("recv");
                    retval = 1;
                    // goto _go_close_socket;
                }

                struct ip *ip =  (struct ip*) incoming_http_req;
                struct tcp *tcp = (struct tcp*) (incoming_http_req + sizeof(struct ip));

                // for (int i = 0; i < MSG_SIZE; ++i) {
                //     print_byte_in_binary(incoming_http_req[i]);
                //     if (i % 7 == 0) {
                //         printf("\n");
                //     }
                // }
                // for ()
                if (ntohs(tcp->dport) == 8080) {
                    char* payload = incoming_http_req + (sizeof(struct ip) + sizeof(struct tcp));
                    payload[100] = '\0';

                    if (payload[0] == 'G' && payload[1] == 'E' && payload[2] == 'T') {


                        // printf("RECEIVED A NEW REQUEST AFTER RECEIVING AN ACK, dest port %d, seqnum %u\n", ntohs(tcp->dport), ntohl(tcp->seq));

                        // printf("THE RAW DATA IS: \n");
                        // printf("Source ip is %d\n", ntohs(ip->src));
                        // printf("Dest ip is %d\n", ntohs(ip->dst));
                        // printf("Source port is %d\n", ntohs(tcp->sport));
                        // printf("Dest port is %d\n", ntohs(tcp->dport));
                        printf("RECEIVED GET REQUEST\n");
                        printf("Payload is %s\n", payload);



                        printf("SENDING SAME PACKET AGAIN, CHECKSUM SHOULD BE GOOD!!!\n");
                        genpacket(tcp, raw_socket, html_response_buf, html_response_buf_len);

                        // printf("SENDING Same Packet AGAIN to figure out why the checksum is incorrect: \n");
                        // for (int i = 0; i < sizeof(struct tcp) + html_response_buf_len; ++i) {
                        //     print_byte_in_binary(response[i]);

                        //     if (i % 8 == 0) {
                        //         printf("\n");
                        //     }
                        // }                

                        // printf("Before the sendto!\n");
                        // if(sendto(raw_socket, response, sizeof(struct tcp) + html_response_buf_len, 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
                        //     perror("sendto() error");
                        //     exit(-1);
                        // } else 
                        //     printf("sendto ok");

                        return;
                    }

                    // printf("Printing payload binary: \n");
                    // int payload_len = MSG_SIZE - (sizeof(struct tcp) + sizeof(struct ip));
                    // for (int i = (sizeof(struct tcp) + sizeof(struct ip)); i < payload_len; ++i) {
                    //     print_byte_in_binary(payload[i]);

                    //     if ((i + 15) % 8 == 0) {
                    //         printf("\n (i == %x) ", (i + 15));
                    //     }
                    // }

                    // printf("\n\nNow printing the entire buffer in binary:\n ");
                    

                    // ok, so I starts at the 15th byte where i = 14. When i = 15, 
                    // we want to print a newline. 

                    // our i is actually zero where i is supposed to be 14. So say we 
                    // add 14 to it. Then once I gets to be 15, we won't actually print a newline.

                    // another way to view it is we want to print a newline when i = 1,
                    // when i = 9, when i = 17, etc.

                    // so technically if i - 1 % 8 == 0 


                    // and what about the numbering? well we want the first number to be 
                    // 0010 which is 16 hex. At this point i will be equal to 0. So add 16 and print it.

                    // for (int i = 0; i < MSG_SIZE; ++i) {
                    //     print_byte_in_binary(incoming_http_req[i]);
                    //     // printf("")
                    //     if ((i - 1) % 8 == 0) {
                    //         printf("\n (i == %x) ", (i + 15));
                    //     }

                    //     // bro, what. am i retarded. what's going on here. 
                    // }

                    // printf("Payload is %s\n", payload);
                    
                }
            }

        }
        
    }

  continue;


    	// bind(servSockD, (struct sockaddr*)&servAddr, 
	// 	sizeof(servAddr)); 

	// listen for connections 
    // if (listen(raw_socket, 1) == -1) {
    //     perror("LISTEN");
    //     retval = 1; /* '1' means "Error" */
    //     return;
    //     // goto _go_close_socket;
    // }

    memset(msg, 0, MSG_SIZE);
    // listen(raw_socket, 1);



        return; // ------------------------------------------------------




                // char *responseBuffer = malloc(PCKT_LEN * sizeof(char));

                // The size of the headers

                // struct ip *ip = (struct ip *) responseBuffer;
                // struct tcp *tcp = (struct tcp *) (responseBuffer);
                // struct sockaddr_in sin, din;

                // int one = 1;
                // const int *val = &one;

                // memset(responseBuffer, 0, PCKT_LEN);

                // // IP structure
                // ip->ver = 0x45;               // Version 4, header length 5 words
                // ip->frag = htons(0x4000);  // Don't fragment
                // printf("Sizeof struct tcp is %ld\n", sizeof(struct tcp));
                // printf("Sizeof struct tcp converted to a uint16 is ", ((uint16_t)))
                
                // ip->len = htons((uint16_t) (sizeof(struct tcp)));
                // ip->ttl = 64;
                // ip->proto = 6;
                // ip->src = ip_hdr->dst;
                // ip->dst = ip_hdr->src;
                // printf("Source IP %u\n", ntohl(ip->src));
                // printf("Dest IP %u\n", ntohl(ip->dst));

                // ip->csum = csum((unsigned short *) responseBuffer, (sizeof(struct ip) + sizeof(struct tcp)));


                // tcp->sport = tcp_hdr->dport;
                // tcp->dport = tcp_hdr->sport;
                // tcp->seq = htonl( (uint32_t)ntohs(tcp_hdr->sport)); // this can just be a random value so should

                // printf("Setting the sequence number for the synACK to %u\n", ((uint32_t)ntohs(tcp_hdr->sport)));

                // be fine to just copy the incoming seq number right.? https://community.infosecinstitute.com/discussion/73516/calculating-seq-ack-number

                // uint32_t cs = 0;
                // size_t len = 0;
                // uint16_t n = (uint16_t) (sizeof(*tcp) + len);
                // uint8_t pseudo[] = {0, ip->proto, (uint8_t) (n >> 8), (uint8_t) (n & 255)};
                // cs = csumup(cs, tcp, n);
                // cs = csumup(cs, &ip->src, sizeof(ip->src));
                // cs = csumup(cs, &ip->dst, sizeof(ip->dst));
                // cs = csumup(cs, pseudo, sizeof(pseudo));
                // tcp->csum = 0; //csumfin(cs);

                
                // printf("INCOMING SEQUENCE NUMBER %u, INCOMING LEN %u, added we get %u\n", ntohl(tcp_hdr->seq), ntohl(ip->len), ntohl(tcp_hdr->seq) + ntohl(ip->len));
                // tcp->ack = htonl(ntohl(tcp_hdr->seq) + 1);
                
                // printf("SETTING ACK %u\n", ntohl(tcp->ack));
                // tcp->flags = TH_SYN | TH_ACK;

                // // 6000 in mongoose
                // tcp->win = htons(32767);
                // tcp->off = (uint8_t) (sizeof(*tcp) / 4 << 4); // data offset? 
                // ^pretty sure this is the header length. Yes, it's 8 bits and comes directly 
                // prior to the flags

                // int sd = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);

                // if(sd < 0)
                // {
                //     perror("socket() error");
                //     exit(-1);
                // } else
                //     printf("socket()-SOCK_RAW and tcp protocol is OK.\n");

                // // The source is redundant, may be used later if needed
                // // // Address familysendto
                // sin.sin_family = AF_INET;
                // // // din.sin_family = AF_INET;

                // // // Source port, can be any, modify as needed

                // sin.sin_port = tcp_hdr->dport;
                // // din.sin_port = htons(SERVER_PORT);

                // // Source IP, can be any, modify as needed
                // char *dstIp = "127.0.0.1";
                // // char *dstIp = "127.0.0.1";

                // char srcPort[100];
                // sprintf(srcPort, "%d", tcp_hdr->dport);
                // char *srcPort = itoa(ntohs(tcp_hdr->dport));
                // sin.sin_addr.s_addr =  inet_addr(ADDR_TO_BIND);
                // din.sin_addr.s_addr = inet_addr(dstIp);

    // printf("SIN sin_family %u, sin_port_t %u, sin_addr %u, socklen %u\n ", sin.sin_family, sin.sin_port, sin.sin_addr.s_addr, sizeof(sockstr));



// UNCOMMENT ME TO GET SD BACK
                // if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
                // {
                //     perror("setsockopt() error");
                //     exit(-1);
                // } else
                //     printf("setsockopt() is OK\n");

                // printf("Using:::::Source IP: %s port: %u, Target IP: %s port: %u.\n", srcIp, atoi(srcPort), dstIp, atoi(dstPort));

                
                // for (int i = 0; i < sizeof(struct ip) + sizeof(struct tcpheader); ++i) {
                //     printf("Raw buffer chraw_socketar is %d\n", (int)rawBuffer[i]);
                // }

                // unsigned int count;
                // // printf("Before the SENDTO! Response buffer size is %lu, ip->len is %hu\n", sizeof(responseBuffer), ntohs(ip->len));
                // fflush(stdout);

                // SIN is destination address
                    // sin.sin_family = AF_INET;
    // din.sin_family = AF_INET;

    // Source port, can be any, modify as needed
    // sin.sin_port = htons(atoi("55555"));
    // din.sin_port = htons(atoi(sprintf("%s", SERVER_PORT)));

    // // Source IP, can be any, modify as needed
    // char *srcIp = "127.0.0.1";
    // char *dstIp = "127.0.0.1";
    
    // char *srcPort = "55555";
    // sin.sin_addr.s_addr = inet_addr(srcIp);
    // din.sin_addr.s_addr = inet_addr(dstIp);

                printf("AFTER THE SENDTO!");
                fflush(stdout);
                // sleep(2);
        


            printf("Msglen is %d\n", msglen);

            if (msglen <= HEADER_SIZE) /* msg  can't be lesser than header! */
                printf("No msg!\n");
            else {
                msg[msglen - 1] = '\0'; /* we need a null character at the end*/
                printf("Your msg _plus_ headers's size is: %s\n",
                    msg + HEADER_SIZE);
            }


            printf("WAITNG FOR AN ACK\n");
            for (;;) {
                if ((msglen = recvfrom(raw_socket, msg, 65536 , 0 , NULL, NULL)) < 0) {
                    perror("recv");
                    retval = 1;
                    // goto _go_close_socket;
                }

                // struct ip* ip_hdr = msg;
                // struct tcp* tcp_hdr = msg + sizeof(struct ip);

                // if ((tcp_hdr->flags & TH_ACK ) && ntohs(tcp_hdr->dport) == SERVER_PORT) {
                //     printf("RECEIVED AN ACK\n");
                //     printf("Source ip is %d\n", ntohs(ip_hdr->src));
                //     printf("Dest ip is %d\n", ntohs(ip_hdr->dst));
                //     printf("Source port is %d\n", ntohs(tcp_hdr->sport));
                //     printf("Dest port is %d\n", ntohs(tcp_hdr->dport));
                //     break;
                // }
            }


            break;
        }

    }

    return retval;

	return 0; 
}
