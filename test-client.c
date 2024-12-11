#include <netinet/in.h> //structure for storing address information 
#include <stdio.h> 
#include <stdlib.h> 
#include <string.h>
#include <sys/socket.h> //for socket APIs 
#include <sys/types.h> 


struct ipheader {

// using short int instead of char fixes "offset of packed field has changed in gcc 4.4"
 unsigned short int      iph_ihl:4, /* Little-endian */

                    iph_ver:4;

 unsigned char      iph_tos;

 uint16_t iph_len;

 uint16_t iph_ident;

 unsigned char      iph_flags;

 unsigned short int iph_offset;

 unsigned char      iph_ttl;

 unsigned char      iph_protocol;

 unsigned short int iph_chksum;

 unsigned int       iph_sourceip;

 unsigned int       iph_destip;

} __attribute__((packed));

 

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

/* Structure of a TCP header */
struct tcpheader {
 unsigned short int tcph_srcport;
 unsigned short int tcph_destport;
 unsigned int       tcph_seqnum;
 unsigned int       tcph_acknum;
 unsigned char      tcph_reserved:4, tcph_offset:4;

 // unsigned char tcph_flags;

  unsigned int

       tcp_res1:4,      /*little-endian*/

       tcph_hlen:4,     /*length of tcp header in 32-bit words*/

       tcph_fin:1,      /*Finish flag "fin"*/

       tcph_syn:1,       /*Synchronize sequence numbers to start a connection*/

       tcph_rst:1,      /*Reset flag */

       tcph_psh:1,      /*Push, sends data to the application*/

       tcph_ack:1,      /*acknowledge*/

       tcph_urg:1,      /*urgent pointer*/

       tcph_res2:2;

 unsigned short int tcph_win;
 unsigned short int tcph_chksum;
 unsigned short int tcph_urgptr;

} __attribute((packed))__;

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


int main(int argc, char const* argv[]) 
{ 

    int PCKT_LEN = 100; // sizeof(struct ip) + sizeof(struct tcp);
    printf("PCKT LEN IS %d\n", PCKT_LEN);
    int sd;

    // No data, just datagram

    char rawBuffer[PCKT_LEN];

    // The size of the headers

    // struct ip *ip = (struct ip *) rawBuffer;

    // struct tcp *tcp = (struct tcp *) (rawBuffer + sizeof(struct ip));

    // struct sockaddr_in sin; //, din;

    // int one = 1;

    // const int *val = &one;

    memset(rawBuffer, 0, PCKT_LEN);

    // if(argc != 5)
    // {
    //     printf("- Invalid parameters!!!\n");
    //     printf("- Usage: %s <source hostname/IP> <source port> <target hostname/IP> <target port>\n", argv[0]);
    //     exit(-1);

    // }

    

    sd = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);

    if(sd < 0)
    {
        perror("socket() error");
        exit(-1);
    }

    else

    printf("socket()-SOCK_RAW and tcp protocol is OK.\n");

    // The source is redundant, may be used later if needed
    // Address family

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

    // IP structure

    // ip->ver = 0x45;               // Version 4, header length 5 words
    // ip->frag = htons(0x4000);  // Don't fragment
    // ip->len = htons((uint16_t) (sizeof(*ip) + sizeof(struct tcpheader)));
    // ip->ttl = 64;
    // ip->proto = 6;
    // ip->src = inet_addr(srcIp);
    // ip->dst = inet_addr(dstIp);

    // ip->csum = ipcsum(ip, sizeof(*ip));
    // ip->csum = csum((unsigned short *) rawBuffer, (sizeof(struct ip) + sizeof(struct tcpheader)));
    

    // ip->iph_ihl = 5;
    // ip->iph_ver = 4;
    // ip->iph_tos = 16;

    
    // ip->iph_len = sizeof(struct ipheader) + sizeof(struct tcpheader);
    // printf("Just set iph_len to %d\n", ip->iph_len);

    // ip->iph_ident = htons(54321);

    // ip->iph_offset = 0;

    // ip->ip9090h_ttl = 64;

    // ip->iph_protocol = 6; // TCP

    // ip->iph_chksum = 0; // Done by kernel

    

    // Source IP, modify as needed, spoofed, we accept through command line argument

    // ip->iph_sourceip = inet_addr(srcIp);

    // Destination IP, modify as needed, but here we accept through command line argument

    // ip->iph_destip = inet_addr(dstIp);

    

    // The TCP structure. The source port, spoofed, we accept through the command line

    // tcp->tcph_srcport = htons(atoi(srcPort));

    // // The destination port, we accept through command line

    // char *dstPort = sprintf("%s", SERVER_PORT);

    // tcp->sport = htons(atoi(srcPort));
    // tcp->dport = htons(atoi(dstPort));
    // tcp->seq = htonl(1);
    // tcp->ack = 0;
    // tcp->flags = TH_SYN | TH_ACK;

    // // 6000 in mongoose
    // tcp->win = htons(32767);
    // tcp->off = (uint8_t) (sizeof(*tcp) / 4 << 4); // data offset? 


    // tcp->tcph_destport = htons(atoi(dstPort));

    // tcp->tcph_seqnum = htonl(1);

    // tcp->tcph_acknum = 0;

    // tcp->tcph_offset = 5;

    // tcp->tcph_syn = 1;

    // tcp->tcph_ack = 0;

    // tcp->tcph_win = htons(32767);

    // tcp->tcph_chksum = 0; // Done by kernel

    // tcp->tcph_urgptr = 0;

    // IP checksservSockDum calculation

    // ip->iph_chksum = csum((unsigned short *) rawBuffer, (sizeof(struct ipheader) + sizeof(struct tcpheader)));

    // Inform the kernel do not fill up the headers' structure, we fabricated our own

    // if(setsockopt(sd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
    // {
    //     perror("setsockopt() error");
    //     exit(-1);
    // }

    // else

    // printf("setsockopt() is OK\n");

    

    // printf("Using:::::Source IP: %s port: %u, Target IP: %s port: %u.\n", srcIp, atoi(srcPort), dstIp, atoi(dstPort));

    
    for (int i = 0; i < sizeof(struct ip) + sizeof(struct tcpheader); ++i) {
        printf("Raw buffer char is %d\n", (int)rawBuffer[i]);
    }

    // sendto() loop, send every 2 second for 50 counts

    unsigned int count;

    // for(count = 0; count < 20; count++)
    // {   
    //     if(sendto(sd, rawBuffer, ip->len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
    //         perror("sendto() error");
    //         exit(-1);
    //     } else
    //         printf("Count #%u - sendto() is OK\n", count);
    //     sleep(2);
    // }

    // close(sd);


    




	// create server socket similar to what was done in 
	// client program 
	int servSockD = socket(AF_INET, SOCK_STREAM, 0); 

	// string store data to send to client 
	// char serMsg[255] = "Message from the server to the "
					// "client \'Hello Client\' "; 

    FILE *fptr;

    // Open a file in read mode
    fptr = fopen("test.html", "r");

    // Store the content of the file
    char serMsg[1000];

    // Read the content and store it inside myString
    int bytesRead = 0;
    while ((bytesRead = fread(serMsg, 1, sizeof(serMsg) - 1, fptr)) > 0){
        
        printf("BytesRead is %d\n", bytesRead);
        printf("Sizeof serMsg is %lu\n", sizeof(serMsg));
        // Null-terminate the rawBuffer
        serMsg[bytesRead] = '\0'; 
      
        // Print the read data
        // printf("%s", serMsg);
    }

    // Print the file content
    // printf("%s", serMsg);

    // // Close the file
    // fclose(fptr); 


    char buffer[1000];
    char *tmp = buffer;

    int num_chars = sprintf(tmp, "HTTP/1.0 200 OK\r\n");
    tmp += num_chars;

    num_chars = sprintf(tmp, "Content-Type: text/html; charset=UTF-8\r\n");
    tmp += num_chars;

    num_chars = sprintf(tmp, "Content-Length: %lu\r\n", strlen(serMsg));
    tmp += num_chars;

    num_chars = sprintf(tmp, "Accept-Ranges: bytes\r\n");
    tmp += num_chars; 

    num_chars = sprintf(tmp, "Connection: close\r\n\r\n");
    tmp += num_chars;

    num_chars = sprintf(tmp, "%s\r\n", (char*)serMsg);
    tmp += num_chars;

    num_chars = sprintf(tmp, "\0");
    tmp+= num_chars;
    // tmp[num_chars] = '\0';

    

    printf("Num chars is %d, sending html response: \n%s\n", strlen(buffer), buffer);


	// define server address 
	struct sockaddr_in servAddr; 

	servAddr.sin_family = AF_INET; 
	servAddr.sin_port = htons(SERVER_PORT); 
	servAddr.sin_addr.s_addr = INADDR_ANY; 


    // }0-------------------

	// bind socket to the specified IP and port 
	// bind(servSockD, (struct sockaddr*)&servAddr, 
	// 	sizeof(servAddr)); 

	// // listen for connections 
	// listen(servSockD, 1); 


    // int new_socket;
    // while (1) {
    //     printf("Waiting for new connection...\n");
    //     // if ((new_socket = accept(servSockD, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
    //     if (new_socket = accept(servSockD, NULL, NULL)) {
    //         // perror("accept");
    //         // exit(EXIT_FAILURE);
    //         // Send message to the newly connected client

    //         // using strlen instead of sizeof here gets rid of the garbage at the end of the response
    //         send(new_socket, buffer, strlen(buffer), 0);
    //         // printf("Hello message sent\n");

    //         // Close the connection
    //         // close(new_socket);
    //     }
    // }

    // return;


    // -------	// // bind socket to the specified IP and port 
	// bind(servSockD, (struct sockaddr*)&servAddr, 
	// 	sizeof(servAddr)); 

	// // listen for connections 
	// listen(servSockD, 1); 


    // int new_socket;
    // while (1) {
    //     printf("Waiting for new connection...\n");
    //     // if ((new_socket = accept(servSockD, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
    //     if (new_socket = accept(servSockD, NULL, NULL)) {
    //         // perror("accept");
    //         // exit(EXIT_FAILURE);
    //         // Send message to the newly connected client

    //         // using strlen instead of sizeof here gets rid of the garbage at the end of the response
    //         send(new_socket, buffer, strlen(buffer), 0);
    //         // printf("Hello message sent\n");

    //         // Close the connection
    //         // close(new_socket);
    //     }
    // }0-------------------

	// // integer to hold client socket. 
	// int clientSocket = accept(servSockD, NULL, NULL); 

	// // send's messages to client socket 

    // for (;;) {
    // 	send(clientSocket, buffer, sizeof(buffer), 0);    
    // }
    int raw_socket;
    struct sockaddr_in sockstr;
    socklen_t socklen;

    int retval = 0; /* the return value (give a look when an error happens)
                     */

    /* no pointer to array!
     * >> It was like "a variable that contains an address -- and in this
     *    address begins an array of chars"! */
    /* now it is simple an array of chars :-)  */
    char msg[MSG_SIZE];
    ssize_t msglen; /* return value from recv() */

    /* do not use IPPROTO_RAW to receive packets */

    // Note: we never call setsockopt on this socket, so IP headers are generated for us by the kernel
    // using the information we pass with struct sockaddr_in
    if ((raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1) {
        perror("socket");
        return 1; /* here there is no clean up -- retval was not used */
    }

    sockstr.sin_family = AF_INET;
    sockstr.sin_port = htons(SERVER_PORT);
    sockstr.sin_addr.s_addr = inet_addr(ADDR_TO_BIND);
    socklen = (socklen_t) sizeof(sockstr);

    printf("Sockstr sin_family %u, sin_port_t %u, sin_addr %u, socklen %u\n ", sockstr.sin_family, sockstr.sin_port, sockstr.sin_addr.s_addr, socklen);

    /* use socklen instead sizeof()  Why had you defined socklen? :-)  */
    if (bind(raw_socket, (struct sockaddr*) &sockstr, socklen) == -1) {
        perror("bind");
        retval = 1; /* '1' means "Error" */
        return;
        // goto _go_close_socket;
    }


                     char responseBuffer[PCKT_LEN];

    // The size of the headers

    // struct ip *ip = (struct ip *) responseBuffer;
    struct tcp *tcp = (struct tcp *) (responseBuffer);
    struct sockaddr_in sin, din;

    int one = 1;
    const int *val = &one;

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


    tcp->dport = htons(SERVER_PORT);
    printf("Dport hex: %x\n", tcp->dport);

    // uint32_t isn = htonl((uint32_t) ntohs(tcp_hdr->sport));

    tcp->seq = 0; // this can just be a random value so should

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
    tcp->csum = 0; // csumfin(cs);

                

                // printf("INCOMING SEQUENCE NUMBER %u, INCOMING LEN %u, added we get %u\n", ntohl(tcp_hdr->seq), ntohl(ip->len), ntohl(tcp_hdr->seq) + ntohl(ip->len));
    
    tcp->ack = htonl(0);
 
    tcp->flags = TH_SYN | TH_ACK;

    // 6000 in mongoose
    tcp->win = htons(32767);
    tcp->off = (uint8_t) (sizeof(*tcp) / 4 << 4); // data offset? 

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = inet_addr(ADDR_TO_BIND);
    dest.sin_port = htons(SERVER_PORT);

    if(sendto(raw_socket, responseBuffer, sizeof(responseBuffer), 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        perror("sendto() error");
        exit(-1);
    } else 
        printf("sendto ok");
    fflush(stdout);
        // printf("Count #%u - sendto() is OK\n", count);


    printf("WAITNG FOR A SYNACK\n");
    for (;;) {
        if ((msglen = recvfrom(raw_socket, msg, 65536 , 0 , NULL, NULL)) < 0) {
            perror("recv");
            retval = 1;
            // goto _go_close_socket;
        }
    
        struct tcp *tcp_msg = (struct tcp*) msg;

        if (tcp_msg->flags & (TH_SYN | TH_ACK)) {
            printf("RECEIVED A SYN-ACK, WILL SEND AN ACK");
        }
    }

    



    return;


   
    // for (;;) {
        if ((msglen = recvfrom(raw_socket, msg, 65536 , 0 , NULL, NULL))) {
            perror("recv");
            retval = 1;
            // goto _go_close_socket;
        }

        struct ip* ip_hdr = msg;
        struct tcp* tcp_hdr = msg + sizeof(struct ip);

        printf("Source ip is %d\n", ntohs(ip_hdr->src));
        printf("Dest ip is %d\n", ntohs(ip_hdr->dst));
        printf("Source port is %d\n", ntohs(tcp_hdr->sport));
        printf("Dest port is %d\n", ntohs(tcp_hdr->dport));

        for (;;) {
            if ((msglen = recvfrom(raw_socket, msg, 65536 , 0 , NULL, NULL))) {
                perror("recv");
                retval = 1;
                // goto _go_close_socket;
            }

            ip_hdr = msg;
            tcp_hdr = msg + sizeof(struct ip);


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

    int one = 1;
    const int *val = &one;

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
    tcp->csum = 0; // csumfin(cs);

                

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

    if(sendto(raw_socket, responseBuffer, sizeof(responseBuffer), 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        perror("sendto() error");
        exit(-1);
    } else 
        printf("sendto ok");
    fflush(stdout);
        // printf("Count #%u - sendto() is OK\n", count);


    printf("WAITNG FOR AN ACK\n");
    for (;;) {
        if ((msglen = recvfrom(raw_socket, msg, 65536 , 0 , NULL, NULL)) < 0) {
            perror("recv");
            retval = 1;
            // goto _go_close_socket;
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

    // }



// _go_close_socket:
//     close(raw_socket);

    return retval;

	return 0; 
}
