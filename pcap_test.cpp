#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>

#define ETHER_ADDR_LEN 6
#define SIZE_ETHERNET 14
#define ETHERTYPE_IP 0x0800
struct Ether_header{
	u_char Destin_MAC[ETHER_ADDR_LEN];
	u_char Source_MAC[ETHER_ADDR_LEN];
	u_short type;
};

struct IP_header{
	u_char ip_vhl;
	u_char ip_tos;
	u_short ip_len;
	u_short ip_id;
	u_short ip_off;
#define IP_RF 0x8000
#define IP_DF 0x4000
#define IP_MF 0x2000
#define IP_OFFMASK 0x1fff
	u_char ip_ttl;
	u_char ip_p;
	u_short ip_usm;
	struct in_addr ip_src, ip_dst;
};

#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

typedef u_int tcp_seq;

struct TCP_header {
	u_short th_sport;	/* source port */
	u_short th_dport;	/* destination port */
	tcp_seq th_seq;		/* sequence number */
	tcp_seq th_ack;		/* acknowledgement number */
	u_char th_offx2;	/* data offset, rsvd */
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
	u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;		/* window */
	u_short th_sum;		/* checksum */
	u_short th_urp;		/* urgent pointer */
};

struct Ether_header* ethernet;
struct IP_header* ip;
struct TCP_header* tcp; 
u_char* payload; 

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}



void print_Ether_info(){
	printf("---------------Ethernet Information---------------\n");
	printf("Ether Source Mac address       : ");
	for(int i=0; i<ETHER_ADDR_LEN; i++)
		printf("%02x ", (ethernet->Source_MAC)[i]);
	printf("\n"); 
	printf("Ether Destination MAC address  : ");
	for(int i=0; i<ETHER_ADDR_LEN; i++)
		printf("%02x ", (ethernet->Destin_MAC)[i]);
	printf("\n");
	//printf("--------------------------------------------------\n");
}
void print_IP_info(){
	printf("-------------------IP Informationn----------------\n");
        printf("IP Source address              : ");
        printf("%s", inet_ntoa(ip->ip_src));
        printf("\n"); 
        printf("IP Destination address         : ");
        printf("%s", inet_ntoa(ip->ip_dst));
        printf("\n");
        //printf("--------------------------------------------------\n");
}

void print_TCP_info(){
        printf("------------------TCP Informationn----------------\n");
        printf("TCP Source port                : ");
        printf("%d", ntohs(tcp->th_sport));
        printf("\n"); 
        printf("TCP Destination port           : ");
        printf("%d", ntohs(tcp->th_dport));
        printf("\n");
        //printf("--------------------------------------------------\n");
}

void print_payload_info(){
        printf("-----------------Payload Information--------------\n");
	for(int i=0; i<16; i++)
		printf("%2x ", payload[i]);
	printf("\n");
        printf("--------------------------------------------------\n\n\n\n");
}

void print_packet_info(){
	print_Ether_info();
	print_IP_info();
	print_TCP_info();
	print_payload_info();
}

int isIP(){
	if(ntohs(ethernet->type) == ETHERTYPE_IP)
		return 1;
	else return 0;

}
int isTCP(){
	if(ip->ip_p == IPPROTO_TCP)
		return 1;
	else return 0;
}

int save_to_struct(const u_char* packet){
	ethernet = (struct Ether_header*)packet;
	if(isIP())
		ip = (struct IP_header*)(packet + SIZE_ETHERNET);
	else return 0;
	if(isTCP())
		tcp = (struct TCP_header*)(packet + SIZE_ETHERNET + IP_HL(ip)*4);
	else return 0;
	payload = (u_char *)(packet + SIZE_ETHERNET + IP_HL(ip)*4 + TH_OFF(tcp)*4);
	payload[16]='\0';
	return 1;
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
	if(pcap_datalink(handle) == DLT_EN10MB){
		if(save_to_struct(packet))
			print_packet_info();
	}
        //printf("%u bytes captured\n", header->caplen);
    }

    pcap_close(handle);
}
