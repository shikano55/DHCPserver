#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <net/ethernet.h>
#include <error.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <resolv.h>
#include <ifaddrs.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netpacket/packet.h>
#include <netinet/tcp.h>
#include <inttypes.h>


/* DHCP packet */
#define EXTEND_FOR_BUGGY_SERVERS 80
#define DHCP_OPTIONS_BUFSIZE    308

/* See RFC 2131 */
struct dhcp_packet {
  uint8_t op;
  uint8_t htype;
  uint8_t hlen;
  uint8_t hops;
  uint32_t xid;
  uint16_t secs;
  uint16_t flags;
  uint32_t ciaddr;
  uint32_t yiaddr;
  uint32_t siaddr_nip;
  uint32_t gateway_nip;
  uint8_t chaddr[16];
  uint8_t sname[64];
  uint8_t file[128];
  uint32_t cookie;
  uint8_t options[DHCP_OPTIONS_BUFSIZE + EXTEND_FOR_BUGGY_SERVERS];
}__attribute__((packed));

struct pseudo_header{
  uint32_t source_address;
  uint32_t dest_address;
  //uint8_t  reserved;
  uint8_t  protocol;
  uint8_t placeholder;
  uint16_t udp_length;
}__attribute__((__packed__));







//Ether Headerの作成---
int set_ethernet_header(void *rep_buf, int rep_size, void *buf, int size, unsigned char *smac){
  struct ether_header *rep_eth;
  struct ether_header *eth;
  rep_eth = (struct ether_header *)rep_buf;
  eth = (struct ether_header *)buf;
  memcpy(&rep_eth->ether_dhost,&eth->ether_shost,ETH_ALEN);
  memcpy(&rep_eth->ether_shost,smac,ETH_ALEN);
  rep_eth->ether_type = eth->ether_type;
  return 0;
}
//----


//チェックサムの計算----
unsigned short csum(unsigned short *ptr,int nbytes) {
  register long sum;
  sum=0;
  while(nbytes>1) {
    sum+=*ptr++;
    nbytes-=2;
  }
  if(nbytes==1) {
    sum += *(u_int8_t *)ptr;
  }
  sum = (sum>>16)+(sum & 0xffff);
  sum = (sum>>16)+(sum & 0xffff);
  return ~sum;
}

//----


//IP Headerの作成----
int set_ip_header(void *rep_buf, struct in_addr *src, struct in_addr *dst){
  struct iphdr *ip;
  ip = (struct iphdr *)(rep_buf + sizeof(struct ether_header));
  ip->version = 4;
  ip->ihl = 5;
  ip->tos = 16;
  ip->tot_len = htons(sizeof(struct iphdr)+sizeof(struct udphdr)+sizeof(struct dhcp_packet));
  ip->id = htons(0);
  ip->frag_off = htons(0);
  ip->ttl = 0x80;
  ip->protocol = IPPROTO_UDP;
  ip->saddr = src->s_addr;
  ip->daddr = dst->s_addr;
  ip->check = 0;
  ip->check = csum ((unsigned short *) (rep_buf+sizeof(struct ether_header)), ip->ihl*4);
  return 0;
}
//----


//UDP Headerの作成----
int set_udp_header(void *rep_buf, int sport, int dport,struct in_addr *src, struct in_addr *dst){
  struct udphdr *udp;
  struct iphdr *ip;
  struct pseudo_header pse;
  udp = (struct udphdr *)(rep_buf + sizeof(struct ether_header)+sizeof(struct iphdr));

  udp->uh_sport = htons(sport);
  udp->uh_dport = htons(dport);
  udp->uh_ulen = htons(sizeof(struct udphdr)+sizeof(struct dhcp_packet));
  udp->uh_sum = 0;

  pse.source_address = src->s_addr;
  pse.dest_address = dst->s_addr;
  pse.placeholder = 0;
  pse.protocol = IPPROTO_UDP;
  pse.udp_length = htons(sizeof(struct udphdr) + sizeof(struct dhcp_packet));
  char *pseudogram;
  int psize = sizeof(struct pseudo_header) + sizeof(struct udphdr) + sizeof(struct dhcp_packet);
  pseudogram = malloc(psize);
  memcpy(pseudogram , (char*) &pse , sizeof (struct pseudo_header));
  memcpy(pseudogram + sizeof(struct pseudo_header) , udp , sizeof(struct udphdr) + sizeof(struct dhcp_packet));
  //udp->uh_sum = csum( (unsigned short*) pseudogram , psize);
  free(pseudogram);
  return 0;
}
//----


//DHCP Packetの作成----
int set_dhcp(void *rep_buf, void *buf,int dhcp_type,struct in_addr *dst, struct in_addr *siaddr, struct in_addr *subnetmask){
  struct dhcp_packet *dhcp, *org_dhcp;
  dhcp = (struct dhcp_packet *)(rep_buf + sizeof(struct ether_header)+sizeof(struct iphdr)+sizeof(struct udphdr));
  org_dhcp = (struct dhcp_packet *)(buf + sizeof(struct ether_header)+sizeof(struct iphdr)+sizeof(struct udphdr));
  int i;
  memcpy(dhcp,org_dhcp,240);
  dhcp->op = 0x02;
  dhcp->ciaddr = (uint32_t)0;
  dhcp->yiaddr = (uint32_t)(dst->s_addr);
  dhcp->siaddr_nip = (uint32_t)(siaddr->s_addr);;
  dhcp->gateway_nip = (uint32_t)0;
  uint8_t option_code[60];
  memset(option_code, 0, sizeof(option_code));
  /***set DHCP Message Type****/
  option_code[0] = 53;
  option_code[1] = 1; 
  option_code[2] = (uint8_t)dhcp_type;
  /***DHCP Server identifier***/
  option_code[3] = 54;
  option_code[4] = 4; 
  memcpy(&option_code[5],&siaddr->s_addr,option_code[4]);
  /*** IP address lease time ***/
  int lease_time = 600;
  unsigned char* cp;
  option_code[9] = 51;
  option_code[10] = 4; 
  cp = (unsigned char *)&lease_time;
  for(i=0;i<4;i++){
    option_code[14-i]=(uint8_t)(*cp++);
  }
  /*** Subnet Mask ***/
  option_code[15] = 1; 
  option_code[16] = 4; 
  memcpy(&option_code[17],&subnetmask->s_addr,option_code[16]);
  /*** Router ***/
  option_code[21] = 3; 
  option_code[22] = 4; 
  memcpy(&option_code[23],&siaddr->s_addr,option_code[22]);
  /*** domain name ***/
  char *domain="example.org"; 
  option_code[27] = 15; 
  option_code[28] = strlen(domain); 
  memcpy(&option_code[29],domain,option_code[28]);
  /**LAST**/
  option_code[29+strlen(domain)]=255;
    
  memcpy(&dhcp->options,&option_code,60);
  return 0;
}
//----



//DHCPのMessage Typeを見つけるための関数、ipV6は無視する
int check_dhcp_message_type(u_char *buf){
  u_char *ptr;
  struct ether_header *eth;
  //struct iphdr *ip;
  struct dhcp_packet *dhcp;
  ptr = buf;
  eth = (struct ether_header *)buf;
  ptr += sizeof(struct ether_header);
  ptr += ((struct iphdr *)ptr)->ihl*4;
  ptr += sizeof(struct udphdr);

  dhcp = (struct dhcp_packet *)ptr;
  
  int k = dhcp->options[2];
  
  //printf("DHCPパケットのoptions[0]:  %d\n",dhcp->options[0]);
  //printf("DHCPパケットのoptions[1]:  %d\n",dhcp->options[1]);
  //printf("DHCPパケットのoptions[2]:  %d\n",k);
  //printf("DHCPパケットのoptions[3]:  %d\n",dhcp->options[3]);
  //printf("DCHPパケットのMessage Typeは　%d",k);
  return k;
}



//static void messagedump(void *, int);
//static void dumpdhcp(void *, int);
//パケットの送信----
int main(){

  int sockfd = 0;
  u_char buf[65535];
  int len = 0;
  //char buf[ETHER_MAX_LEN] = {0};
  sockfd = socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
  
  struct ifreq ifr;
  memset(&ifr,0,sizeof(ifr));
  //strcpy(ifr.ifr_name,"eth0-ss");
  //strcpy(ifr.ifr_name,"eth0-s");
  strcpy(ifr.ifr_name,"enp0s3");
  
  if(ioctl(sockfd,SIOCGIFINDEX, &ifr) < 0){
    perror("ioctl");
    return -1;
  }

  struct sockaddr_ll sa;
  int sockfd_index;
  sockfd_index = ifr.ifr_ifindex;
  sa.sll_family = AF_PACKET;
  sa.sll_protocol = htons(ETH_P_ALL);
  sa.sll_ifindex = sockfd_index;
  if(bind(sockfd,(struct sockaddr *)&sa, sizeof(sa))<0){
    perror("bind");
    close(sockfd);
    return -1;
  }

  struct sockaddr_ll senderinfo;
  socklen_t addrlen;
  
  //メモリーの確保----
  int packetsiz;
  packetsiz = sizeof(struct ether_header)+sizeof(struct ip) + sizeof(struct udphdr)+sizeof(struct dhcp_packet);
  char *rep_buf;
  if( (rep_buf = (char *)malloc(packetsiz)) == NULL){
    perror("malloc");
  }
  memset(rep_buf, 0, packetsiz); //メモリーの中身を0にしてクリアする
  //----

  
  while(1){
    addrlen=sizeof(senderinfo);
    len = recvfrom(sockfd, buf, sizeof(buf), 0,(struct sockaddr *)&senderinfo, &addrlen);
    //if(len < 0 ){
    //  perror("receive error\n");
    //  break;
    //}
 
    //int dhcp_mt = check_dhcp_message_type(buf,sizeof(buf));
    int dhcp_mt = check_dhcp_message_type(buf);
    //printf("dhcp_option %d\n",dhcp_mt);
    
    struct in_addr src ,dst,subnetmask;
    //struct in_addr src ,dst1,dst2,subnetmask;
    
    //inet_aton("192.168.10.1",&src);
    inet_aton("192.168.3.13",&src);
    
    //inet_aton("192.168.10.65",&dst);
    inet_aton("192.168.3.65",&dst);
    
    //inet_aton("0.0.0.0",&dst1);
    //inet_aton("192.168.10.65",&dst2);
    
    inet_aton("255.255.255.0",&subnetmask);
    switch(dhcp_mt){
    case 1: 
      //printf("OFFER\n");
      printf("get DISCOVER\n");
      set_dhcp(rep_buf,buf,2,&dst,&src,&subnetmask);
      break;
    case 3: 
      //printf("ACK\n");
      printf("get REQUEST\n");
      //set_dhcp(rep_buf,buf,5,&dst,&src,&subnetmask);
      set_dhcp(rep_buf,buf,5,&dst,&src,&subnetmask);
      break;
      default: printf("This message is not relevance to dhcp protocol\n");  
      break;
    }
    set_ethernet_header(rep_buf, sizeof(rep_buf), buf, sizeof(buf),ifr.ifr_hwaddr.sa_data);
    int dport=68, sport=67;
    
    set_ip_header(rep_buf, &src,&dst);
    //set_ip_header(rep_buf, &src,&dst1);

    set_udp_header(rep_buf,sport,dport,&src,&dst);
    //messagedump(buf, sizeof(buf));
    //messagedump(rep_buf,sizeof(rep_buf));
    int send_len;
    if(sendto(sockfd, rep_buf, packetsiz, 0, (struct sockaddr*)&senderinfo, sizeof(senderinfo))< 0){
      perror("send sockfd");
      break;
    }
  }

  close(sockfd);
  return 0;
 
  
}
//----
