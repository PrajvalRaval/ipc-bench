#include <assert.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/shm.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <netinet/ip.h>

#include "common/common.h"
#include "common/sockets.h"

void create_ip_packet(char *buffer, const char *source_ip, const char *dest_ip) {
    struct iphdr *ip_header = (struct iphdr *)buffer;

    ip_header->ihl = 5;
    ip_header->version = 4;
    ip_header->tos = 0;
    ip_header->id = htons(54321);
    ip_header->frag_off = 0;
    ip_header->ttl = 64;
    ip_header->protocol = IPPROTO_TCP;
    ip_header->check = 0; // You may want to calculate the correct checksum
    ip_header->saddr = inet_addr(source_ip);
    ip_header->daddr = inet_addr(dest_ip);
}

int tun_alloc(char *dev, int flags) {

  struct ifreq ifr;
  int fd, err;
  char *clonedev = "/dev/net/tun";

   /* open the clone device */
   if( (fd = open(clonedev, O_RDWR)) < 0 ) {
     return fd;
   }

   /* preparation of the struct ifr, of type "struct ifreq" */
   memset(&ifr, 0, sizeof(ifr));

   ifr.ifr_flags = flags;   /* IFF_TUN or IFF_TAP, plus maybe IFF_NO_PI */

   if (*dev) {
     strncpy(ifr.ifr_name, dev, IFNAMSIZ);
   }

   /* try to create the device */
   if( (err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0 ) {
     close(fd);
     return err;
   }

  strcpy(dev, ifr.ifr_name);
  return fd;
}

void cleanup(char* shared_memory) {
	shmdt(shared_memory);
}

void cleanup_tcp(int descriptor, void *buffer) {
	close(descriptor);
	free(buffer);
}

void shm_wait(atomic_char* guard) {
	while (atomic_load(guard) != 'c')
		;
}

void shm_notify(atomic_char* guard) {
	atomic_store(guard, 's');
}

void communicate(int descriptor, char* shared_memory, struct Arguments* args) {
	// Buffer into which to read data
	// void* buffer = malloc(args->size);
	char buffer[args->size];
	create_ip_packet(buffer, "172.19.32.1", "172.19.16.1");
	// create_ip_packet(buffer, "172.19.32.1", "172.19.16.1");

	atomic_char* guard = (atomic_char*)shared_memory;
	atomic_init(guard, 's');
	assert(sizeof(atomic_char) == 1);

	for (; args->count > 0; --args->count) {
		shm_wait(guard);
		// memcpy(buffer, shared_memory + 1, args->size);
		// read(descriptor, buffer, sizeof(buffer));
		write(descriptor, buffer, sizeof(buffer));

		shm_notify(guard);
		shm_wait(guard);

		// memcpy(buffer, shared_memory + 1, args->size);
		read(descriptor, buffer, sizeof(buffer));

		shm_notify(guard);
	}

	cleanup_tcp(descriptor, buffer);
}

int main(int argc, char* argv[]) {
	int segment_id;
	char* shared_memory;
	int tunfd;
    char tun_name[IFNAMSIZ];

	key_t segment_key;

	struct Arguments args;
	parse_arguments(&args, argc, argv);

	segment_key = generate_key("shm");
	segment_id = shmget(segment_key, 1 + args.size, IPC_CREAT | 0666);

	if (segment_id < 0) {
		throw("Could not get segment");
	}

	shared_memory = (char*)shmat(segment_id, NULL, 0);

	if (shared_memory < (char*)0) {
		throw("Could not attach segment");
	}

	strcpy(tun_name, "tun1");
  	tunfd = tun_alloc(tun_name, IFF_TUN);

	communicate(tunfd, shared_memory, &args);

	cleanup(shared_memory);

	return EXIT_SUCCESS;
}