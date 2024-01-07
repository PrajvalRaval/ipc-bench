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

#include "common/common.h"
#include "common/sockets.h"
#include "common/tuntcp.h"

int tun_alloc(char *dev, int flags) {

  struct ifreq ifr;
  int fd, err;
  char *clonedev = "/dev/net/tun";

   if( (fd = open(clonedev, O_RDWR)) < 0 ) {
     return fd;
   }

   memset(&ifr, 0, sizeof(ifr));

   ifr.ifr_flags = flags;

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

void cleanup_tcp(int descriptor, void *buffer) {
	close(descriptor);
	free(buffer);
}

void cleanup(int segment_id, char* shared_memory) {
	shmdt(shared_memory);
	shmctl(segment_id, IPC_RMID, NULL);
}

void shm_wait(atomic_char* guard) {
	while (atomic_load(guard) != 's')
		;
}

void shm_notify(atomic_char* guard) {
	atomic_store(guard, 'c');
}

void communicate(int descriptor, char* shared_memory, struct Arguments* args, struct tcp_conn *conn) {
	struct Benchmarks bench;
	int message;
	void* buffer = malloc(args->size);
	atomic_char* guard = (atomic_char*)shared_memory;

	struct tcp tcp;
	struct ipv4 ip;
	// size_t size;

	// Wait for signal from client
	shm_wait(guard);
	setup_benchmarks(&bench);

	for (message = 0; message < args->count; ++message) {
		bench.single_start = now();

		TCP(conn->src_port, conn->dst_port, conn->seq, conn->ack, TCP_SYN, &tcp);
		IPV4(sizeof(tcp), PROTO_TCP, "192.0.3.1", "192.0.2.1", &ip);
		tcp.checksum = tcp_checksum(&ip,&tcp);

		// size = sizeof(ip) + sizeof(tcp);
		// char packet[size];

		memcpy(buffer, &ip, args->size);
		memcpy(buffer + sizeof(ip), &tcp, args->size);

		memset(shared_memory + 1, buffer, args->size);

		shm_notify(guard);
		shm_wait(guard);

		// Read from client
		read(descriptor, buffer, args->size);
		memcpy(buffer, shared_memory + 1, args->size);
		memset(shared_memory + 1, buffer, args->size);

		shm_notify(guard);
		shm_wait(guard);

		benchmark(&bench);
	}

	evaluate(&bench, args);
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
		throw("Error allocating segment");
	}

	shared_memory = (char*)shmat(segment_id, NULL, 0);

	if (shared_memory == (char*)-1) {
		throw("Error attaching segment");
	}

	strcpy(tun_name, "tun0");
  	tunfd = tun_alloc(tun_name, IFF_TUN);

	struct tcp_conn conn;
	TCPConnection(tunfd, "192.0.2.1", "192.0.3.1", 80, &conn);

	communicate(tunfd, shared_memory, &args, &conn);
	cleanup(segment_id, shared_memory);

	return EXIT_SUCCESS;
}