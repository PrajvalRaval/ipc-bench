#include <arpa/inet.h>
#include <assert.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/in.h>

#include "common/common.h"
#include "common/sockets.h"

int tun_alloc(char* dev, int flags) {
	struct ifreq ifr;
	int fd, err;
	char* clonedev = "/dev/net/tun";

	/* open the clone device */
	if ((fd = open(clonedev, O_RDWR)) < 0) {
		return fd;
	}

	/* preparation of the struct ifr, of type "struct ifreq" */
	memset(&ifr, 0, sizeof(ifr));

	ifr.ifr_flags = flags; /* IFF_TUN or IFF_TAP, plus maybe IFF_NO_PI */

	if (*dev) {
		strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	}

	/* try to create the device */
	if ((err = ioctl(fd, TUNSETIFF, (void*)&ifr)) < 0) {
		close(fd);
		return err;
	}

	strcpy(dev, ifr.ifr_name);
	return fd;
}

void cleanup(char* shared_memory) {
	shmdt(shared_memory);
}

void cleanup_tcp(int descriptor, void* buffer) {
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
    void* buffer = malloc(args->size);

    atomic_char* guard = (atomic_char*)shared_memory;
    atomic_init(guard, 's');
    assert(sizeof(atomic_char) == 1);

    for (; args->count > 0; --args->count) {
        shm_wait(guard);

        // Use struct iphdr to parse the received IP header
        struct iphdr* ip_header = (struct iphdr*) (shared_memory + 1);
        // Access IP header fields as needed (e.g., ip_header->saddr, ip_header->daddr)

        memcpy(buffer, shared_memory + 1 + sizeof(struct iphdr), args->size - sizeof(struct iphdr));
        write(descriptor, buffer, args->size);

        shm_notify(guard);
        shm_wait(guard);

        // Copy payload data to shared memory
        memcpy(shared_memory + 1, buffer, args->size - sizeof(struct iphdr));
        memset(shared_memory + 1 + args->size - sizeof(struct iphdr), 'C', sizeof(struct iphdr)); // Change 'C' as needed

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