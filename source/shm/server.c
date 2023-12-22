#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <netinet/ip.h>

#define BUFSIZE 2000

int tun_alloc(char *dev) {
    struct ifreq ifr;
    int fd, err;

    if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
        perror("Opening /dev/net/tun");
        exit(1);
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    if (*dev) {
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    }

    if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
        perror("ioctl(TUNSETIFF)");
        close(fd);
        exit(1);
    }

    strcpy(dev, ifr.ifr_name);
    return fd;
}

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

int main() {
    char tun_name[IFNAMSIZ];
    int tun_fd;

	strcpy(tun_name, "tun1");
    tun_fd = tun_alloc(tun_name);

    // Assume tun0 and tun1 exist
    // system("ip link set dev tun0 up");
    // system("ip link set dev tun1 up");

    // iptables rules (unchanged)

    while (1) {
        char buf[BUFSIZE];
        ssize_t len;

        // Create an IP packet in the buffer
        create_ip_packet(buf, "172.19.32.1", "172.19.16.1");

        // Write to tun1
        write(tun_fd, buf, sizeof(struct iphdr));

        // You may want to modify, process, or inspect the packet as needed

        // Read from tun0
        len = read(tun_fd, buf, sizeof(buf));

        // Process or inspect the received packet

        // Write to tun1
        write(tun_fd, buf, len);
    }

    // Cleanup (unchanged)

    close(tun_fd);

    return 0;
}
