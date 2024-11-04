/* 
 * $smu-mark$ 
 * $name: sendudp.c$ 
 * $author: Salvatore Sanfilippo <antirez@invece.org>$ 
 * $copyright: Copyright (C) 1999 by Salvatore Sanfilippo$ 
 * $license: This software is under GPL version 2 of license$ 
 * $date: Fri Nov  5 11:55:49 MET 1999$ 
 * $rev: 8$ 
 */ 

/* $Id: send.c,v 1.1.1.1 2003/08/31 17:23:53 antirez Exp $ */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>

#include "hping2.h"
#include "globals.h"

#define MAX_IPS 100000

static struct in_addr ip_src_list[MAX_IPS];
static int ip_src_count = 0;
static int current_ip_src_index = 0;
FILE *ip_src = NULL;

static struct in_addr ip_dst_list[MAX_IPS];
static int ip_dst_count = 0;
static int current_ip_dst_index = 0;
FILE *ip_dst = NULL;

int load_ip_src_list(void)
{
	FILE *file = fopen(ip_src_filename, "r");
	if (!file) {
		perror("fopen");
		return -1;
	}

	char line[INET_ADDRSTRLEN];
	while (fgets(line, sizeof(line), file) && ip_src_count < MAX_IPS) {
		line[strcspn(line, "\n")] = '\0'; // 去除换行符
		if (inet_aton(line, &ip_src_list[ip_src_count]) == 0) {
			fprintf(stderr, "Invalid IP address: %s\n", line);
			continue;
		}
		ip_src_count++;
	}

	fclose(file);
	return 0;
}

int load_ip_dst_list(void)
{
	FILE *file = fopen(ip_dst_filename, "r");
	if (!file) {
		perror("fopen");
		return -1;
	}

	char line[INET_ADDRSTRLEN];
	while (fgets(line, sizeof(line), file) && ip_dst_count < MAX_IPS) {
		line[strcspn(line, "\n")] = '\0'; // 去除换行符
		if (inet_aton(line, &ip_dst_list[ip_dst_count]) == 0) {
			fprintf(stderr, "Invalid IP address: %s\n", line);
			continue;
		}
		ip_dst_count++;
	}

	fclose(file);
	return 0;
}

static void select_next_random_source(void)
{
	unsigned char ra[4];

	ra[0] = hp_rand() & 0xFF;
	ra[1] = hp_rand() & 0xFF;
	ra[2] = hp_rand() & 0xFF;
	ra[3] = hp_rand() & 0xFF;
	memcpy(&local.sin_addr.s_addr, ra, 4);

	if (opt_debug)
		printf("DEBUG: the source address is %u.%u.%u.%u\n",
		    ra[0], ra[1], ra[2], ra[3]);
}

/**
 * @brief Selects the next IP address from the list of source IPs.
 *
 * This function updates the `local.sin_addr` to the next IP address in the `ip_list`.
 * It cycles through the list of IP addresses using a round-robin approach.
 * If the IP list is empty, it prints an error message to `stderr` and returns.
 * If debugging is enabled (`opt_debug`), it prints the selected source address to `stdout`.
 *
 * @note Ensure that the IP list is loaded before calling this function.
 */
static void select_next_list_source(void)
{
    if (ip_src_count == 0) {
        fprintf(stderr, "IP list is empty. Make sure to load the IP list first.\n");
        return;
    }

    local.sin_addr = ip_list[current_ip_src_index];
    current_ip_src_index = (current_ip_src_index + 1) % ip_src_count

    if (opt_debug) {
        printf("DEBUG: the source address is %s\n", inet_ntoa(local.sin_addr));
    }
}


static void select_next_random_dest(void)
{
	unsigned char ra[4];
	char a[4], b[4], c[4], d[4];

	if (sscanf(targetname, "%4[^.].%4[^.].%4[^.].%4[^.]", a, b, c, d) != 4)
	{
		fprintf(stderr,
			"wrong --rand-dest target host, correct examples:\n"
			"  x.x.x.x, 192,168.x.x, 128.x.x.255\n"
			"you typed: %s\n", targetname);
		exit(1);
	}
	a[3] = b[3] = c[3] = d[3] = '\0';

	ra[0] = a[0] == 'x' ? (hp_rand() & 0xFF) : strtoul(a, NULL, 0);
	ra[1] = b[0] == 'x' ? (hp_rand() & 0xFF) : strtoul(b, NULL, 0);
	ra[2] = c[0] == 'x' ? (hp_rand() & 0xFF) : strtoul(c, NULL, 0);
	ra[3] = d[0] == 'x' ? (hp_rand() & 0xFF) : strtoul(d, NULL, 0);
	memcpy(&remote.sin_addr.s_addr, ra, 4);

	if (opt_debug) {
		printf("DEBUG: the dest address is %u.%u.%u.%u\n",
				ra[0], ra[1], ra[2], ra[3]);
	}
}

/**
 * @brief Selects the next destination IP address from the list.
 *
 * This function updates the global variable `local.sin_addr` to the next IP address
 * in the `ip_list`. It also increments the `current_ip_index` to point to the next
 * IP address in the list, wrapping around to the beginning if necessary.
 *
 * If the IP list is empty (`ip_count` is 0), an error message is printed to `stderr`
 * and the function returns without making any changes.
 *
 * If the `opt_debug` flag is set, the function prints the selected IP address to `stdout`
 * for debugging purposes.
 *
 * @note Ensure that the IP list is loaded before calling this function.
 */
static void select_next_list_dest(void)
{
    if (ip_dst_count == 0) {
        fprintf(stderr, "IP list is empty. Make sure to load the IP list first.\n");
        return;
    }

    local.sin_addr = ip_list[current_ip_dst_index];
    current_ip_dst_index = (current_ip_dst_index + 1) % ip_dst_count;

    if (opt_debug) {
        printf("DEBUG: the source address is %s\n", inet_ntoa(local.sin_addr));
    }
}

/* The signal handler for SIGALRM will send the packets */
void send_packet (int signal_id)
{
	int errno_save = errno;

	if (opt_rand_dest)
		select_next_random_dest();
	else if (opt_list_dest)
		select_next_list_dest();

	if (opt_rand_source)
		select_next_random_source();
	else if (opt_list_source)
		select_next_list_source();

	if (opt_rawipmode)	send_rawip();
	else if (opt_icmpmode)	send_icmp();
	else if (opt_udpmode)	send_udp();
	else			send_tcp();

	sent_pkt++;
	Signal(SIGALRM, send_packet);

	if (count != -1 && count == sent_pkt) { /* count reached? */
		Signal(SIGALRM, print_statistics);
		alarm(COUNTREACHED_TIMEOUT);
	} else if (!opt_listenmode) {
		if (opt_waitinusec == FALSE)
			alarm(sending_wait);
		else
			setitimer(ITIMER_REAL, &usec_delay, NULL);
	}
	errno = errno_save;
}
