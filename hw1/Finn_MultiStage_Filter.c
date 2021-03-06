///////////////////////////////////////////////////////////////////////////////
// CNSRL
// Department of Electrical Engineering
// Chung-Yuan Christian University
//
// File Name:Finn_MultiStage_Filter.c
// Project:
// Author:Finonto
// Date:2020.10.30
// Dependencies:
//
// Description: to fine the heavy hitter by MultiStage Filter
//
//
// Copyright notice:  Copyright (C)2020 CNSRL CYCU
// Change history:
//
///////////////////////////////////////////////////////////////////////////////

/* Libtrace program designed to demonstrate the use of the trace_get_source_*
 * shortcut functions. 
 *
 * This code also contains examples of sockaddr manipulation.
 */
#include "libtrace.h"
#include <stdio.h>
#include <inttypes.h>
#include <assert.h>
#include <getopt.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
//#include "prng.h"
#include "../lib/massdal/prng.h"
#define HashCounterNumber 1000
uint32_t threshold = 1000000;
unsigned long HH_Table[1000];
uint16_t Table_entry_cnt = 0;
uint16_t i ;
uint16_t hash_key1 = 0;
uint16_t hash_key2 = 0;
uint16_t hash_key3 = 0;
uint32_t min;
char str[20];
uint32_t HashCounter1[HashCounterNumber] = {0};
uint32_t HashCounter2[HashCounterNumber] = {0};
uint32_t HashCounter3[HashCounterNumber] = {0};
unsigned int total_pkt_len = 0;

inline uint32_t Minof3(uint32_t *a,uint32_t *b,uint32_t *c)
{
	uint32_t min = 0;
	min = *a;
	if (*b<*a)
	{
		min=*b;
		if (*c<*b){min=*c;}
	}
	if (*c<*a){min=*c;}

	return min;
}


inline void MultistageFilter(struct sockaddr *ip,size_t payload_length)
{
	
	
	struct in_addr source_ip_addr;//yk
	

	if (ip->sa_family == AF_INET) 
	{
		
		struct sockaddr_in *v4 = (struct sockaddr_in *)ip;
		source_ip_addr=v4->sin_addr;
		hash_key1 = hash31(3721,917,ntohl(source_ip_addr.s_addr))%HashCounterNumber;
		hash_key2 = hash31(6969,520,ntohl(source_ip_addr.s_addr))%HashCounterNumber;
		hash_key3 = hash31(5278,444,ntohl(source_ip_addr.s_addr))%HashCounterNumber;
		
		
		
		if(HashCounter1[hash_key1] <= threshold || HashCounter2[hash_key2] <= threshold || HashCounter3[hash_key3] <= threshold )
		{	
			
			min = Minof3(&HashCounter1[hash_key1],&HashCounter2[hash_key2],&HashCounter3[hash_key3]) + payload_length ;			
			if(HashCounter1[hash_key1] <= min){HashCounter1[hash_key1] = min;}else{HashCounter1[hash_key1] += payload_length;} 
			if(HashCounter2[hash_key2] <= min){HashCounter2[hash_key2] = min;}else{HashCounter2[hash_key2] += payload_length;}
			if(HashCounter3[hash_key3] <= min){HashCounter3[hash_key3] = min;}else{HashCounter3[hash_key3] += payload_length;}

			if(HashCounter1[hash_key1] >= threshold && HashCounter2[hash_key2] >= threshold && HashCounter3[hash_key3] >= threshold )
			{
				HH_Table[Table_entry_cnt] = source_ip_addr.s_addr ;
				Table_entry_cnt++;
			}		
		}
		else
		{
			min = Minof3(&HashCounter1[hash_key1],&HashCounter2[hash_key2],&HashCounter3[hash_key3]) + payload_length ;			
			if(HashCounter1[hash_key1] <= min){HashCounter1[hash_key1] = min;}else{HashCounter1[hash_key1] += payload_length;} 
			if(HashCounter2[hash_key2] <= min){HashCounter2[hash_key2] = min;}else{HashCounter2[hash_key2] += payload_length;}
			if(HashCounter3[hash_key3] <= min){HashCounter3[hash_key3] = min;}else{HashCounter3[hash_key3] += payload_length;}
		}
		
	}
	
}






void per_packet(libtrace_packet_t *packet)
{
	struct sockaddr_storage addr;
	struct sockaddr *addr_ptr;
	size_t payload_length;

	payload_length=trace_get_payload_length(packet);
	addr_ptr = trace_get_source_address(packet, (struct sockaddr *)&addr);
	total_pkt_len+=payload_length;
	MultistageFilter(addr_ptr,payload_length);
	
}


void libtrace_cleanup(libtrace_t *trace, libtrace_packet_t *packet) {

        /* It's very important to ensure that we aren't trying to destroy
         * a NULL structure, so each of the destroy calls will only occur
         * if the structure exists */
        if (trace)
                trace_destroy(trace);

        if (packet)
                trace_destroy_packet(packet);

}



int main(int argc, char *argv[])
{	
	
        /* This is essentially the same main function from readdemo.c */

        libtrace_t *trace = NULL;
        libtrace_packet_t *packet = NULL;
	
	/* Ensure we have at least one argument after the program name */
        if (argc < 2) {
                fprintf(stderr, "Usage: %s inputURI\n", argv[0]);
                return 1;
        }

        packet = trace_create_packet();

        if (packet == NULL) {
                perror("Creating libtrace packet");
                libtrace_cleanup(trace, packet);
                return 1;
        }

        trace = trace_create(argv[1]);

        if (trace_is_err(trace)) {
                trace_perror(trace,"Opening trace file");
                libtrace_cleanup(trace, packet);
                return 1;
        }
	
	
	
        if (trace_start(trace) == -1) {
                trace_perror(trace,"Starting trace");
                libtrace_cleanup(trace, packet);
                return 1;
        }


        while (trace_read_packet(trace,packet)>0) {
                per_packet(packet);
        }

	printf("------------Heavy Hiiters------------\n");
	for(i=0;i<Table_entry_cnt;i++)
	{
		printf("#%d :  %s  ",i, inet_ntop(AF_INET, &HH_Table[i], str, 20));
		hash_key1 = hash31(3721,917,ntohl(HH_Table[i]))%HashCounterNumber;
		hash_key2 = hash31(6969,520,ntohl(HH_Table[i]))%HashCounterNumber;
		hash_key3 = hash31(5278,444,ntohl(HH_Table[i]))%HashCounterNumber;
		min = Minof3(&HashCounter1[hash_key1],&HashCounter2[hash_key2],&HashCounter3[hash_key3]);
		printf("trasmit %d Bytes  ",min);
		printf("consume %03f%% \n",((float)min*100)/total_pkt_len);
	}

        if (trace_is_err(trace)) {
                trace_perror(trace,"Reading packets");
                libtrace_cleanup(trace, packet);
                return 1;
        }

        libtrace_cleanup(trace, packet);
        return 0;
}

