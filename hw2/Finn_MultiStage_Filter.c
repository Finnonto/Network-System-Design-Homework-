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
#include <stdlib.h>
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
uint16_t i ,j;//for for loop
uint16_t hash_key1 = 0;
uint16_t hash_key2 = 0;
uint16_t hash_key3 = 0;
uint32_t HashCounter1[HashCounterNumber] = {0};
uint32_t HashCounter2[HashCounterNumber] = {0};
uint32_t HashCounter3[HashCounterNumber] = {0};
//top 10 board
unsigned long Top10_Table[10];

long ot; //for timestamp
uint32_t next_report = 0;// for timestamp
uint32_t min;
char str[20];

unsigned int total_pkt_len = 0;//for length
uint64_t count = 0;// for packet number

inline void swap(unsigned long* x,unsigned long* y) {unsigned long t; t = *x; *x=*y; *y=t;}

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

inline uint32_t get_entry_bytes(unsigned long entry)
{
	hash_key1 = hash31(3721,917,ntohl(entry))%HashCounterNumber;
	hash_key2 = hash31(6969,520,ntohl(entry))%HashCounterNumber;
	hash_key3 = hash31(5278,444,ntohl(entry))%HashCounterNumber;
	return Minof3(&HashCounter1[hash_key1],&HashCounter2[hash_key2],&HashCounter3[hash_key3]);
}

inline void bubble_sort(unsigned long *array,uint16_t limit)
{
	for(i=0;i<limit;i--)
	{
		for(j=limit-1;j>i;j--)
		{
			if(get_entry_bytes(array[j])>get_entry_bytes(array[j-1])){swap(&array[j],&array[j-1]);}
		}
	}
}

inline void get_top10entry()
{
	bubble_sort(HH_Table,Table_entry_cnt);
	printf("------------Heavy Hiiters------------\n");
	if(Table_entry_cnt<10)
	{
		for(i=0;i<Table_entry_cnt;i++)
		{
			printf("#%d :  %s  ",i+1, inet_ntop(AF_INET, &HH_Table[i], str, 20));
			min = get_entry_bytes(HH_Table[i]);
			printf("trasmit %d Bytes  ",min);
			printf("consume %03f%% \n",((float)min*100)/total_pkt_len);
		}
	}
	else
	{
		for(i=0;i<10;i++)
		{
			printf("#%d :  %s  ",i+1, inet_ntop(AF_INET, &HH_Table[i], str, 20));
			min = get_entry_bytes(HH_Table[i]);
			printf("trasmit %d Bytes  ",min);
			printf("consume %03f%% \n",((float)min*100)/total_pkt_len);
		}	
	}
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
	struct timeval ts;
	size_t payload_length;
	// get timestamp	
	ts = trace_get_timeval(packet);
	
	if (next_report == 0) {
		next_report = ts.tv_sec + ot;
	}	
	while (ts.tv_sec > next_report) {
		get_top10entry();
		count = 0;
		next_report += ot;
	}
	
	count += 1;	

	//get payload
	payload_length=trace_get_payload_length(packet);

	// get ip source sddress	
	addr_ptr = trace_get_source_address(packet, (struct sockaddr *)&addr);

	// count total packet length 	
	total_pkt_len+=payload_length;

	// apply Multistage Filter to this packet
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
        if (argc < 3) {
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
	
	ot = strtol(argv[2],NULL,10);
	if(ot == 0){
		ot = 1;	
	}

        if (trace_start(trace) == -1) {
                trace_perror(trace,"Starting trace");
                libtrace_cleanup(trace, packet);
                return 1;
        }


        while (trace_read_packet(trace,packet)>0) {
                per_packet(packet);
        }
	
	

        if (trace_is_err(trace)) {
                trace_perror(trace,"Reading packets");
                libtrace_cleanup(trace, packet);
                return 1;
        }

        libtrace_cleanup(trace, packet);
        return 0;
}

