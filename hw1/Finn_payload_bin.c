///////////////////////////////////////////////////////////////////////////////
// CNSRL
// Department of Electrical Engineering
// Chung-Yuan Christian University
//
// File Name:Finn_payload_bin.c
// Project:
// Author:Finonto
// Date:2020.10.30
// Dependencies:
//
// Description: to count the payload distribution
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

void print_bin(uint32_t *bin);


uint32_t bin[15] = {0};


void print_bin(uint32_t *bin)
{
	int i;
	for(i=0;i<15;i++)
	{
		printf("%d\n",bin[i]);
	}	
}


void per_packet(libtrace_packet_t *packet)
{
	struct sockaddr_storage addr;
	struct sockaddr *addr_ptr;
	size_t payload_length, frame_length;


	payload_length=trace_get_payload_length(packet);
	frame_length=trace_get_framing_length(packet);
	switch(payload_length/100)
	{
		case 0:bin[0]++;break;
		case 1:bin[1]++;break;
		case 2:bin[2]++;break;
		case 3:bin[3]++;break;
		case 4:bin[4]++;break;
		case 5:bin[5]++;break;
		case 6:bin[6]++;break;
		case 7:bin[7]++;break;
		case 8:bin[8]++;break;
		case 9:bin[9]++;break;
		case 10:bin[10]++;break;
		case 11:bin[11]++;break;
		case 12:bin[12]++;break;
		case 13:bin[13]++;break;
		default:bin[14]++;break;
		
	}

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

	print_bin(bin);


        if (trace_is_err(trace)) {
                trace_perror(trace,"Reading packets");
                libtrace_cleanup(trace, packet);
                return 1;
        }

        libtrace_cleanup(trace, packet);
        return 0;
}

