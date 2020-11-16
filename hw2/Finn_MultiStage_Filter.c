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
#include <ncurses.h>

#define HashCounterNumber 1000
#define threshold  100000
#define HH_Table_len  1000
#define compare(a,b)(a>=b?b:a)
#define swap(x,y) { Heavy_Hitter_Entry t= x ; x =y ;y = t; }

typedef struct _Heavy_Hitter_Entry{
	struct in_addr IP;
	uint16_t hash_key1;
	uint16_t hash_key2;
	uint16_t hash_key3;
	
}Heavy_Hitter_Entry;

typedef struct _win_border_struct {
	chtype 	ls, rs, ts, bs, 
	 	tl, tr, bl, br;
}WIN_BORDER;
 
typedef struct _WIN_struct {

	int startx, starty;
	int height, width;
	WIN_BORDER border;
}WIN;

void init_win_params(WIN *p_win);
void create_box(WIN *win, bool flag);
void clean_win();


void Filter_init();
uint32_t get_entry_bytes(Heavy_Hitter_Entry* entry);
void bubble_sort(Heavy_Hitter_Entry *array,uint16_t limit);
void get_top10entry(Heavy_Hitter_Entry *HH_Table);
void MultistageFilter(struct sockaddr *ip,size_t payload_length);




Heavy_Hitter_Entry HH_Table[HH_Table_len];
uint16_t Table_entry_cnt = 0;
uint16_t hash_key1 ;
uint16_t hash_key2 ;
uint16_t hash_key3 ;
uint32_t HashCounter1[HashCounterNumber] = {0};
uint32_t HashCounter2[HashCounterNumber] = {0};
uint32_t HashCounter3[HashCounterNumber] = {0};


long ot; //for timestamp
uint32_t next_report = 0;// for timestamp
uint64_t first_time = 0;//
uint32_t total_time = 0;
long  percentage;
uint32_t min;
unsigned int total_pkt_len = 0;//for length


WIN win;

void init()
{
	int i;
	for(i=0;i<HashCounterNumber;i++)
	{
		HashCounter1[i] = 0; 
		HashCounter2[i] = 0;
		HashCounter3[i] = 0;
	}
	
	Table_entry_cnt = 0;
	total_pkt_len = 0;
}

void bubble_sort(Heavy_Hitter_Entry *array,uint16_t limit)
{
	uint8_t i,j;
	for(i=0;i<10;i++)
	{
		for(j=limit-1;j>i;j--)
		{
			if(get_entry_bytes(&array[j])>get_entry_bytes(&array[j-1]))
			{
				swap(array[j],array[j-1]);
			}
		}
	}
}


uint32_t get_entry_bytes(Heavy_Hitter_Entry *entry)
{
	hash_key1 = entry->hash_key1;
	hash_key2 = entry->hash_key2;
	hash_key3 = entry->hash_key3;
	return compare(compare(HashCounter1[hash_key1],HashCounter2[hash_key2]) ,HashCounter3[hash_key3]);
}


void get_top10entry(Heavy_Hitter_Entry *HH_Table)
{	
	
	uint16_t i,x, y;

	x = win.startx;
	y = win.starty;
	
	bubble_sort(HH_Table,Table_entry_cnt);
	
	if(Table_entry_cnt<10)
	{	
		clean_win();	
		for(i=0;i<Table_entry_cnt;i++)
		{
			
			min = get_entry_bytes(&HH_Table[i]);
			
			if(((float)min*100)/total_pkt_len < percentage)break;
			else
			{
				mvprintw(y+i+3,x+14,"%s",inet_ntoa(HH_Table[i].IP));
				mvprintw(y+i+3,x+34,"%d",min);	
				mvprintw(y+i+3,x+50,"%.1f",((float)min*100)/total_pkt_len);
			}
			
		}	
		
		usleep(400000);
		refresh();
	}
	else
	{
		clean_win();
		for(i=0;i<10;i++)
		{
			
			min = get_entry_bytes(&HH_Table[i]);
			
			if(((float)min*100)/total_pkt_len < percentage)break;
			else
			{
				mvprintw(y+i+3,x+14,"%s",inet_ntoa(HH_Table[i].IP));
				mvprintw(y+i+3,x+34,"%d",min);	
				mvprintw(y+i+3,x+50,"%.1f",((float)min*100)/total_pkt_len);
			}
			
		}	
		
		usleep(400000);
		refresh();
	}
}



void MultistageFilter(struct sockaddr *ip,size_t payload_length)
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
			
			min = compare(compare(HashCounter1[hash_key1],HashCounter2[hash_key2]) ,HashCounter3[hash_key3]) + payload_length ;			
			if(HashCounter1[hash_key1] <= min){HashCounter1[hash_key1] = min;}else{HashCounter1[hash_key1] += payload_length;} 
			if(HashCounter2[hash_key2] <= min){HashCounter2[hash_key2] = min;}else{HashCounter2[hash_key2] += payload_length;}
			if(HashCounter3[hash_key3] <= min){HashCounter3[hash_key3] = min;}else{HashCounter3[hash_key3] += payload_length;}

			if(HashCounter1[hash_key1] >= threshold && HashCounter2[hash_key2] >= threshold && HashCounter3[hash_key3] >= threshold )
			{
				HH_Table[Table_entry_cnt].IP = source_ip_addr;
				HH_Table[Table_entry_cnt].hash_key1 = hash_key1;
				HH_Table[Table_entry_cnt].hash_key2 = hash_key2;
				HH_Table[Table_entry_cnt].hash_key3 = hash_key3;
				
				Table_entry_cnt++;
			}		
		}
		else
		{
			min = compare(compare(HashCounter1[hash_key1],HashCounter2[hash_key2]) ,HashCounter3[hash_key3]) + payload_length ;			
			if(HashCounter1[hash_key1] <= min){HashCounter1[hash_key1] = min;}else{HashCounter1[hash_key1] += payload_length;} 
			if(HashCounter2[hash_key2] <= min){HashCounter2[hash_key2] = min;}else{HashCounter2[hash_key2] += payload_length;}
			if(HashCounter3[hash_key3] <= min){HashCounter3[hash_key3] = min;}else{HashCounter3[hash_key3] += payload_length;}
		}
		
	}
	
}
//my long dick

void clean_win()
{
	uint16_t i;
	{
		for(i=0;i<10;i++)
		{
			mvprintw(i+3,14,"                ");
			mvprintw(i+3,34,"          ");	
			mvprintw(i+3,50,"          ");
		}	
		
		//refresh();
	}
}

void init_win_params(WIN *p_win)
{
	p_win->height = 13;
	p_win->width = COLS-1;
	p_win->starty = 0;	
	p_win->startx = 0;

	p_win->border.ls = '|';
	p_win->border.rs = '|';
	p_win->border.ts = '-';
	p_win->border.bs = '-';
	p_win->border.tl = '+';
	p_win->border.tr = '+';
	p_win->border.bl = '+';
	p_win->border.br = '+';

}

void create_box(WIN *p_win, bool flag)
{	
	int i, j;
	int x, y, w, h; 

	x = p_win->startx;
	y = p_win->starty;
	w = p_win->width;
	h = p_win->height;

	if(flag == TRUE)
	{	mvaddch(y, x, p_win->border.tl);
		mvaddch(y, x + w, p_win->border.tr);
		mvaddch(y + h, x, p_win->border.bl);
		mvaddch(y + h, x + w, p_win->border.br);
		
		mvprintw(y+1,x+1," top10");
		mvprintw(y+1,x+19,"IP");
		mvprintw(y+1,x+35,"Bytes");
		mvprintw(y+1,x+48,"Comsume(%)");
		mvprintw(1,65,"time(0)");
		for(i=3;i<13;i++)
		{
			mvprintw(y+i,x+1,"#%d",i-2);
		}
		
		mvvline(y + 1, x, p_win->border.ls, h - 1);
		mvvline(y + 1, x+10, p_win->border.ls, h - 1);
		mvvline(y + 1, x+30, p_win->border.ls, h - 1);
		mvvline(y + 1, x+45, p_win->border.ls, h - 1);
		mvvline(y + 1, x+60, p_win->border.ls, h - 1);
		mvvline(y + 1, x + w, p_win->border.rs, h - 1);
		

		mvhline(y, x + 1, p_win->border.ts, w - 1);
		mvhline(y + h, x + 1, p_win->border.bs, w - 1);
		mvhline(y + 2, x + 1, p_win->border.bs, w - 1);

	}
	else
		for(j = y; j <= y + h; ++j)
			for(i = x; i <= x + w; ++i)
				mvaddch(j, i, ' ');
				
	refresh();

}



void per_packet(libtrace_packet_t *packet)
{
	struct sockaddr_storage addr;
	struct sockaddr *addr_ptr;
	struct timeval ts;
	size_t payload_length;
	uint16_t x, y;

	x = win.startx;
	y = win.starty;
		

	//get payload
	payload_length=trace_get_payload_length(packet);

	// get ip source sddress	
	addr_ptr = trace_get_source_address(packet, (struct sockaddr *)&addr);

	// count total packet length 	
	total_pkt_len+=payload_length;

	// apply Multistage Filter to this packet
	MultistageFilter(addr_ptr,payload_length);

	// get timestamp	
	ts = trace_get_timeval(packet);
	

	
	if (next_report == 0 ) 
	{
		next_report = ts.tv_sec + ot;
		first_time = ts.tv_sec;
	}	

	total_time = ts.tv_sec - first_time;

	while (ot != 0 && ts.tv_sec > next_report) 
	{
		mvprintw(y+1,x+65,"time(%d)",next_report-first_time);
		get_top10entry(&HH_Table[0]);
		
		next_report += ot;
		init();
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
        if (argc < 4) {
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
		if(ot < 0){
			ot = 0;	
		}

        if (trace_start(trace) == -1) {
                trace_perror(trace,"Starting trace");
                libtrace_cleanup(trace, packet);
                return 1;
        }
		
		percentage = strtol(argv[3],NULL,10);
		printf("%ld",percentage);
		if (percentage <= 0){
			percentage = 1;
		}
	

		//Board init
		initscr();
		start_color();
		curs_set(0);
		cbreak();
		init_pair(1, COLOR_CYAN, COLOR_BLACK);
		init_win_params(&win);
		attron(COLOR_PAIR(1));
		refresh();
		attroff(COLOR_PAIR(1));
		create_box(&win, TRUE);


        while (trace_read_packet(trace,packet)>0) {
				
                per_packet(packet);
        }
		
		get_top10entry(&HH_Table[0]);
		mvprintw(1,65,"time(%d)",total_time);

        if (trace_is_err(trace)) {
                trace_perror(trace,"Reading packets");
                libtrace_cleanup(trace, packet);
                return 1;
        }

        libtrace_cleanup(trace, packet);
        
	
		while(getch())break;

	endwin();
	return 0;

}


