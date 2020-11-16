LIBINCLUDE = -ltrace
LIBDIR = ../lib/massdal
all: create read time length source gettcp http write filter config header \
	mplstag mplscount yk_sourcedemo
yk_sourcedemo: yk_sourcedemo.c
	gcc -o yk_sourcedemo yk_sourcedemo.c $(LIBINCLUDE)
Finn_payload_bin: Finn_payload_bin.c
	gcc -o Finn_payload_bin Finn_payload_bin.c $(LIBINCLUDE)
Finn_MultiStage_Filter: Finn_MultiStage_Filter.c
	gcc  -Wall -g -o Finn_MultiStage_Filter Finn_MultiStage_Filter.c $(LIBDIR)/prng.c $(LIBINCLUDE) -lm 

create: createdemo.c
	gcc -o createdemo createdemo.c $(LIBINCLUDE)

read: readdemo.c
	gcc -o readdemo readdemo.c $(LIBINCLUDE)
	
time: timedemo.c 
	gcc -o timedemo timedemo.c $(LIBINCLUDE)

length: lengthdemo.c
	gcc -o lengthdemo lengthdemo.c $(LIBINCLUDE)

source: sourcedemo.c
	gcc -o sourcedemo sourcedemo.c $(LIBINCLUDE)

gettcp: gettcpdemo.c
	gcc -o gettcpdemo gettcpdemo.c $(LIBINCLUDE)

http: httpcount.c
	gcc -o httpcount httpcount.c $(LIBINCLUDE)

write: writedemo.c
	gcc -o writedemo writedemo.c $(LIBINCLUDE)

filter: filterdemo.c
	gcc -o filterdemo filterdemo.c $(LIBINCLUDE)

config: configdemo.c
	gcc -o configdemo configdemo.c $(LIBINCLUDE)

header: headerdemo.c
	gcc -o headerdemo headerdemo.c $(LIBINCLUDE)

mplscount: mplscount.c
	gcc -o mplscount mplscount.c $(LIBINCLUDE)

mplstag: mplstag.c
	gcc -o mplstag mplstag.c $(LIBINCLUDE)

clean:
	rm -f createdemo readdemo timedemo sourcedemo lengthdemo gettcpdemo
	rm -f httpcount writedemo filterdemo configdemo headerdemo mplstag
	rm -f mplscount yk_sourcedemo Finn_payload_bin Finn_MultiStage_Filter
	
