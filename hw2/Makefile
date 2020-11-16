LIBINCLUDE = -ltrace -lncurses -lm
LIBDIR = ../lib/massdal

Finn_MultiStage_Filter: Finn_MultiStage_Filter.c
	gcc  -Wall -g -o Finn_MultiStage_Filter Finn_MultiStage_Filter.c $(LIBDIR)/prng.c $(LIBINCLUDE) 



clean:
	rm -f mplscount Finn_MultiStage_Filter
	
