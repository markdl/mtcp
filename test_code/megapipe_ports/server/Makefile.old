# Makefile for server

PSDIR = ../../../../io_engine/io_engine-2.0.38.2
MTCPDIR = ../../../mtcp-io
DPDKDIR = ../../../dpdk

CC = gcc -g -O3
CFLAGS = -m64 -g -O3 -pthread  -march=native -DRTE_MACHINE_CPUFLAG_SSE -DRTE_MACHINE_CPUFLAG_SSE2 -DRTE_MACHINE_CPUFLAG_SSE3 -DRTE_MACHINE_CPUFLAG_SSSE3 -DRTE_MACHINE_CPUFLAG_SSE4_1 -DRTE_MACHINE_CPUFLAG_SSE4_2 -DRTE_MACHINE_CPUFLAG_AES -DRTE_MACHINE_CPUFLAG_PCLMULQDQ -DRTE_MACHINE_CPUFLAG_AVX -DRTE_COMPILE_TIME_CPUFLAGS=RTE_CPUFLAG_SSE,RTE_CPUFLAG_SSE2,RTE_CPUFLAG_SSE3,RTE_CPUFLAG_SSSE3,RTE_CPUFLAG_SSE4_1,RTE_CPUFLAG_SSE4_2,RTE_CPUFLAG_AES,RTE_CPUFLAG_PCLMULQDQ,RTE_CPUFLAG_AVX  -I$(DPDKDIR)/include -include $(DPDKDIR)/include/rte_config.h -O3 -I./include/ -I/home/ajamshed/trunk/tcp/util/include -I$(MTCPDIR)/include -I/home/ajamshed/trunk/io_engine/io_engine-2.0.38.2/include

LDFLAGS = -m64 -g -O3 -pthread  -march=native -DRTE_MACHINE_CPUFLAG_SSE -DRTE_MACHINE_CPUFLAG_SSE2 -DRTE_MACHINE_CPUFLAG_SSE3 -DRTE_MACHINE_CPUFLAG_SSSE3 -DRTE_MACHINE_CPUFLAG_SSE4_1 -DRTE_MACHINE_CPUFLAG_SSE4_2 -DRTE_MACHINE_CPUFLAG_AES -DRTE_MACHINE_CPUFLAG_PCLMULQDQ -DRTE_MACHINE_CPUFLAG_AVX -DRTE_COMPILE_TIME_CPUFLAGS=RTE_CPUFLAG_SSE,RTE_CPUFLAG_SSE2,RTE_CPUFLAG_SSE3,RTE_CPUFLAG_SSSE3,RTE_CPUFLAG_SSE4_1,RTE_CPUFLAG_SSE4_2,RTE_CPUFLAG_AES,RTE_CPUFLAG_PCLMULQDQ,RTE_CPUFLAG_AVX -I$(DPDKDIR)/include -include $(DPDKDIR)/include/rte_config.h -O3 -I./include/ -I/home/ajamshed/trunk/tcp/util/include -I$(MTCPDIR)/include -I/home/ajamshed/trunk/io_engine/io_engine-2.0.38.2/include -include $(DPDKDIR)/include/rte_config.h -Wl,-export-dynamic -L$(DPDKDIR)/lib -L/home/ajamshed/trunk/io_engine/io_engine-2.0.38.2/lib -L$(MTCPDIR)/lib -Wl,-lnuma -Wl,-lmtcp -Wl,-lps -Wl,-lpthread -Wl,-lrt -Wl,-ldl -Wl,/home/ajamshed/trunk/tcp/util/http_parsing.o -Wl,/home/ajamshed/trunk/tcp/util/tdate_parse.o -L$(DPDKDIR)/lib -Wl,--whole-archive -Wl,-lrte_distributor -Wl,-lrte_kni -Wl,-lrte_pipeline -Wl,-lrte_table -Wl,-lrte_port -Wl,-lrte_timer -Wl,-lrte_hash -Wl,-lrte_lpm -Wl,-lrte_power -Wl,-lrte_acl -Wl,-lrte_meter -Wl,-lrte_sched -Wl,-lm -Wl,-lrt -Wl,--start-group -Wl,-lrte_kvargs -Wl,-lrte_mbuf -Wl,-lrte_ip_frag -Wl,-lethdev -Wl,-lrte_malloc -Wl,-lrte_mempool -Wl,-lrte_ring -Wl,-lrte_eal -Wl,-lrte_cmdline -Wl,-lrte_cfgfile -Wl,-lrte_pmd_bond -Wl,-lrte_pmd_vmxnet3_uio -Wl,-lrte_pmd_virtio_uio -Wl,-lrte_pmd_i40e -Wl,-lrte_pmd_ixgbe -Wl,-lrte_pmd_e1000 -Wl,-lrte_pmd_ring -Wl,-lrt -Wl,-lm -Wl,-ldl -Wl,--end-group -Wl,--no-whole-archive

MTCP_FLD = -lmtcp -L$(MTCPDIR)/lib/
MTCP_INC = $(MTCPDIR)/include
MTCPLIB = $(MTCPDIR)/lib/libmtcp.a

PS_FLD = -lps -L$(PSDIR)/lib/
PS_INC = $(PSDIR)/include
PSLIB = $(PSDIR)/lib/libps.a

INC = -I${MTCP_INC} -I${PS_INC}
LIBS = -lnuma -lpthread -lrt
LIB = ${PS_FLD} ${MTCP_FLD}

all: server-mtcp server-linux

server-mtcp: server-mtcp.c server-mtcp.h
	$(CC) $(CFLAGS) $(INC) $(LIBS) $(LIB) -o $@ $< $(MTCPLIB) $(PSLIB) $(LDFLAGS)

server-linux: server-linux.c server-linux.h
	$(CC) $(CFLAGS) $(LDFLAGS)  -o $@ $<

server-linux-ports: server-linux-ports.c server-linux-ports.h
	$(CC) $(CFLAGS) $(LDFLAGS)  -o $@ $<

clean:
	rm -rf server-mtcp server-linux *~
