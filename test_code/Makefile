SSL_INSTALL=/home/utcpdev/openssl/install
MTCP_INSTALL=/home/utcpdev/mtcp/mtcp
DPDK_INSTALL=/home/utcpdev/mtcp/dpdk
MTCP_UTIL=/home/utcpdev/mtcp/util

MTCP_UTIL_OBJ=$(addprefix $(MTCP_UTIL)/,http_parsing.o tdate_parse.o netlib.o)

CC=gcc -g -O0 -Wall -Werror -fgnu89-inline
#CFLAGS=-Wall -g -lssl -lcrypto
#CFLAGS=-Wall -g -L$HOME/openssl/install/lib -lssl -lcrypto -Wl,-rpath=/home/utcpdev/openssl/install/lib
#CFLAGS=-Wall -g
DPDK_MACHINE_FLAGS = $(shell cat ${DPDK_INSTALL}/include/cflags.txt)
DPDK_LIB_FLAGS = $(shell cat ${DPDK_INSTALL}/lib/ldflags.txt)
INCL=-I${SSL_INSTALL}/include -I${MTCP_INSTALL}/include -I${MTCP_UTIL}/include -I${DPDK_INSTALL}/include

LIBS=-L${SSL_INSTALL}/lib -l:libssl.a -l:libcrypto.a -Wl,-rpath=${SSL_INSTALL}/lib
#LIBS=-lssl -lcrypto
LIBS+=-ldl -L${MTCP_INSTALL}/lib -L${DPDK_INSTALL}/lib -L${DPDK_INSTALL}/lib -lmtcp -lpthread -lnuma ${DPDK_LIB_FLAGS}

TARGETS = linux-server mtcp-server linux-messenger mtcp-messenger ssl-linux-messenger ssl-mtcp-messenger linux-messenger-client mtcp-messenger-client #ssl-linux-messenger ssl-mtcp-messenger

all: ${TARGETS}

%.o: %.c
	${CC} -c $^ ${INCL} -o $@

mtcp-server.o: server.c
	${CC} -c $^ ${INCL} -o $@

mtcp-server: mtcp-server.o hashmap.o linked_list.o
	${CC} $^ ${LIBS} ${MTCP_UTIL_OBJ} -o $@

linux-server.o: server.c
	${CC} -c -DUSE_LINUX $^ ${INCL} -o $@

linux-server: linux-server.o hashmap.o linked_list.o
	${CC} $^ ${LIBS} ${MTCP_UTIL_OBJ} -o $@

mtcp-messenger.o: messenger.c
	${CC} -c $^ ${INCL} -o $@

mtcp-messenger: mtcp-messenger.o hashmap.o linked_list.o
	${CC} $^ ${LIBS} ${MTCP_UTIL_OBJ} -o $@

linux-messenger.o: messenger.c
	${CC} -c -DUSE_LINUX $^ ${INCL} -o $@

linux-messenger: linux-messenger.o hashmap.o linked_list.o
	${CC} $^ ${LIBS} ${MTCP_UTIL_OBJ} -o $@

ssl-linux-messenger.o: messenger.c
	${CC} -c -DUSE_LINUX -DUSE_SSL $^ ${INCL} -o $@

ssl-linux-messenger: ssl-linux-messenger.o hashmap.o linked_list.o
	${CC} $^ ${LIBS} ${MTCP_UTIL_OBJ} -o $@

ssl-mtcp-messenger.o: messenger.c
	${CC} -c -DUSE_SSL $^ ${INCL} -o $@

ssl-mtcp-messenger: ssl-mtcp-messenger.o hashmap.o linked_list.o
	${CC} $^ ${LIBS} ${MTCP_UTIL_OBJ} -o $@

mtcp-messenger-client.o: client.c
	${CC} -c $^ ${INCL} -o $@

mtcp-messenger-client: mtcp-messenger-client.o hashmap.o linked_list.o
	${CC} $^ ${LIBS} ${MTCP_UTIL_OBJ} -o $@

linux-messenger-client.o: client.c
	${CC} -c $^ ${INCL} -o $@

linux-messenger-client: linux-messenger-client.o hashmap.o linked_list.o
	${CC} $^ -DUSE_LINUX ${LIBS} ${MTCP_UTIL_OBJ} -o $@


clean:
	rm -f *.o *~ \#*\# ${TARGETS}
