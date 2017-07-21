SSL_INSTALL=/home/utcpdev/openssl/install
MTCP_INSTALL=/home/utcpdev/mtcp/mtcp
DPDK_INSTALL=/home/utcpdev/mtcp/dpdk
MTCP_UTIL=/home/utcpdev/mtcp/util

MTCP_UTIL_OBJ=$(addprefix $(MTCP_UTIL)/,http_parsing.o tdate_parse.o netlib.o)

CC=gcc -g -O0 -Wall -Werror -fgnu89-inline -DMAX_CPUS=32
#CC=gcc -g -DMAX_CPUS=32
DPDK_MACHINE_FLAGS = $(shell cat ${DPDK_INSTALL}/include/cflags.txt)
DPDK_LIB_FLAGS = $(shell cat ${DPDK_INSTALL}/lib/ldflags.txt)

INCL=-I${SSL_INSTALL}/include -I${MTCP_INSTALL}/include -I${MTCP_UTIL}/include -I${DPDK_INSTALL}/include -I./

LIBS=-L${SSL_INSTALL}/lib -l:libssl.a -l:libcrypto.a -Wl,-rpath=${SSL_INSTALL}/lib
#LIBS=-lssl -lcrypto
LIBS+=-ldl -L${MTCP_INSTALL}/lib -L${DPDK_INSTALL}/lib -L${DPDK_INSTALL}/lib -lmtcp -lpthread -lnuma ${DPDK_LIB_FLAGS}

TARGETS = linux-server mtcp-server linux-messenger mtcp-messenger ssl-linux-messenger ssl-mtcp-messenger linux-messenger-client mtcp-messenger-client ssl-linux-messenger ssl-mtcp-messenger ssl-linux-messenger-client ssl-mtcp-messenger-client

all: ${TARGETS}

%.o: %.c
	${CC} -c $^ ${INCL} -o $@

mtcp_ssl_functions.o: ssl_functions.c
	${CC} -c $^ ${INCL} -o $@

linux_ssl_functions.o: ssl_functions.c
	${CC} -c -DUSE_LINUX $^ ${INCL} -o $@

# MTCP SERVER
mtcp-server.o: server.c
	${CC} -c $^ ${INCL} -o $@

mtcp-server: mtcp-server.o hashmap.o linked_list.o mtcp_ssl_functions.o
	${CC} $^ ${LIBS} ${MTCP_UTIL_OBJ} -o $@

# LINUX SERVER
linux-server.o: server.c
	${CC} -c -DUSE_LINUX $^ ${INCL} -o $@

linux-server: linux-server.o hashmap.o linked_list.o linux_ssl_functions.o
	${CC} $^ ${LIBS} ${MTCP_UTIL_OBJ} -o $@


# MTCP MESSENGER SERVER
mtcp-messenger.o: messenger.c
	${CC} -c $^ ${INCL} -o $@

mtcp-messenger: mtcp-messenger.o hashmap.o linked_list.o
	${CC} $^ ${LIBS} ${MTCP_UTIL_OBJ} -o $@


# LINUX MESSENGER SERVER
linux-messenger.o: messenger.c
	${CC} -c -DUSE_LINUX $^ ${INCL} -o $@

linux-messenger: linux-messenger.o hashmap.o linked_list.o
	${CC} $^ ${LIBS} ${MTCP_UTIL_OBJ} -o $@


# SSL+MTCP MESSENGER SERVER
ssl-mtcp-messenger.o: messenger.c
	${CC} -c -DUSE_SSL $^ ${INCL} -o $@

ssl-mtcp-messenger: ssl-mtcp-messenger.o hashmap.o linked_list.o mtcp_ssl_functions.o
	${CC} $^ ${LIBS} ${MTCP_UTIL_OBJ} -o $@


# SSL+LINUX MESSENGER SERVER
ssl-linux-messenger.o: messenger.c
	${CC} -c -DUSE_LINUX -DUSE_SSL $^ ${INCL} -o $@

ssl-linux-messenger: ssl-linux-messenger.o hashmap.o linked_list.o linux_ssl_functions.o
	${CC} $^ ${LIBS} ${MTCP_UTIL_OBJ} -o $@


# MTCP MESSENGER CLIENT
mtcp-messenger-client.o: client.c
	${CC} -c $^ ${INCL} -o $@

mtcp-messenger-client: mtcp-messenger-client.o hashmap.o linked_list.o
	${CC} $^ ${LIBS} ${MTCP_UTIL_OBJ} -o $@


# LINUX MESSENGER CLIENT
linux-messenger-client.o: client.c
	${CC} -c -DUSE_LINUX $^ ${INCL} -o $@

linux-messenger-client: linux-messenger-client.o hashmap.o linked_list.o
	${CC} $^ ${LIBS} ${MTCP_UTIL_OBJ} -o $@


# SSL+MTCP MESSENGER CLIENT
ssl-mtcp-messenger-client.o: client.c
	${CC} -c -DUSE_SSL $^ ${INCL} -o $@

ssl-mtcp-messenger-client: ssl-mtcp-messenger-client.o hashmap.o linked_list.o mtcp_ssl_functions.o
	${CC} $^ ${LIBS} ${MTCP_UTIL_OBJ} -o $@


# SSL+LINUX MESSENGER CLIENT
ssl-linux-messenger-client.o: client.c
	${CC} -c -DUSE_LINUX -DUSE_SSL $^ ${INCL} -o $@

ssl-linux-messenger-client: ssl-linux-messenger-client.o hashmap.o linked_list.o linux_ssl_functions.o
	${CC} $^ ${LIBS} ${MTCP_UTIL_OBJ} -o $@



clean:
	rm -f *.o *~ \#*\# ${TARGETS}
