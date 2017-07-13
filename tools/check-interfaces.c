#include <rte_ethdev.h>
#include <stdlib.h>
#include <stdio.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <string.h>

int main() {
	int cpu = 24;
	int channels = 4;
	int num_queues = 4;
	int eths_num = 0;
	
	
	uint32_t cpumask = 0;
	for (int ret = 0; ret < cpu; ret++) {
		cpumask |= (1 << ret);
	}
	char cpumaskbuf[10];
	sprintf(cpumaskbuf, "%X", cpumask);

	char mem_channels[5];
	sprintf(mem_channels, "%d", channels);
	
	char *argv[] = {"", "-c", cpumaskbuf, "-n", mem_channels,
						 "--proc-type=auto", ""};

	int ret = rte_eal_init(6, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL args\n");
	int num_devices = rte_eth_dev_count();

	printf("Number of devices: %d\n", num_devices);
	rte_exit(EXIT_SUCCESS, "Complete\n");
}
