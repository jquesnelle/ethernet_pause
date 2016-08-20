#include <stdio.h>
#include <stdlib.h>

/* If you are building x64 on Windows with WinPcap change add
 * || defined(_WIN64) to #if defined(WIN32) on line 40 */
#include <pcap/pcap.h>



int main(int argc, char **argv)
{
	pcap_t *fp;
	char* endptr = NULL;
	pcap_if_t *alldevs, *d;
	int SLEEP_TIME_MS = 10;
	long index = -1, num_ifaces = 0;
	char errbuf[PCAP_ERRBUF_SIZE + 1];
	unsigned char PAUSE_FRAME[60] = 
	{ 
		0x01, 0x80, 0xC2, 0x00, 0x00, 0x01, /* Destination MAC: Spanning tree for bridges	*/
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* Source MAC:      Null						*/
		0x88, 0x08,							/* EtherType:       MAC control					*/
		0x00, 0x01,							/* OpCode:			Pause						*/
		0xFF, 0xFF,							/* pause_time:		65535						*/	
											/* 42 bytes of padding							*/
	};

	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Could not enumerate interfaces: %s\n", errbuf);
		return 1;
	}

	if (argc != 2)
	{
		long counter = 0;

		fprintf(stderr, "Please pass interface name, description, or index on the command line\n\n");

		printf("Index\tName Description\n\n");
		for (d = alldevs; d; d = d->next)
			printf("%ld\t%s %s\n", counter++, d->name, d->description);

		return 1;
	}

	index = strtoul(argv[1], &endptr, 10);
	if (!endptr || *endptr != '\0')
		index = -1;

	for (d = alldevs; d; d = d->next, ++num_ifaces)
	{
		if (index == -1 && (strcmp(d->description, argv[1]) == 0 || strcmp(d->name, argv[1]) == 0))
			index = num_ifaces;
	}

	if (index < 0 || index >= num_ifaces)
	{
		fprintf(stderr, "Could not find interface %s\n", argv[1]);
		return 1;
	}

	d = alldevs;
	while (index--)
		d = d->next;

	if ((fp = pcap_open_live(d->name, 65536, 1, 1000, errbuf)) == NULL)
	{
		fprintf(stderr, "Unable to open the interface: %s\n", errbuf);
		return 1;
	}

	memset(PAUSE_FRAME + 18, 0, 42); /* fill padding with 00 */

	while (1)
	{
		if (pcap_sendpacket(fp, PAUSE_FRAME, sizeof(PAUSE_FRAME)) != 0)
		{
			fprintf(stderr, "Error sending frame: %s\n", pcap_geterr(fp));
			break;
		}

#ifdef _WIN32
		Sleep(SLEEP_TIME_MS);
#else
		usleep(SLEEP_TIME_MS * 1000);
#endif
	}

	pcap_close(fp);
	return 0;
}