#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <osmocom/core/bits.h>
#include <pcap.h>
#include <arpa/inet.h>

#include "a51.h"
#include "xcch.h"

char errbuf[PCAP_ERRBUF_SIZE];
void* pcap_handle;
pcap_dumper_t *pcap_wr_handle;

int _packet_no;
uint8_t	_key[8];

#define LINE_LEN		16
#define	BURST_SIZE		464
#define	GSM_NORMAL_UM_TYPE	0x1
#define	GSM_BURST_UM_TYPE	0x3

#define DECRYPT_CHECK

static void
burst_print(sbit_t *burst_data) {
	printf("burst data: [ ");
	for (int i = 0; i < BURST_SIZE; i++) {
		printf("%d", ((uint8_t)burst_data[i]) >> 7);
	}
	printf(" ]\n");
}

static void
dispatcher_handler(u_char *dumpfile,
    struct pcap_pkthdr *header, const u_char *pkt_data)
{
	int i, ret, uplink;
	unsigned int *frame_no_ptr;
	unsigned int frame_no;
	uint8_t dest[256 + 48];
	sbit_t burst_data[464];

	memset(dest, 0, sizeof(dest));
	memset(burst_data, 0, sizeof(burst_data));

	_packet_no++;

	if (pkt_data[34] == GSM_BURST_UM_TYPE) {
		// copy header
		memcpy(&dest, pkt_data, 48);

		// copy data
		memcpy(burst_data, &pkt_data[48], 512-48);

		frame_no_ptr = (unsigned int *)&pkt_data[40];
		frame_no = htonl(*frame_no_ptr);

		uplink = pkt_data[36] & 0x40;
#ifdef DEBUG
		printf("%d | %ld:%ld (%u)\n", _packet_no, header->ts.tv_sec, header->ts.tv_usec, header->len);

		printf("frame = %d, ", frame_no);
		if (uplink != 0) {
			printf("uplink\n");
		} else {
			printf("downlink\n");
		}
#endif

		// decrypt encrypted bursts
		if ( (frame_no > 604674) && (frame_no < 604703)) {
			a51_decrypt((unsigned char *)burst_data, (unsigned char *)_key,
			    frame_no, uplink);
			dest[45] = 0xf0; //mark antenna number as having decrypted first
		}

#ifdef DECRYPT_CHECK // to use with b.pcap
		if (frame_no == 604283) {
			printf ("SANITY CHECK:\n");
			printf("	frame = %d, ", frame_no);
			burst_print(burst_data);
		}

		if (frame_no == 604691) {
			printf("	frame = %d, ", frame_no);
			burst_print(burst_data);
		}
#endif

		//decode burst
		ret = xcch_decode(&dest[48], burst_data);

		dest[34] = GSM_NORMAL_UM_TYPE; // Set type to data
		dest[45] |= 0x01; // mark as decoded

		header->caplen = 184/8 + 48;
		header->len = header->caplen;

		pcap_dump(dumpfile, header, &dest);
	} else {
		pcap_dump(dumpfile, header, pkt_data);
	}
}

int main(int argc, char *argv[])
{
	long long int temp = 0x0;

	if (argc != 4) {
		printf("usage: ./a.out <input> <output> <key>");
		return 1;
	}

	pcap_handle = pcap_open_offline(argv[1], &errbuf);

	if (!pcap_handle) {
		printf("PCAP: %s\n", errbuf);
		return 1;
	}

	pcap_wr_handle = pcap_dump_open(pcap_handle, argv[2]);

	if (!pcap_wr_handle) {
		printf("PCAP WR: failed\n");
		return 1;
	}

	if ((temp = strtoull(argv[3], NULL, 0)) == 0) {
		printf("bad key\n");
		return 1;
	}

	printf("using 0x%llx as key\n", temp);

	for (int i = 0, j = 7; i < 8; i++, j--) {
		_key[j] = (temp >> (i * 8)) & 0xff;
	}

	printf("starting ... \n");
	pcap_loop(pcap_handle, 0, dispatcher_handler, (unsigned char *)pcap_wr_handle);
	printf("done!\n");

	pcap_dump_close(pcap_wr_handle);
	pcap_close(pcap_handle);
}
