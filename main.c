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

#define LINE_LEN 16
static void
packet_print(const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	for (int i = 1 + 48; (i < header->caplen + 1 ) ; i++)
	{
		printf("%.2x ", pkt_data[i-1]);
		if ( (i % LINE_LEN) == 0) printf("\n");
	}
}

void dispatcher_handler(u_char *dumpfile,
                        /* const */ struct pcap_pkthdr *header, const u_char *pkt_data)
{
	int i, ret, uplink;
	unsigned int *frame_no_ptr;
	unsigned int frame_no;
	uint8_t dest[256+48];
	sbit_t burst_data[464];
	memset(dest, 0, sizeof(dest));
	memset(burst_data, 0, sizeof(burst_data));

	_packet_no++;

	if (header->caplen == 512) {
		printf("%d | %ld:%ld (%u)\n", _packet_no, header->ts.tv_sec, header->ts.tv_usec, header->len);
		memcpy(&dest, pkt_data, 48);

		//decode burst
		memcpy(burst_data, &pkt_data[48], 512-48);

		//
		// check if the frame number needs to be decrypted
		//
		frame_no_ptr = (unsigned int *)&pkt_data[40];
		frame_no = htonl(*frame_no_ptr);

		// "\xc7\x6b\x76\xa9\xf1\xac\xbd\xcb"
		const uint8_t secret[8] = {0xcb, 0xbd, 0xac, 0xf1, 0xa9, 0x76, 0x6b, 0xc7};
		char *key = malloc(8);
		sprintf(key, "%c%c%c%c%c%c%c%c",
				secret[7],
				secret[6],
				secret[5],
				secret[4],
				secret[3],
				secret[2],
				secret[1],
				secret[0]);

		printf("frame_no = %d\n", frame_no);
		uplink = pkt_data[36] & 0x40;
		if ( (frame_no > 361543) && (frame_no < 361982))
		{
			a51_decrypt((unsigned char *)burst_data, (unsigned char *)key,
			    frame_no, uplink);
			dest[45] = 0xf0; //mark antenna number as having decrypted first
		}

		ret = xcch_decode(&dest[48], burst_data);
		/*
		   printf("DECODE RET=%d\n", ret);

		   for (i = 0; i < 256; i++)
		   {
		   if (dest[i] != 0)
		   printf("%.2x ", dest[i], dest[i]);
		   }
		   printf("\n");
		   */
		dest[34] = 1;
		dest[45] |= 0x01; //antenna number
		header->caplen = 184/8 + 48;
		header->len = header->caplen;
		free(key);

		pcap_dump(dumpfile, header, &dest);
	} else {
		pcap_dump(dumpfile, header, pkt_data);
	}
}

int main(int argc, char *argv[])
{

	if (argc != 3) {
		printf("Need input & output files\n");
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

	pcap_loop(pcap_handle, 0, dispatcher_handler,  (unsigned char *)pcap_wr_handle);

	pcap_dump_close(pcap_wr_handle);
	pcap_close(pcap_handle);
}
