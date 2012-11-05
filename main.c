#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <osmocom/core/bits.h>
#include <pcap.h>
#include <arpa/inet.h>

#include "a51.h"
#include "xcch.h"

// DEFINES
#define LINE_LEN		16
#define	BURST_SIZE		464
#define	GSM_NORMAL_UM_TYPE	0x1
#define	GSM_BURST_UM_TYPE	0x3
#define DECRYPT_CHECK
#define	MAX_DECRYPT_BLOCKS	100

// STRUCTS
typedef struct decrypt_block decrypt_block_t;

struct decrypt_block  {
	decrypt_block_t	*next;
	unsigned int	start_frame;
	unsigned int	end_frame;
	uint8_t		key[8];
};

// GLOBALS
char		errbuf[PCAP_ERRBUF_SIZE];
void*		pcap_handle;
pcap_dumper_t	*pcap_wr_handle;
decrypt_block_t	*_decrypt_block;
int		 _packet_no;

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
		printf("%d | %ld:%ld (%u)\n", _packet_no, header->ts.tv_sec,
		    header->ts.tv_usec, header->len);

		printf("frame = %d, ", frame_no);
		if (uplink != 0) {
			printf("uplink\n");
		} else {
			printf("downlink\n");
		}
#endif

		if (frame_no > _decrypt_block->end_frame) {
			if (_decrypt_block->next != NULL) {
				_decrypt_block = _decrypt_block->next;
			}
		}

		// decrypt encrypted bursts
		if (frame_no > _decrypt_block->start_frame &&
		    frame_no < _decrypt_block->end_frame) {
			a51_decrypt((unsigned char *)burst_data, (unsigned char *)_decrypt_block->key,
			    frame_no, uplink);
			dest[45] = 0xf0; //mark antenna number as decrypted
		}

#ifdef DECRYPT_CHECK // use this with b.pcap
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

static void
parse_decrypt_block_file(FILE* fp, decrypt_block_t **db, size_t *lsize) {
	long long int temp = 0x0;
	char *linebuf, *split;

	if (getline(&linebuf, lsize, fp) != -1) {
		if (*db == NULL) {
			*db = malloc(sizeof (decrypt_block_t));
		}

		printf("Frame block : ");

		split = strtok(linebuf,  " \n\r");
		(*db)->start_frame = strtol(split, NULL, 0);
		printf("start = %ld, ", (*db)->start_frame);

		split = strtok(NULL,  " \n\r");
		(*db)->end_frame = strtol(split, NULL, 0);
		printf("stop = %ld, ", (*db)->end_frame);

		split = strtok(NULL,  " \n\r");
		temp = strtoull(split, NULL, 0);
		printf("key = 0x%llx\n", temp);

		for (int k = 0, j = 7; k < 8; k++, j--) {
			(*db)->key[j] = (temp >> (k * 8)) & 0xff;
		}
		free (linebuf);
		parse_decrypt_block_file(fp, &(*db)->next, lsize);
	}
}

static void
free_decrypt_blocks(decrypt_block_t *db) {
	if (db != NULL) {
		decrypt_block_t	*db_next = db->next;
		free (db);
		free_decrypt_blocks(db_next);
	}
}

int main(int argc, char *argv[])
{
	FILE			*keyfile;
	int			i = 0;
	size_t			lsize = 0;
	decrypt_block_t	*head_decrypt_block;

	if (argc != 4) {
		printf("usage: %s <input file> <output file> <key file>",
		    argv[0]);
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

	keyfile = fopen(argv[3], "r");

	if (!keyfile) {
		printf("Could not read key file %s\n", argv[3]);
		return 1;
	}

	/*
	 * parse the key file for range - key pairs and
	 * stuff those in a global list of structs
	 */
	head_decrypt_block = _decrypt_block = malloc(sizeof (decrypt_block_t));
	parse_decrypt_block_file(keyfile, &_decrypt_block, &lsize);

	fclose(keyfile);

	printf("starting ... \n");
	pcap_loop(pcap_handle, 0, dispatcher_handler, (unsigned char *)pcap_wr_handle);
	printf("done!\n");

	free_decrypt_blocks(head_decrypt_block);

	pcap_dump_close(pcap_wr_handle);
	pcap_close(pcap_handle);
}
