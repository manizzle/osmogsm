#include <stdio.h>
#include <assert.h>

#include "conv.h"
#include "bits.h"

static const uint8_t conv_xcch_next_output[][2] = {
        { 0, 3 }, { 1, 2 }, { 0, 3 }, { 1, 2 },
        { 3, 0 }, { 2, 1 }, { 3, 0 }, { 2, 1 },
        { 3, 0 }, { 2, 1 }, { 3, 0 }, { 2, 1 },
        { 0, 3 }, { 1, 2 }, { 0, 3 }, { 1, 2 },
};

static const uint8_t conv_xcch_next_state[][2] = {
        {  0,  1 }, {  2,  3 }, {  4,  5 }, {  6,  7 },
        {  8,  9 }, { 10, 11 }, { 12, 13 }, { 14, 15 },
        {  0,  1 }, {  2,  3 }, {  4,  5 }, {  6,  7 },
        {  8,  9 }, { 10, 11 }, { 12, 13 }, { 14, 15 },
};

const struct osmo_conv_code conv_xcch = {
        .N = 2,
        .K = 5,
        .len = 224,
        .next_output = conv_xcch_next_output,
        .next_state  = conv_xcch_next_state,
};


int main(int argc, char *argv[])
{
	unsigned char cB[456];
	unsigned char conv[224];
	unsigned int i;

	memset(cB, 0x00, sizeof cB);
	memset(conv, 0x00, sizeof conv);

	assert(argc == 2);
	assert(strlen(argv[1]) == 456);

	for (i = 0; i < sizeof cB; i++) {
		if (argv[1][i] == '1')
			cB[i] = 0x80;
		else
			cB[i] = 0x00;
	}

	osmo_conv_decode(&conv_xcch, cB, conv);
	for (i = 0; i < sizeof conv; i++)
		printf("%01x", conv[i]);
	printf("\n");
}
