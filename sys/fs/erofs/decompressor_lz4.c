/* SPDX-License-Identifier: MIT */
/* Contiguous-buffer LZ4 backend for EROFS FreeBSD. */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/endian.h>

#include <fs/erofs/compress.h>

#define EROFS_LZ4_TOKEN_LITERAL_SHIFT 4
#define EROFS_LZ4_TOKEN_MATCH_MASK    0x0f
#define EROFS_LZ4_MAX_RUN	      15
#define EROFS_LZ4_EXT_SENTINEL	      255
#define EROFS_LZ4_MIN_MATCH	      4
#define EROFS_LZ4_OFFSET_BYTES	      2

static int
lz4_finish(const uint8_t *ip, const uint8_t *iend, int partial)
{
	if (partial)
		return (0);
	while (ip < iend) {
		if (*ip++ != 0)
			return (EINTEGRITY);
	}
	return (0);
}

int
z_erofs_lz4_buffer_decompress(const struct z_erofs_decompress_req *rq)
{
	const uint8_t *input;
	uint8_t *output;
	unsigned int token;
	size_t length, copylen;
	size_t offset;
	size_t input_pos, output_pos;

	if (rq == NULL || (rq->inputsize != 0 && rq->in == NULL) ||
	    (rq->outputsize != 0 && rq->out == NULL))
		return (EINTEGRITY);
	if (rq->inputsize == 0)
		return (rq->outputsize == 0 ? 0 : EINTEGRITY);
	/*
	 * A length grows by at most 255 per input byte, so it cannot reach
	 * SIZE_MAX however long the input is.
	 */
	input = rq->in;
	output = rq->out;
	input_pos = 0;
	output_pos = 0;

	while (input_pos < rq->inputsize) {
		token = input[input_pos++];
		length = token >> EROFS_LZ4_TOKEN_LITERAL_SHIFT;
		if (length == EROFS_LZ4_MAX_RUN) {
			unsigned int value;
			do {
				if (input_pos >= rq->inputsize)
					return (EINTEGRITY);
				value = input[input_pos++];
				length += value;
			} while (value == EROFS_LZ4_EXT_SENTINEL);
		}
		if (length > rq->inputsize - input_pos)
			return (EINTEGRITY);
		if (!rq->partial_decoding &&
		    length > rq->outputsize - output_pos)
			return (EINTEGRITY);
		copylen = MIN(length, rq->outputsize - output_pos);
		memcpy(output + output_pos, input + input_pos, copylen);
		input_pos += length;
		output_pos += copylen;
		if (output_pos == rq->outputsize)
			return (lz4_finish(input + input_pos,
			    input + rq->inputsize, rq->partial_decoding));
		if (input_pos >= rq->inputsize)
			break;
		if (EROFS_LZ4_OFFSET_BYTES > rq->inputsize - input_pos)
			return (EINTEGRITY);
		offset = le16dec(input + input_pos);
		input_pos += EROFS_LZ4_OFFSET_BYTES;
		if (offset == 0 || offset > output_pos)
			return (EINTEGRITY);
		length = token & EROFS_LZ4_TOKEN_MATCH_MASK;
		if (length == EROFS_LZ4_MAX_RUN) {
			unsigned int value;
			do {
				if (input_pos >= rq->inputsize)
					return (EINTEGRITY);
				value = input[input_pos++];
				length += value;
			} while (value == EROFS_LZ4_EXT_SENTINEL);
		}
		length += EROFS_LZ4_MIN_MATCH;
		if (!rq->partial_decoding &&
		    length > rq->outputsize - output_pos)
			return (EINTEGRITY);
		copylen = MIN(length, rq->outputsize - output_pos);
		while (copylen-- != 0) {
			output[output_pos] = output[output_pos - offset];
			++output_pos;
		}
		if (output_pos == rq->outputsize)
			return (lz4_finish(input + input_pos,
			    input + rq->inputsize, rq->partial_decoding));
	}
	return (output_pos == rq->outputsize ?
		lz4_finish(input + input_pos, input + rq->inputsize,
		    rq->partial_decoding) :
		EINTEGRITY);
}
