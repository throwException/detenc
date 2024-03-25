#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "enc.h"
#include "util.h"
#include "config.h"

void usage()
{
	fprintf(stderr, "usage: detenc enc <keyfile>\n");
	fprintf(stderr, "       detenc dec <keyfile>\n");
}

size_t read_file(char const* filename, char* buffer, size_t length)
{
	FILE* file = fopen(filename, "r");
	if (file == nullptr) return 0;
	size_t count = fread(buffer, 1, length, file);
	fclose(file); 
	return count;
}

bool read_keyfile(char const* filename, ByteRangePtr& buffer)
{
	char text[buffer.size() * 2];
	size_t count = read_file(filename, text, sizeof(text));
	if ((count == (buffer.size() * 2)) &&
	    (ishex(text, count))) {
		parsehex(text, count, buffer.ptr(), buffer.size());
		memset(text, 0, sizeof(text));
		return true;
	} else {
		memset(text, 0, sizeof(text));
		return false;
	}
}

int main (int argc, char *argv[])
{
	if (argc < 5) {
		usage();
		return -1;
	}

	StaticBuffer<KEY_SIZE> key { };
	ByteRangePtr keyptr(key);
	if (!read_keyfile(argv[2], keyptr)) {
		fprintf(stderr, "cannot read hex bytes from key file\n");
		return -1;
	}
	ConstByteRangePtr ckey(key);

	if (strcmp(argv[1], "enc") == 0) {
		Enc* enc = new Enc();
		int result = enc->run(ckey, true, argv[3], argv[4]);
		delete enc;
		return result;
	} else if (strcmp(argv[1], "dec") == 0) {
		Enc* enc = new Enc();
		int result = enc->run(ckey, false, argv[3], argv[4]);
		delete enc;
		return result;
	} else {
		usage();
		return -1;
	}
}
