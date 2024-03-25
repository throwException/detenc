#pragma once
#include <cstdint>
#include "buffer.h"

class Enc
{
	public:
		int run(ConstByteRangePtr& key, bool encrypt, char const* inputfilename, char const* outputfilename);
};

