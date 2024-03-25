#pragma once
#include <cstdint>

class BufferException { };

class Buffer
{
	public:
		virtual uint8_t* ptr() = 0;

		virtual size_t size() = 0;
};

template <int N>
class StaticBuffer : public Buffer
{
	private:
		uint8_t _data[N];

	public:
		virtual uint8_t* ptr() override { return _data; }

		virtual size_t size() override { return N; }

		StaticBuffer()
		{
			memset(_data, 0, N);
		}

		StaticBuffer(uint8_t const* data, size_t length)
		{
			if (length > N) {
				throw BufferException();
			}
			memcpy(_data, data, length);
			memset(_data + length, 0, N - length);
		}
};

class ByteRangePtr
{
	private:
		uint8_t* _data;
		size_t _size;

	public:
		uint8_t* ptr() { return _data; }

		size_t size() { return _size; }

		ByteRangePtr(Buffer& buf)
		 : _data(buf.ptr()), _size(buf.size())
		{
		}

		ByteRangePtr(uint8_t* data, size_t size)
		 : _data(data), _size(size)
		{
		}
};

class ConstByteRangePtr
{
	private:
		uint8_t const* _data;
		size_t _size;

	public:
		uint8_t const* ptr() { return _data; }

		size_t size() { return _size; }

		ConstByteRangePtr(Buffer& buf)
		 : _data(buf.ptr()), _size(buf.size())
		{
		}

		ConstByteRangePtr(ByteRangePtr& ptr)
		 : _data(ptr.ptr()), _size(ptr.size())
		{
		}

		ConstByteRangePtr(uint8_t const* data, size_t size)
		 : _data(data), _size(size)
		{
		}
};

