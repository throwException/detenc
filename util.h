#pragma once
#include <cstdint>

template <typename T>
inline void dump(T const* buffer, size_t length)
{
	for (size_t i = 0; i < length; i++) {
		fprintf(stderr, "%02x", buffer[i]);
	}
	fprintf(stderr, "\n");
}

template <typename T>
inline T min(T a, T b)
{
	return a < b ? a : b;
}

inline bool ishexchar(char c)
{
	return
		((c >= '0') && (c <= '9')) ||
		((c >= 'a') && (c <= 'f')) ||
		((c >= 'A') && (c <= 'F'));
}

inline uint8_t char2hex(char c)
{
	if ((c >= '0') && (c <= '9')) {
		return (uint8_t)c - (uint8_t)'0';
	} else if ((c >= 'a') && (c <= 'f')) {
		return (uint8_t)c - (uint8_t)'a' + 10u;
	} else if ((c >= 'A') && (c <= 'F')) {
		return (uint8_t)c - (uint8_t)'A' + 10u;
	} else {
		return 0u;
	}
}

inline uint8_t twochars2hex(char const* cc)
{
	return (char2hex(cc[0]) << 4) + char2hex(cc[1]);
}

inline bool ishex(char const* text, size_t text_length)
{
	if (text_length % 2 != 0) {
		return false;
	}
	for (size_t i = 0; i < text_length; i++) {
		if (!ishexchar(text[i])) {
			return false;
		}
	}
	return true;
}

inline void parsehex(char const* text, size_t text_length, uint8_t* buffer, size_t buffer_length)
{
	if (text_length % 2 != 0) {
		throw -1;
	}
	size_t byte_count = min(buffer_length, text_length / 2);
	for (size_t i = 0; i < byte_count; i++) {
		buffer[i] = twochars2hex(text + (i * 2));
	}
}

inline void increment(uint8_t* buffer, size_t length)
{
	size_t byte = length - 1;
	while (buffer[byte] == 0xff) {
		buffer[byte] = 0;
		if (byte == 0) {
			byte = length -1;
		} else {
			byte--;
		}
	}
	buffer[byte]++;
}
