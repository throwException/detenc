#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "enc.h"
#include "config.h"
#include "util.h"

class RunException
{
	private:
		int _retval;
		char const* _message;

	public:
		int retval() const { return _retval; }
		char const* message() const { return _message; }

		RunException(int retval, char const* message)
		 : _retval(retval), _message(message)
		{ }
};

class Cmac
{
	private:
		EVP_MAC* _mac = nullptr;
		EVP_MAC_CTX* _ctx = nullptr;

	public:
		Cmac()
		{
		}

		void init(ConstByteRangePtr& key)
		{
			_mac = EVP_MAC_fetch(NULL, "CMAC", NULL);
			if (_mac == nullptr) {
				throw RunException(1001, "EVP_MAC_fetch failed");
			}

			_ctx = EVP_MAC_CTX_new(_mac);
			if (_mac == nullptr) {
				throw RunException(1002, "EVP_MAC_CTX_new failed");
			}

			OSSL_PARAM params[2];
			params[0] = OSSL_PARAM_construct_utf8_string("cipher", (char*)"AES-256-CBC", 0);
			params[1] = OSSL_PARAM_construct_end();

			if (!EVP_MAC_init(_ctx, key.ptr(), key.size(), params)) {
				throw RunException(1003, "EVP_MAC_init failed");
			}
		}

		void update(ConstByteRangePtr& buffer)
		{
			if (!EVP_MAC_update(_ctx, buffer.ptr(), buffer.size())) {
				throw RunException(1004, "EVP_MAC_update failed");
			}
		}

		size_t finalize(ByteRangePtr& mac)
		{
			size_t length = mac.size();
			if (!EVP_MAC_final(_ctx, mac.ptr(), &length, mac.size())) {
				throw RunException(1005, "CMAC_Final failed");
			}
			return length;
		}

		~Cmac()
		{
			if (_ctx != nullptr) {
				EVP_MAC_CTX_free(_ctx);
				_ctx = nullptr;
			}

			if (_mac != nullptr) {
				EVP_MAC_free(_mac);
				_mac = nullptr;
			}
		}
};

class Cryptor
{
	private:
		EVP_CIPHER* _cipher = nullptr;
		EVP_CIPHER_CTX* _ctx = nullptr;

	public:
		Cryptor()
		{
		}

		void init(ConstByteRangePtr& key, ConstByteRangePtr& iv, bool encrypt)
		{
			_cipher = EVP_CIPHER_fetch(NULL, "AES-256-CTR", NULL);
			if (_cipher == nullptr) {
				throw RunException(2001, "EVP_CIPHER_fetch failed");
			}

			if (EVP_CIPHER_key_length(_cipher) != key.size()) {
				throw RunException(2002, "bad key size");
			}

			if (EVP_CIPHER_iv_length(_cipher) != iv.size()) {
				throw RunException(2003, "bad iv size");
			}

			_ctx = EVP_CIPHER_CTX_new();
			if (_ctx == nullptr) {
				throw RunException(2004, "EVP_CIPHER_CTX_new failed");
			}

			if (!EVP_CipherInit_ex2(_ctx, _cipher, key.ptr(), iv.ptr(), encrypt, nullptr)) {
				throw RunException(2005, "EVP_CipherInit_ex2 failed");
			}
		}

		size_t update(ConstByteRangePtr& input, ByteRangePtr& output)
		{
			int outlen = output.size();
			if (!EVP_CipherUpdate(_ctx, output.ptr(), &outlen, input.ptr(), input.size())) {
				throw RunException(2006, "EVP_CipherUpdate failed");
			}
			return outlen;
		}

		size_t finalize(ByteRangePtr& output)
		{
			int outlen = output.size();
			if (!EVP_EncryptFinal_ex(_ctx, output.ptr(), &outlen)) {
				throw RunException(2006, "EVP_EncryptFinal_ex failed");
			}
			return outlen;
		}

		~Cryptor()
		{
			if (_ctx != nullptr) {
				EVP_CIPHER_CTX_cleanup(_ctx);
				_ctx = nullptr;
			}
			if (_cipher != nullptr) {
				EVP_CIPHER_free(_cipher);
				_cipher = nullptr;
			}
		}
};

class Inputfile
{
	private:
		FILE* _file = nullptr;

	public:
		Inputfile()
		{
		}

		void open(char const* filename)
		{
			if (strcmp(filename, "-") == 0) {
				_file = stdin;
			} else {
				_file = fopen(filename, "r");
				if (_file == nullptr) {
					throw RunException(3001, "fopen for read failed");
				}
			}
		}

		size_t read(ByteRangePtr& buffer)
		{
			size_t bytes = fread(buffer.ptr(), 1, buffer.size(), _file);
			if (ferror(_file)) {
				throw RunException(3002, "fread failed");
			}
			return bytes;
		}

		bool eof()
		{
			return feof(_file);
		}

		void seek(off_t position)
		{
			if (fseek(_file, position, SEEK_SET)) {
				throw RunException(3003, "fseek failed");
			}
		}

		~Inputfile()
		{
			if (_file != nullptr) {
				fclose(_file);
				_file = nullptr;
			}
		}
};

class Outputfile
{
	private:
		FILE* _file = nullptr;

	public:
		Outputfile()
		{
		}

		void open(char const* filename)
		{
			if (strcmp(filename, "-") == 0) {
				_file = stdout;
			} else {
				_file = fopen(filename, "w");
				if (_file == nullptr) {
					throw RunException(4001, "fopen for write failed");
				}
			}
		}

		void write(ConstByteRangePtr& buffer)
		{
			if (fwrite(buffer.ptr(), 1, buffer.size(), _file) != buffer.size()) {
				throw RunException(4002, "fwrite failed");
			}
		}

		~Outputfile()
		{
			if (_file != nullptr) {
				fclose(_file);
				_file = nullptr;
			}
		}
};

int Enc::run(ConstByteRangePtr& key, bool encrypt, char const* inputfilename, char const* outputfilename)
{
	try
	{
		ConstByteRangePtr ivkey { key.ptr(), key.size() / 2 };
		ConstByteRangePtr enckey { key.ptr() + (key.size() / 2), key.size() / 2 };

		Inputfile input { };
		input.open(inputfilename);

		Outputfile output { };
		output.open(outputfilename);

		StaticBuffer<IV_SIZE> iv { };
		if (encrypt) {
			Cmac cmac { };
			cmac.init(ivkey);

			StaticBuffer<BUF_SIZE> buffer { };
			while (!input.eof()) {
				ByteRangePtr inptr(buffer);
				size_t bytes = input.read(inptr);
				ConstByteRangePtr bufptr(buffer.ptr(), bytes);
				cmac.update(bufptr);
			}

			ByteRangePtr macptr(iv);
			size_t macbytes = cmac.finalize(macptr);
			if (macbytes != iv.size()) {
				throw RunException(5001, "iv too short");
			}
			input.seek(0);
			ConstByteRangePtr ivptr(iv);
			output.write(ivptr);
		} else {
			ByteRangePtr ivptr(iv);
			if (input.read(ivptr) != IV_SIZE) {
				throw RunException(5002, "failed to read iv");
			}
		}

		{
			Cryptor cryptor { };
			ConstByteRangePtr ivptr(iv);
			cryptor.init(enckey, ivptr, encrypt);
			StaticBuffer<BUF_SIZE> buffer { };

			while (!input.eof()) {
				ByteRangePtr bufptr(buffer);
				size_t bytes = input.read(bufptr);
				ConstByteRangePtr inputptr(buffer.ptr(), bytes);
				bytes = cryptor.update(inputptr, bufptr);
				ConstByteRangePtr outputptr(buffer.ptr(), bytes);
				output.write(outputptr);
			}
		}
	} catch (RunException rx) {
		fprintf(stderr, "%s\n", rx.message());
		return rx.retval();
	} catch (BufferException bx) {
		fprintf(stderr, "buffer error\n");
		return 5003;
	}

	return 0;
}

