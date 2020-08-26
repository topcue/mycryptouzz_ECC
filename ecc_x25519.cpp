#include <iostream>
#include <tuple>
#include <cstdint>
#include <ctype.h>
#include <stdio.h>
#include <string>
#include <iomanip>
#include <exception>

#include "../cryptopp/xed25519.h"
#include "../cryptopp/cryptlib.h"
#include "../cryptopp/osrng.h"
#include "../cryptopp/files.h"
#include "../cryptopp/hex.h"
#include "../cryptopp/filters.h"

#include "util.h"

#define DEBUG 1

using namespace std;
using namespace CryptoPP;

void saving_keys_file() {
	using namespace CryptoPP;

	AutoSeededRandomPool prng;

	x25519 ecdh(prng);
	FileSink fs("private.key.bin");
	ecdh.Save(fs);
}

void loading_keys() {
	using namespace CryptoPP;

	FileSource fs("private.key.bin", true);
	x25519 ecdh;
	ecdh.Load(fs);

	AutoSeededRandomPool prng;
	bool valid = ecdh.Validate(prng, 3);
	if (valid == false)
		throw std::runtime_error("Invalid private key");
#if DEBUG
	std::cout << "[*] Keys are valid" << std::endl;
#endif
}

void foo() {
	using namespace CryptoPP;

	AutoSeededRandomPool rndA, rndB;
	x25519 ecdhA(rndA), ecdhB(rndB);

	//////////////////////////////////////////////////////////////

	SecByteBlock privA(ecdhA.PrivateKeyLength());
	SecByteBlock pubA(ecdhA.PublicKeyLength());
	ecdhA.GenerateKeyPair(rndA, privA, pubA);

	SecByteBlock privB(ecdhB.PrivateKeyLength());
	SecByteBlock pubB(ecdhB.PublicKeyLength());
	ecdhB.GenerateKeyPair(rndB, privB, pubB);

	//////////////////////////////////////////////////////////////

	SecByteBlock sharedA(ecdhA.AgreedValueLength());
	SecByteBlock sharedB(ecdhB.AgreedValueLength());

	if(ecdhA.AgreedValueLength() != ecdhB.AgreedValueLength())
		throw std::runtime_error("Shared secret size mismatch");

	if(!ecdhA.Agree(sharedA, privA, pubB))
		throw std::runtime_error("Failed to reach shared secret (1)");

	if(!ecdhB.Agree(sharedB, privB, pubA))
		throw std::runtime_error("Failed to reach shared secret (2)");

	size_t len = std::min(ecdhA.AgreedValueLength(), ecdhB.AgreedValueLength());
	if(!len || !VerifyBufsEqual(sharedA.BytePtr(), sharedB.BytePtr(), len))
		throw std::runtime_error("Failed to reach shared secret (3)");

#if DEBUG
	HexEncoder encoder(new FileSink(std::cout));

	std::cout << "Shared secret (A): ";
	StringSource(sharedA, sharedA.size(), true, new Redirector(encoder));
	std::cout << std::endl;

	std::cout << "Shared secret (B): ";
	StringSource(sharedB, sharedB.size(), true, new Redirector(encoder));
	std::cout << std::endl;
#endif
}

void Run(uint8_t *Data, size_t Size) {
	saving_keys_file();
	loading_keys();
	foo();
}


extern "C" int LLVMFuzzerTestOneInput(uint8_t *Data, size_t Size) {

#if DEBUG
	cout << "\n===================================" << endl;
	cout << "[*] Data" << endl;
	hexdump(Data, Size);
#endif

	Run(Data, Size);

	return 0;
}


// EOF


