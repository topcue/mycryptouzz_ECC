#include <iostream>
#include <tuple>
#include <cstdint>
#include <ctype.h>
#include <stdio.h>
#include <string>
#include <iomanip>
#include <exception>

#include "../cryptopp/oids.h"
#include "../cryptopp/eccrypto.h"
#include "../cryptopp/cryptlib.h"
#include "../cryptopp/osrng.h"
#include "../cryptopp/files.h"
#include "../cryptopp/hex.h"
#include "../cryptopp/filters.h"

#include "util.h"

#define DEBUG 1

using namespace std;
using namespace CryptoPP;
using namespace ASN1;

void Run_ECMQV() {
	OID CURVE = secp256r1();
	AutoSeededRandomPool rng;

	ECMQV < ECP >::Domain mqvA( CURVE ), mqvB( CURVE );

	// Party A, static (long term) key pair
	SecByteBlock sprivA(mqvA.StaticPrivateKeyLength()), spubA(mqvA.StaticPublicKeyLength());
	// Party A, ephemeral (temporary) key pair
	SecByteBlock eprivA(mqvA.EphemeralPrivateKeyLength()), epubA(mqvA.EphemeralPublicKeyLength());

	// Party B, static (long term) key pair
	SecByteBlock sprivB(mqvB.StaticPrivateKeyLength()), spubB(mqvB.StaticPublicKeyLength());
	// Party B, ephemeral (temporary) key pair
	SecByteBlock eprivB(mqvB.EphemeralPrivateKeyLength()), epubB(mqvB.EphemeralPublicKeyLength());

	// Imitate a long term (static) key
	mqvA.GenerateStaticKeyPair(rng, sprivA, spubA);
	// Ephemeral (temporary) key
	mqvA.GenerateEphemeralKeyPair(rng, eprivA, epubA);

	// Imitate a long term (static) key
	mqvB.GenerateStaticKeyPair(rng, sprivB, spubB);
	// Ephemeral (temporary) key
	mqvB.GenerateEphemeralKeyPair(rng, eprivB, epubB);

	if(mqvA.AgreedValueLength() != mqvB.AgreedValueLength())
		throw runtime_error("Shared secret size mismatch");

	SecByteBlock sharedA(mqvA.AgreedValueLength()), sharedB(mqvB.AgreedValueLength());

	if(!mqvA.Agree(sharedA, sprivA, eprivA, spubB, epubB))
		throw runtime_error("Failed to reach shared secret (A)");

	if(!mqvB.Agree(sharedB, sprivB, eprivB, spubA, epubA))
		throw runtime_error("Failed to reach shared secret (B)");

	Integer ssa, ssb;

	ssa.Decode(sharedA.BytePtr(), sharedA.SizeInBytes());

	ssb.Decode(sharedB.BytePtr(), sharedB.SizeInBytes());

	if(ssa != ssb)
		throw runtime_error("Failed to reach shared secret (C)");

#if DEBUG
	cout << "[*] (A) : " << std::hex << ssa << endl;
	cout << "[*] (B) : " << std::hex << ssb << endl;
	cout << "[*] Agreed to shared secret" << endl;
#endif
}

void Run(uint8_t *Data, size_t Size) {
	Run_ECMQV();
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


