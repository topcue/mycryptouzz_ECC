#include <iostream>
#include <tuple>
#include <cstdint>
#include <stdint.h>
#include <stddef.h>
#include <memory>
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

#define DEBUG 0

using namespace std;
using namespace CryptoPP;

class ED25519_KEYS{
	public:
		ed25519::Signer signer;
		ed25519::Verifier verifier;

		ED25519_KEYS() {
			AutoSeededRandomPool prng;

			FileSource fs1("private.key.bin", true);
			ed25519::Signer signer_;
			signer_.AccessPrivateKey().Load(fs1);

			bool valid = signer_.GetPrivateKey().Validate(prng, 3);
			if (valid == false)
				throw std::runtime_error("Invalid private key");

			FileSource fs2("public.key.bin", true);
			ed25519::Verifier verifier_;
			verifier_.AccessPublicKey().Load(fs2);

			valid = verifier_.GetPublicKey().Validate(prng, 3);
			if (valid == false)
				throw std::runtime_error("Invalid public key");
#if DEBUG
			std::cout << "[*] Keys are valid" << std::endl;
#endif
			signer = signer_;
			verifier = verifier_;
		}
};


void saving_keys_file() {
	AutoSeededRandomPool prng;

	ed25519::Signer signer;
	signer.AccessPrivateKey().GenerateRandom(prng);

	FileSink fs1("private.key.bin");
	signer.GetPrivateKey().Save(fs1);

	ed25519::Verifier verifier(signer);

	FileSink fs2("public.key.bin");
	verifier.GetPublicKey().Save(fs2);

#if DEBUG
	HexEncoder encoder(new FileSink(std::cout));

	std::cout << "[*] Private key : ";
	signer.GetPrivateKey().Save(encoder);
	std::cout << std::endl;

	std::cout << "[*] Public key  : ";
	verifier.GetPublicKey().Save(encoder);
	std::cout << std::endl;
# endif
}


void ED25519_SIGN_VERIFY(ED25519_KEYS* A, uint8_t* Data, size_t Size) {
	bool valid;
	AutoSeededRandomPool prng;

	ed25519::Signer signer = A->signer;
	ed25519::Verifier verifier = A->verifier;

	std::string message;
	std::string signature;
	message.reserve( Size );
	for (int i; i < Size; i++)
		message += std::to_string(i) + ' ';

	StringSource(message, true, new SignerFilter(NullRNG(), signer, new StringSink(signature)));
	StringSource(signature+message, true, new SignatureVerificationFilter(verifier,
				new ArraySink((byte*)&valid, sizeof(valid))));

	if (valid == false)
		throw std::runtime_error("Invalid signature over message");

#if DEBUG
	HexEncoder encoder(new FileSink(std::cout));
	std::cout << "[*] Signature : ";
	StringSource(signature, true, new Redirector(encoder));
	std::cout << std::endl;
	std::cout << "[*] Verified signature over message" << std::endl;
#endif
}

void ED25519_SIGN_VERIFY_with_pipeline(ED25519_KEYS* A, uint8_t* Data, size_t Size) {
	bool valid;
	AutoSeededRandomPool prng;

	ed25519::Signer signer = A->signer;
	ed25519::Verifier verifier = A->verifier;

	std::string message;
	std::string signature;
	message.reserve( Size );
	for (int i; i < Size; i++)
		message += std::to_string(i) + ' ';

	// Determine maximum size, allocate a string with the maximum size
	size_t siglen = signer.MaxSignatureLength();
	signature.resize(siglen);

	// Sign, and trim signature to actual size
	siglen = signer.SignMessage(NullRNG(), (const byte*)&message[0], message.size(),
			(byte*)&signature[0]);
	signature.resize(siglen);

	valid = verifier.VerifyMessage((const byte*)&message[0], message.size(),
			(const byte*)&signature[0], signature.size());

	if (valid == false)
		throw std::runtime_error("Invalid signature over message");
#if DEBUG
	HexEncoder encoder(new FileSink(std::cout));
	std::cout << "[*] Signature : ";
	StringSource(signature, true, new Redirector(encoder));
	std::cout << std::endl;
	std::cout << "[*] Verified signature over message" << std::endl;
#endif
}


void Run(uint8_t *Data, size_t Size) {
	saving_keys_file();
	ED25519_KEYS A;
	ED25519_SIGN_VERIFY(&A, Data, Size);
	ED25519_SIGN_VERIFY_with_pipeline(&A, Data, Size);
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


