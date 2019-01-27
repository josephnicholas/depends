#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>

#include "bitcoin/compat/sanity.h"
#include "bitcoin/random.h"
#include "bitcoin/key.h"
#include "bitcoin/pubkey.h"

#include "bitcoin/init.h"
#include "bitcoin/util.h"
#include "bitcoin/base58.h"
#include "bitcoin/key_io.h"
#include "bitcoin/chainparams.h"
#include "bitcoin/outputtype.h"
#include "bitcoin/utilstrencodings.h"

#include "bitcoin.h"
#include "util.h"

extern "C" {
	// Liboqs
	#include <oqs/oqs.h>
}
#define MESSAGE_LEN 50

//! The actual byte data
std::vector<unsigned char, secure_allocator<unsigned char> > keydata;

// Experimental Variables
static OQS_SIG *qTESLA_I_context_sign = OQS_SIG_new(OQS_SIG_alg_default);
uint8_t *public_key = new uint8_t[qTESLA_I_context_sign->length_public_key]; 
uint8_t *private_key = new uint8_t[qTESLA_I_context_sign->length_public_key];
uint8_t *message = new uint8_t[MESSAGE_LEN];
size_t message_len = MESSAGE_LEN;
uint8_t *signature = new uint8_t(qTESLA_I_context_sign->length_signature);
size_t signature_len;
OQS_STATUS rc, ret = OQS_ERROR;

// vch = secret_key
static bool OQS_Check(const unsigned char *vch) {
    return true;
}

static void OQS_MakeNewKey(bool fCompressedIn) {
    do {
        //GetStrongRandBytes(keydata.data(), keydata.size());
        OQS_randombytes(keydata.data(), keydata.size());
    } while (!OQS_Check(keydata.data()));
    //fValid = true;
    //fCompressed = fCompressedIn;
}

// Privkey and Public Key - We just return whatever us called by keypair
static CPrivKey OQS_GetPrivKey() {
    //assert(fValid);
    CPrivKey privkey = CPrivKey(private_key, private_key + qTESLA_I_context_sign->length_secret_key);
    
    //privkey.
    //int ret;
    //size_t privkeylen;
    //privkey.resize(PRIVATE_KEY_SIZE);
    //privkeylen = PRIVATE_KEY_SIZE;
    //ret = ec_privkey_export_der(secp256k1_context_sign, privkey.data(), &privkeylen, begin(), fCompressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED);
    //assert(ret);
    //privkey.resize(privkeylen);
    return privkey;
}

static CPubKey OQS_GetPubKey() {
    //assert(fValid);
    //secp256k1_pubkey pubkey;
    //size_t clen = CPubKey::PUBLIC_KEY_SIZE;
    //CPubKey result;
    //int ret = secp256k1_ec_pubkey_create(secp256k1_context_sign, &pubkey, begin());
    //assert(ret);
    //secp256k1_ec_pubkey_serialize(secp256k1_context_sign, (unsigned char*)result.begin(), &clen, &pubkey, fCompressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED);
    //assert(result.size() == clen);
    //assert(result.IsValid());
    std::vector<unsigned char> vch(public_key, public_key + qTESLA_I_context_sign->length_public_key);
    
    CPubKey result = CPubKey(vch);
    return result;
}

//SigHasLowR

static bool OQS_Sign(const uint256 &hash, std::vector<unsigned char>& vchSig, bool grind, uint32_t test_case) {
    if (!fValid)
        return false;
    vchSig.resize(CPubKey::SIGNATURE_SIZE);
    size_t nSigLen = CPubKey::SIGNATURE_SIZE;
    unsigned char extra_entropy[32] = {0};
    WriteLE32(extra_entropy, test_case);
    secp256k1_ecdsa_signature sig;
    uint32_t counter = 0;
    int ret = secp256k1_ecdsa_sign(secp256k1_context_sign, &sig, hash.begin(), begin(), secp256k1_nonce_function_rfc6979, (!grind && test_case) ? extra_entropy : nullptr);

    // Grind for low R
    while (ret && !SigHasLowR(&sig) && grind) {
        WriteLE32(extra_entropy, ++counter);
        ret = secp256k1_ecdsa_sign(secp256k1_context_sign, &sig, hash.begin(), begin(), secp256k1_nonce_function_rfc6979, extra_entropy);
    }
    assert(ret);
    secp256k1_ecdsa_signature_serialize_der(secp256k1_context_sign, vchSig.data(), &nSigLen, &sig);
    vchSig.resize(nSigLen);
    return true;
}

// Liboqs test
static OQS_STATUS signature_test_correctness (const char *method_name)
{
	char *private_key_str;
	char *public_key_str;

	// Create signature with vallid algorithm
	if (qTESLA_I_context_sign == nullptr) {
		return OQS_SUCCESS;
	}

	printf("++++LIBOQS SIG TEST++++ [%s]\n", qTESLA_I_context_sign->method_name);

	//public_key = new uint8_t[sig->length_public_key];
	//private_key = new uint8_t[sig->length_secret_key];
	//message = new uint8_t[message_len];
	//signature = new uint8_t[signature_len];
    

	if ((public_key == nullptr) || (private_key == nullptr) || (message == nullptr) || (signature == nullptr)) {
		fprintf(stderr, "ERROR: allocation failed\n");
		//goto err;
	}
	
	printf("++++Start SIG TEST++++\n");
	// Create random bytes message.
	//OQS_randombytes(message, message_len);
    OQS_MakeNewKey(true);

	// Generate private_key and public key
	rc = OQS_SIG_keypair(qTESLA_I_context_sign, public_key, private_key);
	if (rc != OQS_SUCCESS) {
		printf("ERROR: key_pair creation error");
		ret = OQS_ERROR;
	}

    // Sign a message with qTesla_I signature sheme
    rc = OQS_SIG_sign(qTESLA_I_context_sign, signature, &signature_len, keydata.data(), keydata.size(), private_key);
    if (rc != OQS_SUCCESS) {
        printf("ERROR: sining error");
        ret = OQS_ERROR;
    }

    rc = OQS_SIG_verify(qTESLA_I_context_sign, keydata.data(), keydata.size(), signature, signature_len, public_key);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: signature verify failed!\n");
		ret = OQS_ERROR;
	}

	printf("++++Private KEYS++++\n");
	bin_to_hex(private_key, qTESLA_I_context_sign->length_secret_key, &private_key_str);
    std::vector<unsigned char> private_key_container = ParseHex(private_key_str);
    std::string base58Key = EncodeBase58(private_key_container.data(), private_key_container.data() + private_key_container.size());
	printf("b58 key size: %d\n", private_key_container.size(), base58Key.size());

    // Key creation(Bitcoin)
    CKey key1  = DecodeSecret(base58Key);

    printf("++++Public KEYS++++\n");
    bin_to_hex(public_key, qTESLA_I_context_sign->length_public_key, &public_key_str);

	printf("PRIVATE_KEY: %s\n", private_key_str);
    printf("\n");
    printf("WIF import key(base58): %s\n", base58Key.c_str());
	printf("\n");
	printf("PUBLIC_KEY: %s\n", public_key_str);

	if (qTESLA_I_context_sign != NULL) {
		OQS_MEM_secure_free(private_key, qTESLA_I_context_sign->length_secret_key);
	}
	OQS_MEM_insecure_free(public_key);
	OQS_MEM_insecure_free(keydata.data());
	OQS_MEM_insecure_free(signature);
	OQS_SIG_free(qTESLA_I_context_sign);

	return ret;
}

int main (int argc, char *argv[])
{
    // Liboqs
	// Use system RNG in this program
	OQS_randombytes_switch_algorithm(OQS_RAND_alg_system);
	signature_test_correctness(OQS_SIG_alg_picnic_L1_FS);

    return 0;
}
