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
	#include "oqs/oqs.h"
}
// Experimental Variables
static OQS_SIG *qTESLA_I_context_sign = OQS_SIG_new(OQS_SIG_alg_default);
// Bitcoin specific functions

/** All alphanumeric characters except for "0", "I", "O", and "l" */
static const char* OQS_pszBase58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
static const int8_t OQS_mapBase58[256] = {
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1, 0, 1, 2, 3, 4, 5, 6,  7, 8,-1,-1,-1,-1,-1,-1,
    -1, 9,10,11,12,13,14,15, 16,-1,17,18,19,20,21,-1,
    22,23,24,25,26,27,28,29, 30,31,32,-1,-1,-1,-1,-1,
    -1,33,34,35,36,37,38,39, 40,41,42,43,-1,44,45,46,
    47,48,49,50,51,52,53,54, 55,56,57,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
};
//! The actual byte data
std::vector<unsigned char, secure_allocator<unsigned char> > keydata;
static OQS_SIG *sig = nullptr;

static bool OQS_Check(const unsigned char *vch) {
    return false;//secp256k1_ec_seckey_verify(secp256k1_context_sign, vch);
}

static void OQS_MakeNewKey(bool fCompressedIn) {
    do {
        //GetStrongRandBytes(keydata.data(), keydata.size());
        OQS_randombytes(keydata.data(), keydata.size());
    } while (!OQS_Check(keydata.data()));
    //fValid = true;
    //fCompressed = fCompressedIn;
}

static bool OQS_DecodeBase58(const char* psz, std::vector<unsigned char>& vch)
{
    // Skip leading spaces.
    while (*psz && isspace(*psz))
        psz++;
    // Skip and count leading '1's.
    int zeroes = 0;
    int length = 0;
    while (*psz == '1') {
        zeroes++;
        psz++;
    }
    // Allocate enough space in big-endian base256 representation.
    int size = strlen(psz) * 733 /1000 + 1; // log(58) / log(256), rounded up.
    std::vector<unsigned char> b256(size);
    // Process the characters.
    static_assert(sizeof(OQS_mapBase58)/sizeof(OQS_mapBase58[0]) == 256, "OQS_mapBase58.size() should be 256"); // guarantee not out of range
    while (*psz && !isspace(*psz)) {
        // Decode base58 character
        int carry = OQS_mapBase58[(uint8_t)*psz];
        if (carry == -1)  // Invalid b58 character
            return false;
        int i = 0;
        for (std::vector<unsigned char>::reverse_iterator it = b256.rbegin(); (carry != 0 || i < length) && (it != b256.rend()); ++it, ++i) {
            carry += 58 * (*it);
            *it = carry % 256;
            carry /= 256;
        }
        assert(carry == 0);
        length = i;
        psz++;
    }
    // Skip trailing spaces.
    while (isspace(*psz))
        psz++;
    if (*psz != 0)
        return false;
    // Skip leading zeroes in b256.
    std::vector<unsigned char>::iterator it = b256.begin() + (size - length);
    while (it != b256.end() && *it == 0)
        it++;
    // Copy result into output vector.
    vch.reserve(zeroes + (b256.end() - it));
    vch.assign(zeroes, 0x00);
    while (it != b256.end())
        vch.push_back(*(it++));
    return true;
}

static OQS_STATUS OQS_GetPubKey()  {
    // poly_mul & poly_add createsPubKey
    OQS_STATUS rc;
    uint8_t public_key[OQS_SIG_qTESLA_I_length_public_key];
	uint8_t secret_key[OQS_SIG_qTESLA_I_length_secret_key];
    
    CPubKey result;

    rc = OQS_SIG_qTESLA_I_keypair(public_key, secret_key);

    return OQS_SUCCESS;
}

static bool OQS_VerifyPubKey(const CPubKey& pubkey) {
    //unsigned char rnd[8];
    //std::string str = "Bitcoin key verification\n";
    //GetRandBytes(rnd, sizeof(rnd));
    //uint256 hash;
    //CHash256().Write((unsigned char*)str.data(), str.size()).Write(rnd, sizeof(rnd)).Finalize(hash.begin());
    //std::vector<unsigned char> vchSig;
    //Sign(hash, vchSig);
    //return pubkey.Verify(hash, vchSig);
    return true;
}

static bool OQS_DecodeBase58Check(const char* psz, std::vector<unsigned char>& vchRet)
{
    if (!DecodeBase58(psz, vchRet) ||
        (vchRet.size() < 4)) {
        vchRet.clear();
        return false;
    }
    // re-calculate the checksum, ensure it matches the included 4-byte checksum
    uint256 hash = Hash(vchRet.begin(), vchRet.end() - 4);
    if (memcmp(&hash, &vchRet[vchRet.size() - 4], 4) != 0) {
        vchRet.clear();
        return false;
    }
    vchRet.resize(vchRet.size() - 4);
    return true;
}

// Liboqs test
static OQS_STATUS signature_test_correctness (const char *method_name)
{
	OQS_SIG *sig = nullptr;
	uint8_t *public_key = nullptr;
	uint8_t *private_key = nullptr;
	uint8_t *message = nullptr;
	size_t message_len = 100;
	uint8_t *signature = nullptr;
	size_t signature_len = 1376;
	OQS_STATUS rc, ret = OQS_ERROR;

	char *private_key_str;
	char *public_key_str;

	// Create signature with vallid algorithm
	sig = OQS_SIG_new(method_name);
	if (sig == nullptr) {
		return OQS_SUCCESS;
	}

	printf("++++LIBOQS SIG TEST++++ [%s]\n", sig->method_name);

	public_key = new uint8_t[sig->length_public_key];
	private_key = new uint8_t[sig->length_secret_key];
	message = new uint8_t[message_len];
	signature = new uint8_t[signature_len];
    

	if ((public_key == nullptr) || (private_key == nullptr) || (message == nullptr) || (signature == nullptr)) {
		fprintf(stderr, "ERROR: allocation failed\n");
		//goto err;
	}
	
	printf("++++Start SIG TEST++++\n");
	// Create random bytes message.
	OQS_randombytes(message, message_len);

	// Generate private_key and public key
	rc = OQS_SIG_keypair(sig, public_key, private_key);
	if (rc != OQS_SUCCESS) {
		printf("ERROR: key_pair creation error");
		ret = OQS_ERROR;
	}

    // Sign a message with qTesla_I signature sheme
    rc = OQS_SIG_sign(sig, signature, &signature_len, message, message_len, private_key);
    if (rc != OQS_SUCCESS) {
        printf("ERROR: sining error");
        ret = OQS_ERROR;
    }

    rc = OQS_SIG_verify(sig, message, message_len, signature, signature_len, public_key);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: signature verify failed!\n");
		ret = OQS_ERROR;
	}

	printf("++++Private KEYS++++\n");
	bin_to_hex(private_key, sig->length_secret_key, &private_key_str);
    std::vector<unsigned char> private_key_container = ParseHex(private_key_str);
    std::string base58Key = EncodeBase58(private_key_container.data(), private_key_container.data() + private_key_container.size());
	printf("b58 key size: %d\n", private_key_container.size(), base58Key.size());

    // Key creation(Bitcoin)
    CKey key1  = DecodeSecret(base58Key);

    printf("++++Public KEYS++++\n");
    bin_to_hex(public_key, sig->length_public_key, &public_key_str);

	printf("PRIVATE_KEY: %s\n", private_key_str);
    printf("\n");
    printf("WIF import key(base58): %s\n", base58Key.c_str());
	printf("\n");
	printf("PUBLIC_KEY: %s\n", public_key_str);

	if (sig != NULL) {
		OQS_MEM_secure_free(private_key, sig->length_secret_key);
	}
	OQS_MEM_insecure_free(public_key);
	OQS_MEM_insecure_free(message);
	OQS_MEM_insecure_free(signature);
	OQS_SIG_free(sig);

	return ret;
}

int main (int argc, char *argv[])
{
    // Liboqs
	// Use system RNG in this program
	OQS_randombytes_switch_algorithm(OQS_RAND_alg_system);
	signature_test_correctness(OQS_SIG_alg_default);

    return 0;
}
