
#include "crypto_auth.h"
#include "randombytes.h"

// FACT constant; uninteresting
size_t
crypto_auth_bytes(void)
{
    return crypto_auth_BYTES;
}

// FACT constant; uninteresting
size_t
crypto_auth_keybytes(void)
{
    return crypto_auth_KEYBYTES;
}

// FACT constant; uninteresting
const char *
crypto_auth_primitive(void)
{
    return crypto_auth_PRIMITIVE;
}

// FACT simple wrapper
int
crypto_auth(unsigned char *out, const unsigned char *in,
            unsigned long long inlen, const unsigned char *k)
{
    return crypto_auth_hmacsha512256(out, in, inlen, k);
}

// FACT simple wrapper
int
crypto_auth_verify(const unsigned char *h, const unsigned char *in,
                   unsigned long long inlen,const unsigned char *k)
{
    return crypto_auth_hmacsha512256_verify(h, in, inlen, k);
}

// FACT
// I don't know if we can do anything with generating randomness/entropy
// seems too hairy for FaCT to handle
// (possible workaround: randomness source as a [vetted!] C extern)
// but otherwise this is just a simple wrapper
void
crypto_auth_keygen(unsigned char k[crypto_auth_KEYBYTES])
{
    randombytes_buf(k, crypto_auth_KEYBYTES);
}
