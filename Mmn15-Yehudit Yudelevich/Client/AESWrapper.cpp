#include "AESWrapper.h"
#include <modes.h>
#include <aes.h>
#include <filters.h>
#include <stdexcept>
#include <immintrin.h>	


AESWrapper::AESWrapper(const char* key, int length)
{   // Ensure the key length is exactly 32 bytes (256-bit AES).
	if (length != DEFAULT_KEYLENGTH)
		throw std::length_error("key length must be 32 bytes");
    // Copy the key into the internal key buffer.
	memcpy_s(_key, DEFAULT_KEYLENGTH, key, length);
}

AESWrapper::~AESWrapper()
{
}

std::string AESWrapper::encrypt(const char* plain, unsigned int length)
{    // Initialization vector (IV) of 16 bytes (AES block size), set to zero.
    CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE] = { 0 };  
    // Set up AES encryption in CBC mode
    CryptoPP::AES::Encryption aesEncryption(_key, DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, iv);
    // String to hold the resulting ciphertext.

    std::string cipher;

    // Encrypt the plaintext and apply PKCS7 padding.
    CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink(cipher), CryptoPP::BlockPaddingSchemeDef::PKCS_PADDING);
    stfEncryptor.Put(reinterpret_cast<const CryptoPP::byte*>(plain), length);
    stfEncryptor.MessageEnd();
    // Return the ciphertext.
    return cipher;
}
