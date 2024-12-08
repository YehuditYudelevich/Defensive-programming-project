#pragma once

#include <string>



class AESWrapper
{
public:
	static const unsigned int DEFAULT_KEYLENGTH = 32;
private:

	unsigned char _key[DEFAULT_KEYLENGTH];

	AESWrapper(const AESWrapper& aes);
public:

	/**
	 * @brief AESWrapper constructor that initializes the AES encryption key.
	 * @param key The AES key to be used for encryption (must be 32 bytes).
	 * @param length The length of the key.
	 * @throws std::length_error If the key length is not 32 bytes.
	 */
	AESWrapper(const char* key, int size);
	/**
	 * @brief AESWrapper destructor.
	 * Currently empty but provided for completeness in case cleanup is needed later.
	 */
	~AESWrapper();
	/**
	 * @brief Encrypts the input plaintext using AES in CBC mode with PKCS7 padding.
	 * @param plain The plaintext to be encrypted.
	 * @param length The length of the plaintext.
	 * @return std::string The resulting ciphertext after encryption.
	 */
	std::string encrypt(const char* plain, unsigned int length);
}; 
