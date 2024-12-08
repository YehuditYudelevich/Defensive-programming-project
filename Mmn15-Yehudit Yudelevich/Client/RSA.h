#pragma once
#include <osrng.h>
#include <rsa.h>
#include <string>
#include <base64.h>
#include <iostream>
#include <fstream>
#include <files.h> 
#include <osrng.h> 




class RSAPrivateWrapper
{
public:
	static const unsigned int BITS = 1024;

private:
	CryptoPP::AutoSeededRandomPool _rng;
	CryptoPP::RSA::PrivateKey _privateKey;
public:
	/**
	 * @brief Default constructor that initializes a new RSA private key.
	 * This constructor generates a new RSA private key using a random number generator.
	 */
	RSAPrivateWrapper();
	/**
	 * @brief Constructor that loads an RSA private key from a binary file.
	 * @param file_path The path to the file containing the private key in binary format.
	 * @throws CryptoPP::Exception If there is an error loading the private key.
	 */
	RSAPrivateWrapper(const std::string& file_path);

	/**
	 * @brief Destructor for RSAPrivateWrapper.
	 * Currently, the destructor doesn't have specific cleanup actions,
	 * but it is provided for completeness in case future cleanup is required.
	 */
	~RSAPrivateWrapper();

	/**
	 * @brief Retrieves the RSA private key as a string.
	 * This function converts the internal private key into a string and returns it.
	 * @return std::string The private key in string format.
	 */
	std::string getPrivateKey() const;
	/**
	 * @brief Retrieves the RSA public key as a string.
	 * This function extracts the public key from the internal private key and returns it as a string.
	 * @return std::string The public key in string format.
	 */
	std::string getPublicKey() const;

	/**
	 * @brief Decrypts a given ciphertext using the RSA private key.
	 * This function decrypts the provided ciphertext using the OAEP SHA decryption scheme.
	 * @param cipher The encrypted text to be decrypted.
	 * @return std::string The decrypted plaintext.
	 * @throws CryptoPP::Exception If there is an error during decryption.
	 */
	std::string decrypt( std::string cipher);
	
	
}; 
