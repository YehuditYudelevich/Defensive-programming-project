#include "RSA.h"

RSAPrivateWrapper::RSAPrivateWrapper()
{
    // Initialize the private key with the specified bit size.
    _privateKey.Initialize(_rng, BITS); 
}

RSAPrivateWrapper::RSAPrivateWrapper(const std::string& file_path)

{
   
    try {
        CryptoPP::StringSource ss(file_path, true);   // Load the private key from the binary file.
        _privateKey.Load(ss);  // Load the private key into the internal object.
        std::cout << "Private key loaded successfully." << std::endl;
    }
    catch (const CryptoPP::Exception& e) {
        // Handle and throw an error if the private key loading fails.
        std::cerr << "Error loading private key: " << e.what() << std::endl;
        throw;
    }
}

RSAPrivateWrapper::~RSAPrivateWrapper()
{
}

std::string RSAPrivateWrapper::getPrivateKey() const
{
    std::string key;
    CryptoPP::StringSink ss(key);
    _privateKey.Save(ss); // Save the private key to a string.
    return key;
}

std::string RSAPrivateWrapper::getPublicKey() const
{
    // Derive the public key from the private key.
    CryptoPP::RSAFunction publicKey(_privateKey);
    std::string key;
    CryptoPP::StringSink ss(key);
    publicKey.Save(ss);  // Save the public key to a string.
    return key;
}
std::string RSAPrivateWrapper::decrypt(std::string cipher)
{
    
    std::string decrypted;

    try {
        // Create a decryption object using the private key.
        CryptoPP::RSAES_OAEP_SHA_Decryptor d(_privateKey);
        // Decrypt the ciphertext.
        CryptoPP::StringSource ss_cipher(cipher, true,
            new CryptoPP::PK_DecryptorFilter(_rng, d, new CryptoPP::StringSink(decrypted))
        );

    }
    catch (const CryptoPP::Exception& e) {
        std::cerr << "Error during decryption: " << e.what() << std::endl;
        throw;  
    }

    return decrypted;  // Return the decrypted plaintext.
}
