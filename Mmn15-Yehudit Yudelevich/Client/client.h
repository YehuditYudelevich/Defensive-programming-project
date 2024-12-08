
#pragma once
#include <iostream>
#include <thread>
#include <chrono>
#include <string>
#include <fstream>
#include <sstream>
#include <stdexcept>

const uint8_t NUM_OF_TRIALS = 4;
const uint8_t TIME = 4;
uint8_t NUM_OF_TRIALS_CRC = 0;

/**
 * @brief Pads the input string with '0' characters at the end until it reaches the total length.
 *
 * @param str The input string to be padded.
 * @param totalLength The desired total length of the string after padding.
 * @return std::string The padded string, or the original string if it's already long enough.
 */
std::string padding(const std::string& str, size_t totalLength);

std::string generate_RSA_key();


class Client {
private:
    std::string client_name;
    std::string client_ip;
    uint16_t client_port;
    std::string path_to_file;
    std::string unique_id;
    std::string private_key;
    std::string AES;

public:
    Client();
     /**
     * @brief Reads client info (IP, port, name, file path) from the transfer.info file.
     * Opens the file, extracts the IP address, port, client name, and file path.
     * @return void
     */
    void read_transfer_file();

     /**
     * @brief Reads client info (name, unique ID, private key) from the me.info file.
     * @return void
     */
    void read_me_file();

     /**
     * @brief Writes the client name, unique ID, and optionally the private key to the me.info file.
     * @param client_name The name of the client.
     * @param unique_id The unique ID of the client.
     * @param private_key The private key (optional).
     * @return void
     */
    void write_me_file(const std::string& client_name, const std::string& unique_id, const std::string& private_key);
     /**
     * @brief Checks if a file exists.
     * Attempts to open the specified file. If the file can be opened, it exists.
     * @param name The name or path of the file to check.
     * @return bool Returns `true` if the file exists, `false` otherwise.
     */
    bool file_exists(const std::string& name);
 
     /**
     * Sends a registration request to the server and processes the response.
     */
    void send_registration_request();

     /**
     * @brief Reads the private key from the "priv.key" file.
     * @return The private key as a string, or an empty string if the file cannot be opened.
     */
    std::string accept_private_key();


     /**
     * @brief Decrypts the provided AES key using the private key.
     * @param aes_key The AES key to be decrypted.
     * @return The decrypted AES key as a string.
     */
    std::string open_aes_key(std::string aes_key);

     /**
     * @brief Sends the public key to the server, receives the encrypted AES key, and decrypts it.
     * @param public_key The public key to be sent to the server.
     * @return The decrypted AES key as a string.
     */
    std::string send_public_key(std::string public_key);

     /**
     * @brief Encrypts the given file content using the AES key stored in the client.
     * This function uses the stored AES key to encrypt the provided file content using AES encryption.
     * @param file_content The content of the file to be encrypted.
     * @return std::string The encrypted file content as cipher text.
     */
    std::string encrypt_file(std::string file_content);

     /**
     * @brief Sends a file to the server in chunks and verifies the CRC.
     * The function reads a file, encrypts it, and sends it in chunks (packets) to the server. After the file is sent,
     * the function verifies the CRC sent by the server to ensure data integrity.
     */
    void send_file();
    
     /**
     * @brief Sends a CRC confirmation to the server after successful verification.
     * @param file_name The name of the file that was sent.
     */
    void send_crc(std::string file_name);

     /**
     * @brief Sends a CRC error message to the server and resends the file.
     * @param file_name The name of the file that needs to be resent.
     */
    void send_crc_not_ok(std::string file_name);

     /**
     * @brief Sends a final CRC error message to the server after multiple failed attempts.
     * @param file_name The name of the file that failed to send correctly.
     */
    void send_crc_not_ok_end(std::string file_name);

      /**
     * Function: Client::send_recconected
     * This function handles the re-login process by sending a login request to the server,
     * receiving the server's response, and extracting the AES key from the response for decryption.
     * @return std::string - the decrypted AES key or an empty string in case of failure.
     */
    std::string send_recconected();
 
    


};
