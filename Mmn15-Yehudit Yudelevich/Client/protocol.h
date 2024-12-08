#pragma once
#include <string>
#include <fstream>
#include <cstdint>
#include <sstream>
#include <vector>
#include <iostream>
#include <boost/asio.hpp>
#include <map>

const uint8_t VERSION_DEAFULT = 3;
const uint8_t PAYLOAD_SIZE = 4;
const uint8_t CODE = 4;
const uint8_t CLIENT_ID = 16;
const uint8_t CONTENT_SIZE = 4;
const uint8_t ORG_FILE_SIZE = 4;
const uint8_t PACKET_NUMBER = 4;
const uint8_t CKSUM = 4;
const size_t NAME = 255;
const size_t FILE_NAME = 255;
const size_t MAX_SIZE = 1024;
const size_t PUBLIC_KEY = 160;
const size_t NAME_AND_PUBLIC_KEY = 415;


extern std::map<std::string, size_t> request_code_to_server;
extern std::map<std::string, size_t> answer_code_to_client;

class Request_to_server {
public:

    std::string client_id;
    uint8_t version;
    uint16_t code;
    uint8_t payload_size;
    std::string payload;
    Request_to_server() = default;
    Request_to_server(std::string client_id, uint8_t version, uint16_t code, uint32_t payload_size, const std::string& payload);

    /**
 * @brief Prepares the request data in a string format for sending to the server.
 *
 * @return A string containing the request data formatted for sending.
 */
    virtual std::string prepare_for_sending();
protected:

    /**
 * @brief Creates a payload string from multiple fields.
 *
 * @param fields A vector containing the fields to be included in the payload.
 * @param payload_size The size of the payload.
 * @return A string representing the created payload, or an empty string if an error occurs.
 */
    std::string create_payload(const std::vector<std::string>& fields, uint32_t payload_size);

};
class send_the_request {
public:

    /**
 * @brief Constructor for the send_the_request class.
 *
 * @param io The Boost ASIO io_context object used for asynchronous operations.
 */
    send_the_request(boost::asio::io_context& io);

    /**
 * @brief Extracts the request code from a request string.
 *
 * @param request_string The request string containing multiple lines.
 * @return A string representing the request code.
 * @throws std::runtime_error If the request string does not contain enough lines.
 */
    std::string extract_request_code(const std::string& request_string);

    /**
 * @brief Sends the request to the server and handles retries if the request fails.
 *
 * @param request The request object to be sent.
 * @param sender The sender object managing the sending process.
 * @return A string representing the status of the request (Success/Failed).
 */
    std::string send_request_to_server(Request_to_server& request, send_the_request& sender);

    /**
 * @brief Processes a general request by sending it to the server and receiving the response.
 *
 * @param ip The IP address of the server.
 * @param port The port number of the server.
 * @param the_request The request data in string format.
 * @param code_request The request code extracted from the request.
 * @param TIME The number of retry attempts made.
 * @return A string representing the status of the request (Success/Failed).
 */
    std::string process_request(const std::string& ip, const std::string& port, const std::string& the_request, const std::string& code_request, const uint8_t& TIME);
    boost::asio::ip::tcp::socket socket;
    /**
     * @brief Reads the server's response from the socket.
     *
     * @param socket The TCP socket used for communication with the server.
     * @return A string representing the server's full response.
     */
    std::string read_response(boost::asio::ip::tcp::socket& socket);
private:
    std::string the_request;
    std::string code_request;
   
};


/**
 * @brief Constructor for Registration request.
 *
 * @param client_id The unique identifier of the client.
 * @param version The protocol version being used.
 * @param code The request code for registration.
 * @param payload_size The size of the payload.
 * @param Name The client's name.
 */
class Registration : public Request_to_server {
public:
    std::string Name;
    Registration(std::string client_id, uint8_t version, uint16_t code, uint32_t payload_size, const std::string& Name);
    std::string prepare_for_sending()  override;
};


/**
 * @brief Constructor for Sending_public_key request.
 *
 * @param client_id The unique identifier of the client.
 * @param version The protocol version being used.
 * @param code The request code for sending a public key.
 * @param payload_size The size of the payload.
 * @param Name The client's name.
 * @param public_key The client's public key to be sent to the server.
 */
class Sending_public_key : public Request_to_server {
public:
    std::string Name;
    std::string public_key;

    Sending_public_key(std::string client_id, uint8_t version, uint16_t code, size_t payload_size, const std::string& Name, const std::string& public_key);
    std::string prepare_for_sending()  override;

};


/**
 * @brief Constructor for login_again request.
 *
 * @param client_id The unique identifier of the client.
 * @param version The protocol version being used.
 * @param code The request code for login.
 * @param payload_size The size of the payload.
 * @param Name The client's name.
 */

class login_again : public Request_to_server {
public:
    std::string Name;
    login_again(std::string client_id, uint8_t version, uint16_t code, uint32_t payload_size, const std::string& Name);
    std::string prepare_for_sending()  override;
};


/**
 * @brief Constructor for Sending_file request.
 *
 * @param client_id The unique identifier of the client.
 * @param version The protocol version being used.
 * @param code The request code for sending a file.
 * @param payload_size The size of the payload.
 * @param content_size The size of the file content.
 * @param orig_file_size The original size of the file.
 * @param packet_number The current packet number.
 * @param total_packet The total number of packets.
 * @param file_name The name of the file being sent.
 * @param file_content The content of the file.
 */
class Sending_file : public Request_to_server {
public:
    uint8_t content_size;
    uint8_t orig_file_size;
    uint8_t packet_number;
    uint8_t total_packet;
    std::string file_name;
    std::string file_content;
    Sending_file(std::string client_id, uint8_t version, uint16_t code, size_t payload_size, size_t content_size, size_t orig_file_size, const uint8_t& packet_number, const uint8_t& total_packet, const std::string& file_name, const std::string& file_content);
    std::string prepare_for_sending()  override;
};

/**
 * @brief Constructor for CRC_normal request.
 *
 * @param client_id The unique identifier of the client.
 * @param version The protocol version being used.
 * @param code The request code for normal CRC check.
 * @param payload_size The size of the payload.
 * @param file_name The name of the file being checked.
 */
class CRC_normal : public Request_to_server {
public:
    std::string file_name;
    CRC_normal(std::string client_id, uint8_t version, uint16_t code, uint32_t payload_size, const std::string& file_name);
    std::string prepare_for_sending()  override;
};

/**
 * @brief Constructor for CRC_not_normal request.
 *
 * @param client_id The unique identifier of the client.
 * @param version The protocol version being used.
 * @param code The request code for abnormal CRC check.
 * @param payload_size The size of the payload.
 * @param file_name The name of the file being checked.
 */
class CRC_not_normal : public Request_to_server {
public:
    std::string file_name;
    CRC_not_normal(std::string client_id, uint8_t version, uint16_t code, uint32_t payload_size, const std::string& file_name);
    std::string prepare_for_sending()  override;
};


/**
 * @brief Constructor for CRC_end request.
 *
 * @param client_id The unique identifier of the client.
 * @param version The protocol version being used.
 * @param code The request code for CRC end.
 * @param payload_size The size of the payload.
 * @param file_name The name of the file being checked.
 */
class CRC_end : public Request_to_server {
public:
    std::string file_name;
    CRC_end(std::string client_id, uint8_t version, uint16_t code, uint32_t payload_size, const std::string& file_name);
    std::string prepare_for_sending()  override;
};

/**
 * @brief Base class for handling server responses.
 */
class ServerResponse {
public:
    uint8_t version;
    uint16_t code;
    uint16_t payload_size;
    std::string payload;
    ServerResponse(uint8_t version, uint16_t code, uint32_t payload_size, const std::string& payload);
protected:
    /**
     * @brief Creates a payload string from multiple fields.
     *
     * @param fields A vector containing the fields to be included in the payload.
     * @param payload_size The size of the payload.
     * @return A string representing the created payload, or an empty string if an error occurs.
     */
    std::string create_payload(const std::vector<std::string>& fields, uint32_t payload_size);
};


/**
 * @brief Class representing a successful registration response.
 */
class Registration_successful : public ServerResponse {
public:
    std::string CLIENT_ID;

    /**
     * @brief Constructor for Registration_successful.
     *
     * @param version The protocol version.
     * @param code The response code.
     * @param payload_size The size of the payload.
     * @param CLIENT_ID The client's unique identifier.
     */
    Registration_successful(uint8_t version, uint16_t code, uint32_t payload_size, const std::string& CLIENT_ID);
};

/**
 * @brief Class representing a failed registration response.
 */
class Registration_failed : public ServerResponse {
public:
    /**
    * @brief Constructor for Registration_failed.
    *
    * @param version The protocol version.
    * @param code The response code.
    * @param payload_size The size of the payload.
    * @param payload The payload content explaining the failure.
    */
    Registration_failed(uint8_t version, uint16_t code, uint32_t payload_size, const std::string& payload);
};

/**
 * @brief Class representing a response when a public key is received and an AES key is sent.
 */
class Public_key_received_AES_sent : public ServerResponse {
public:
    std::string AES;
    std::string CLIENT_ID;
    /**
    * @brief Constructor for Public_key_received_AES_sent.
    *
    * @param version The protocol version.
    * @param code The response code.
    * @param payload_size The size of the payload.
    * @param CLIENT_ID The client's unique identifier.
    * @param AES The AES key received from the server.
    */
    Public_key_received_AES_sent(uint8_t version, uint16_t code, uint32_t payload_size, const std::string& CLIENT_ID, const std::string& AES);
};

/**
 * @brief Class representing a response indicating that the file is valid.
 */
class file_vlid : public ServerResponse {
public:
    std::string CLIENT_ID;
    std::string CONTENT_SIZE;
    std::string FILE_NAME;
    std::string CKSUM;
    /**
   * @brief Constructor for file_vlid.
   *
   * @param version The protocol version.
   * @param code The response code.
   * @param payload_size The size of the payload.
   * @param CLIENT_ID The client's unique identifier.
   * @param CONTENT_SIZE The size of the file content.
   * @param FILE_NAME The name of the file.
   * @param CKSUM The checksum of the file.
   */
    file_vlid(uint8_t version, uint16_t code, uint32_t payload_size, const std::string& CLIENT_ID, const std::string& CONTENT_SIZE, const std::string& FILE_NAME, const std::string& CKSUM);
};
/**
 * @brief Class representing a confirmation of message receipt.
 */
class Confirmation_receiving_message : public ServerResponse {
public:
    std::string CLIENT_ID;
    
    /**
    * @brief Constructor for Confirmation_receiving_message.
    *
    * @param version The protocol version.
    * @param code The response code.
    * @param payload_size The size of the payload.
    * @param CLIENT_ID The client's unique identifier.
    */
    Confirmation_receiving_message(uint8_t version, uint16_t code, uint32_t payload_size, const std::string& CLIENT_ID);
};

/**
 * @brief Class representing a reconnecting response.
 */
class reconnecting : public ServerResponse {
public:
    std::string CLIENT_ID;
    std::string AES;
    /**
  * @brief Constructor for reconnecting.
  *
  * @param version The protocol version.
  * @param code The response code.
  * @param payload_size The size of the payload.
  * @param CLIENT_ID The client's unique identifier.
  * @param AES The AES key used for reconnection.
  */
    reconnecting(uint8_t version, uint16_t code, uint32_t payload_size, const std::string& CLIENT_ID, const std::string& AES);
};

/**
 * @brief Class representing a failed reconnection attempt.
 */
class reconnecting_failled : public ServerResponse {
public:
    std::string CLIENT_ID;
    /**
    * @brief Constructor for reconnecting_failled.
    *
    * @param version The protocol version.
    * @param code The response code.
    * @param payload_size The size of the payload.
    * @param CLIENT_ID The client's unique identifier.
    */
    reconnecting_failled(uint8_t version, uint16_t code, uint32_t payload_size, const std::string& CLIENT_ID);
};

/**
 * @brief Class representing a general error response from the server.
 */
class Error_general : public ServerResponse {
public:
    std::string ERROR_TEXT;
    /**
    * @brief Constructor for Error_general.
    *
    * @param version The protocol version.
    * @param code The response code.
    * @param payload_size The size of the payload.
    * @param ERROR_TEXT A description of the error.
    */
    Error_general(uint8_t version, uint16_t code, uint32_t payload_size, const std::string& ERROR_TEXT);
};










