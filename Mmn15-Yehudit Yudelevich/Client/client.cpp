#include "client.h"
#include "protocol.cpp"
#include "RSA.h"
#include <base64.h>
#include "encode.cpp"
#include "FILE_PROCESS.cpp"
#include "AESWrapper.cpp"
#include "CRC.cpp"
#include <winsock2.h>
#include <cstdlib>

# define CHUNK_SIZE 2048;
boost::asio::io_context io_context;
Request_to_server request_to_server;
send_the_request request(io_context);

std::string padding(const std::string& str, size_t totalLength) {
    // If the string is already long enough, return it as is.
    if (str.length() >= totalLength) {
        return str;
    }

    // Pad the string with '0' characters to reach the desired length.
    return str + std::string(totalLength - str.length(), '0');
}
std::string generate_RSA_key() {
    RSAPrivateWrapper rsa;
    std::string private_key = rsa.getPrivateKey();
    std::cout << "----------------------------------------------------------------\n";
    std::cout << "the RSA keys created, move to write the private key in priv.key\n";
    std::string key_on_base64 = Encoder::b64encode(rsa.getPrivateKey());
    std::cout << "---------------------------------------------------------------\n";
    std::ofstream file("priv.key");
    if (file.is_open()) {
        file << key_on_base64;
        file.close();
    }
    else {
        throw std::runtime_error("\nError opening priv.key\n");
    }
    std::ofstream file2("me.info", std::ios::app);
    if (file2.is_open()) {
        file2 << key_on_base64;
        file2.close();
    }
    else {
        throw std::runtime_error("\nError opening me.info\n");
    }

    return rsa.getPublicKey();
}


bool Client::file_exists(const std::string& name) {
    std::ifstream file(name);
    //check if the file exists
    return file.good();
}
Client::Client() {}

void Client::read_transfer_file() {
    // Open the transfer.info file
    std::fstream file("transfer.info");
    if (!file.is_open()) {
        std::cerr << "Error: Could not open file transfer.info" << std::endl;
        return;
    }
    // Read the IP and port from the first line
    std::string ip_and_port;
    std::getline(file, ip_and_port);
    size_t colon_pos = ip_and_port.find(':');
    if (colon_pos != std::string::npos) {
        client_ip = ip_and_port.substr(0, colon_pos);
        client_port = std::stoi(ip_and_port.substr(colon_pos + 1));
    }
    else {
        std::cerr << "Error: IP and port format is incorrect" << std::endl;
        return;
    }
    // Read the client name
    std::getline(file, client_name);
    if (client_name.size() > 100) {
        std::cerr << "Error: client name is too long" << std::endl;
		return;
    }
    std::getline(file, path_to_file);
    std::cout << "the client details are:" << std::endl;
    std::cout << "The name is: " <<  client_name << std::endl; 
    std::cout << "The path to file is: " << path_to_file << std::endl; 
    std::cout << "The ip is: " << client_ip << std::endl; 
    std::cout << "The port is: " << client_port << std::endl; 
    std::cout<<"-----------------------------------------------"<<std::endl;
    // Close the file after reading
    file.close();
}

void Client::read_me_file() {
    // Open the me.info file
    std::fstream file("me.info");
    if (!file.is_open()) {
        std::cerr << "Error: Could not open file me.info" << std::endl;
        return;
    }
    // Read the client name, unique ID, and private key
    std::getline(file, client_name);
    std::getline(file, unique_id);
    std::getline(file, private_key);
    // Close the file after reading
    file.close();
}

std::vector<std::string> split_to_fields(std::string& str) {
    std::vector<std::string> fields;
    std::string field;
    std::istringstream ss(str);
    // Split the string by spaces and store each field
    while (std::getline(ss, field, ' ')) {
        fields.push_back(field);
    }
    return fields;
}
void Client::write_me_file(const std::string& client_name, const std::string& unique_id, const std::string& private_key = "") {
    std::ofstream file("me.info");
    // Open the me.info file for writing
    if (!file.is_open()) {
        std::cerr << "Error: Could not open file me.info" << std::endl;
        return;
    }
    // Write the client name, unique ID, and private key (if provided)
    std::cout << "the client name is: " << client_name << std::endl;
    std::cout << "the unique id is: " << unique_id << std::endl;
    std::cout<<"-----------------------------------------------"<<std::endl;
    file << client_name << std::endl;
    file << unique_id << std::endl;
    file << private_key << std::endl;
    // Close the file after writing
    file.close();
}

void Client::send_registration_request() {
    std::cout<<"move to send registration request."<<std::endl;
    std::cout<<"-----------------------------------------------"<<std::endl;
    std::string the_answer_from_server;
    std::vector<std::string> fields;
    // Pad the client name to the required length.
    std::string the_client_name = padding(client_name, NAME);
    Registration registration("11111111111111111111111111111111\n", VERSION_DEAFULT, request_code_to_server.at("Registration"), NAME, the_client_name);
    
    try {
        send_the_request sender(io_context);
        // Send the request and receive the response from the server.
        the_answer_from_server = sender.send_request_to_server(registration, sender);
        // Split the server's response into fields
        fields = split_to_fields(the_answer_from_server);
        std::cout << "The response from the server was successfully received.\n" << std::endl;
        // Ensure the response contains enough fields.
        if (fields.size() >= 4) {
            // Extract the version, code, and payload size from the response.
            uint8_t version = static_cast<uint8_t>(std::stoi(fields.at(0)));
            uint16_t code = static_cast<uint16_t>(std::stoi(fields.at(1)));
            uint8_t payload_size = static_cast<uint8_t>(std::stoi(fields.at(2)));
            // Get the unique client ID from the server's response.
            unique_id = padding(fields.at(3), 16);
            // Create a registration success object.
            Registration_successful Registration_from_server(version, code, payload_size, unique_id);
            // Update the client with the server-provided client ID.
            unique_id = Registration_from_server.CLIENT_ID;
            std::cout<<"move to Update customer information in me file:"<<std::endl;
            // Write the client name and unique ID to the me file.
            write_me_file(client_name, Registration_from_server.CLIENT_ID);
        }
        else {
            throw std::runtime_error("Invalid server response format.");
        }
    }
    catch (std::exception& e) {
        // Handle any exception that occurs and create a failed registration response.
        Registration_failed failed(VERSION_DEAFULT, answer_code_to_client.at("Registration_failed"), 1, "");
        std::cerr << "Exception in send_registration_request: " << e.what() << std::endl;

    }
}


std::string Client::accept_private_key() {
    std::string private_key;
    std::fstream file("priv.key");
    // Check if the file can be opened
    if (!file.is_open()) {
        std::cerr << "Error: Could not open file priv.key" << std::endl;
        return "";
    }
    // Read the private key line by line and append to the string
    std::string line;
    while (std::getline(file, line)) {
        private_key += line; 
    }
    // Close the file after reading
    file.close();
    return private_key;
    
    
}

std::string Client::open_aes_key(std::string aes_key) {
    std::string AES;
    std::string private_key = accept_private_key();
    std::string p_key;
    // Decode the private key from base64 format
    CryptoPP::StringSource ss(private_key, true,
        new CryptoPP::Base64Decoder(
            new CryptoPP::StringSink(p_key)
        ) 
    );
    // Decrypt the AES key using the private RSA key
    RSAPrivateWrapper rsapriv(p_key);
    AES =rsapriv.decrypt(aes_key);
    return AES;
}



std::string Client::send_public_key(std::string public_key) {
    std::cout << "Move to send public key" << std::endl;
    std::cout << "-----------------------------------------------" << std::endl;
    std::string the_answer_from_server;
    std::string the_client_name = padding(client_name, NAME);
    std::string AES_AFTER_DECRYPTION;
    // Prepare the public key request
    Sending_public_key sending_public_key(unique_id, VERSION_DEAFULT, request_code_to_server.at("Sending_public_key"),NAME_AND_PUBLIC_KEY, the_client_name, public_key);

    try {
        send_the_request sender(io_context);
        // Send the request and receive the server's response
        the_answer_from_server = sender.send_request_to_server(sending_public_key, sender);

        std::cout << "The response from the server was successfully received." <<std::endl;
       
        // Parse the server's response
        std::istringstream response_stream(the_answer_from_server);
        std::string version_str, code_str, payload_size_str, client_id_str;
        response_stream >> version_str >> code_str >> payload_size_str >> client_id_str;

        // Convert the response fields to appropriate data types
        uint8_t version = static_cast<uint8_t>(std::stoi(version_str));
        uint16_t code = static_cast<uint16_t>(std::stoi(code_str));
        uint8_t payload_size = static_cast<uint8_t>(std::stoi(payload_size_str));
        std::string CLIENT_ID = padding(client_id_str, 16);

        // Find the AES key in the server's response
        size_t aes_start_pos = the_answer_from_server.find(CLIENT_ID) + CLIENT_ID.length();
        if (aes_start_pos >= the_answer_from_server.length()) {
            throw std::runtime_error("AES key is missing after client ID.");
        }

        // Extract the encrypted AES key
        std::string AES = the_answer_from_server.substr(aes_start_pos+1, 128);
        
        // Remove leading spaces from the AES key
        size_t first_not_space = AES.find_first_not_of(' ');
        if (first_not_space != std::string::npos) {
            AES = AES.substr(first_not_space);  // רק אם נמצא מקום חוקי
        }

        // Check if the AES key is empty
        if (AES.empty()) {
            throw std::runtime_error("AES key is empty or missing.");
        }

        std::cout << "An encrypted AES key was received from the server" << std::endl;
        
        // יצירת אובייקט Public_key_received_AES_sent
        Public_key_received_AES_sent AES_from_server(version, code, payload_size, CLIENT_ID, AES);

        std::cout << "Move to open the AES key by the private key..." << std::endl;
     
        // Decrypt the AES key using the private key
        AES_AFTER_DECRYPTION = open_aes_key(AES_from_server.AES);
        Client::AES = AES_AFTER_DECRYPTION;
        std::cout << "The key has been opened successfully." << std::endl;
        std::cout << "-----------------------------------------------" << std::endl;

        return AES_AFTER_DECRYPTION;

    }
    catch (std::exception& e) {
        // Handle exceptions and create a failed registration response
        Registration_failed failed(VERSION_DEAFULT, answer_code_to_client.at("Registration_failed"), 1, "");
        std::cerr << "Exception in send_public_key: " << e.what() << std::endl;
        return "";
    }
}


std::string Client::encrypt_file(std::string file_content) {
    // Create an AES encryption object using the stored AES key.
    AESWrapper aes(this->AES.c_str(), this->AES.length());
    // Encrypt the file content using AES encryption.
    std::string cipher_text = aes.encrypt(file_content.c_str(), file_content.length());
    std::cout << "The file has been successfully encrypted" << std::endl;
    // Return the encrypted content (cipher text).
    return cipher_text;
    
}


void Client::send_file() {
    std::cout << "move to send file" << std::endl;
    std::cout<<"-----------------------------------------------"<<std::endl;
    // Get the file path and content
    std::string file_path = FileUtil::get_path_to_file();
    std::string the_file_content = FileUtil::get_file_content(file_path);
    // Encrypt the file content
    std::string encrypt_file= Client::encrypt_file(the_file_content);
    // Get the file name and pad it to 255 bytes
    std::string file_name = FileUtil::get_file_name(file_path);
    file_name.resize(NAME, '\0');
    // Calculate CRC for the file
    unsigned long crc_of_client = calc_crc(file_path);
    std::cout << "--------------------------------------------" << std::endl;
    std::cout << "CRC calculation performed successfully" << std::endl;
    // Get the size of the encrypted file
    uint32_t size_of_encrypted_file = encrypt_file.length();
    size_t total_packets = size_of_encrypted_file / CHUNK_SIZE ;

    // Check if there's a remainder that requires an additional packet
    if (size_of_encrypted_file % 2048 != 0) {
		total_packets++;
	}
    
    size_t current_packet = 1;
    size_t current_position = 0;
    uint32_t original_file_size = the_file_content.length();

    // Send the file in chunks
    send_the_request sender(io_context);
    std::string the_answer_from_server;
    while (current_packet <= total_packets) {
        // Get the content for the current packet
        std::string packet_content = encrypt_file.substr(current_position, 2048);
        size_t size_packet = packet_content.length();
        size_t payload_size = 267 + size_packet;
        // Send a packet to the server
        if (unique_id.back() != '\n') {
            unique_id += "\n"; //to split between the id and the version
        }
        Sending_file sending_file(unique_id, VERSION_DEAFULT, request_code_to_server.at("Sending_file"), payload_size, size_of_encrypted_file, original_file_size, current_packet, total_packets, file_name, packet_content);
        std::cout << "A request to the server includes a file packet sent successfully"  << std::endl;
        the_answer_from_server= sender.send_request_to_server(sending_file, sender);

        current_packet++;
        current_position += CHUNK_SIZE;
    }
    std::cout << "the file was sent successfully" << std::endl;
    std::cout<<"-----------------------------------------------"<<std::endl;
    std::cout << "The response from the server was successfully received." << std::endl;
    // Split the server's response and verify CRC
    std::vector<std::string> fields = split_to_fields(the_answer_from_server);
    if (fields.size() == 7) {
        unsigned long CRC_server = std::stoul(fields.at(6));
        std::cout << "CRC from server successfully received." << std::endl;
        std::cout << "-----------------------------------------------" << std::endl;
        std::cout << "A CRC confirmation/rejection request is sent to the server." << std::endl;
       
        if (crc_of_client == CRC_server) {
            // CRC is valid, confirm with the server
            send_crc(file_name);
            return ;
        }
        else if (NUM_OF_TRIALS_CRC < 2) {
            // Resend the file if CRC doesn't match
            NUM_OF_TRIALS_CRC++;
            std::cout << "crc not valid at the first time." << fields.at(6) << std::endl;
            send_crc_not_ok(file_name);
        }
        else {
            // End after too many CRC mismatches
            std::cout << "crc not valid at the 2 time." << fields.at(6) << std::endl;
            send_crc_not_ok_end(file_name);
        }
    }
    else {
        throw std::runtime_error("Invalid server response format.");
    }
    
    return;
}



void Client::send_crc(std::string file_name) {
    // Create a CRC confirmation message
    CRC_normal crc_normal(unique_id, VERSION_DEAFULT, request_code_to_server.at("CRC_normal"),255 ,file_name);
    try {
        // Send the CRC confirmation to the server
        send_the_request sender(io_context);
        std::string the_answer_from_server = sender.send_request_to_server(crc_normal, sender);
        std::cout << "Confirmation from the server was received successfully, CRC is correct."<< std::endl;
        std::cout << "Logging out...." << std::endl;
        // Exit the process after confirmation
        std::exit(EXIT_SUCCESS);


        
    }
    catch (std::exception& e) {
		std::cerr << "Exception in send_crc: " << e.what() << std::endl;
	}
	
}
void Client::send_crc_not_ok(std::string file_name) {
    // Create a CRC error message
    CRC_not_normal crc_not_normal(unique_id, VERSION_DEAFULT, request_code_to_server.at("CRC_not_normal"), 255, file_name);
    try {
        // Send the CRC error message to the server
		send_the_request sender(io_context);
		std::string the_answer_from_server = sender.send_request_to_server(crc_not_normal, sender);
        std::cout << "Bad CRC received a second time, sending the file again\n" << std::endl;
        send_file();
	}
	catch (std::exception& e) {
        // Handle any errors during the process
		std::cerr << "Exception in send_crc_not_ok: " << e.what() << std::endl;
	}


}
void Client::send_crc_not_ok_end(std::string file_name) {
    // Create a final CRC error message indicating the end of the process
    CRC_end crc_end(unique_id, VERSION_DEAFULT, request_code_to_server.at("CRC_end"), 255, file_name);
    try {
        // Send the final CRC error message to the server
        send_the_request sender(io_context);
        std::string the_answer_from_server = sender.send_request_to_server(crc_end, sender);
        std::cout << "Bad CRC received last time, we're done\n" << std::endl;
        std::exit(EXIT_SUCCESS);

    }
    catch (std::exception& e) {
        // Handle any errors during the process
		std::cerr << "Exception in send_crc_not_ok_end: " << e.what() << std::endl;
	}

}
std::string Client::send_recconected() {
    //Padding the client name to ensure it has the required length
    std::string the_client_name = padding(client_name, NAME);
    std::string AES_AFTER_DECRYPTION;
    
    // Creating a login_again object to prepare the request with the unique_id and client_name
    login_again login_again(unique_id+"\n", VERSION_DEAFULT, request_code_to_server.at("Login_again"), NAME, the_client_name);
    try {
        // Sending the request to the server
        send_the_request sender(io_context);
        std::string the_answer_from_server = sender.send_request_to_server(login_again, sender);
        // Parsing the server's response using istringstream to break down the fields
        std::istringstream response_stream(the_answer_from_server);

        // Reading the version, code, payload size, and client ID from the response
        std::string version_str, code_str, payload_size_str, client_id_str;
        response_stream >> version_str >> code_str >> payload_size_str >> client_id_str;

        // Converting the version, code, and payload size from strings to numbers
        uint8_t version = static_cast<uint8_t>(std::stoi(version_str));


        uint16_t code = static_cast<uint16_t>(std::stoi(code_str));
        uint8_t payload_size = static_cast<uint8_t>(std::stoi(payload_size_str));
        // Padding the client ID to the expected size (16 characters)
        std::string CLIENT_ID = padding(client_id_str, 16);
        // Finding the position where the AES key starts in the response string
        size_t aes_start_pos = the_answer_from_server.find(CLIENT_ID) + CLIENT_ID.length();
        // Check if the AES key was found after the client ID
        if (aes_start_pos >= the_answer_from_server.length()) {
            throw std::runtime_error("AES key is missing after client ID.");
        }

        // Extracting the AES key (128 characters) from the server's response
        std::string AES = the_answer_from_server.substr(aes_start_pos + 1, 128);


        // Removing any leading spaces from the AES key if present
        size_t first_not_space = AES.find_first_not_of(' ');
        if (first_not_space != std::string::npos) {
            AES = AES.substr(first_not_space);  
        }
        // Checking if the AES key is empty
        if (AES.empty()) {
            throw std::runtime_error("AES key is empty or missing.");
            return "";
        }

        std::cout << "An encrypted AES key was received from the server" << std::endl;

        // Creating a Public_key_received_AES_sent object with the extracted data
        Public_key_received_AES_sent AES_from_server(version, code, payload_size, CLIENT_ID, AES);

        std::cout << "Move to open the AES key by the private key..." << std::endl;

        // Decrypting the AES key using the private key
        AES_AFTER_DECRYPTION = open_aes_key(AES_from_server.AES);
        Client::AES = AES_AFTER_DECRYPTION;
        std::cout << "The key has been opened successfully." << std::endl;
        std::cout << "-----------------------------------------------" << std::endl;

       
    }
    catch (std::exception& e) {
        if (std::remove("me") == 0) {
            std::cout << "File 'me' deleted successfully." << std::endl;
           
        }
        else {
            std::cerr << "Error deleting file 'me'." << std::endl;

        }
        std::cerr << "Registration failed. Exiting the program." << std::endl;
        exit(EXIT_FAILURE);
    }
    return AES_AFTER_DECRYPTION;


}
