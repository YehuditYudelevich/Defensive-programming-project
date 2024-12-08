
#include "protocol.h"
// Maps for request and response codes between client and server
std::map < std::string, size_t> request_code_to_server = {
    {"Registration", 825},
    {"Sending_public_key", 826},
    {"Login_again", 827},
    {"Sending_file", 828},
    {"CRC_normal", 900},
    {"CRC_not_normal", 901},
    {"CRC_end", 902}
};

std::map<std::string, size_t> answer_code_to_client = {
    {"Registration_successful", 1600},
    {"Registration_failed", 1601},
    {"Public_key_received_AES_sent", 1602},
    {"file_vlid", 1603},
    {"Confirmation_receiving_message", 1604},
    {"reconnecting", 1605},
    {"reconnecting_failled", 1606},
    {"Error_general", 1607}
};

// Protected method to create a payload from multiple fields
// Converts multiple fields into a single payload string
 std::string Request_to_server::create_payload(const std::vector<std::string>& fields, uint32_t payload_size) {
    std::ostringstream ss;
    if (payload_size < fields.size()) {
        std::cerr << "Error: payload_size is smaller than the number of fields" << std::endl;
        return "";
    }
    for (const auto& field : fields) {
        ss << field<<"\n";
    }
    return ss.str();
}

// Prepare the request data to send it to the server in string format
std::string Request_to_server::prepare_for_sending() {
    std::ostringstream ss;
    ss << client_id  << static_cast<int>(version) << "\n" << static_cast<int>(code) << "\n" << std::to_string(payload_size) <<  payload;
    return ss.str();
}


// Extract the request code from the request string
std::string send_the_request::extract_request_code(const std::string& request_string) {
    std::istringstream stream(request_string);
    std::string line;
    std::vector<std::string> lines;
    while (std::getline(stream, line)) {
        lines.push_back(line);
    }
    if (lines.size() >= 3) {
        // The request code is located in the third line
        return lines[2];
    }
    else {
        throw std::runtime_error("Request string does not contain enough lines.");
    }
}

// Constructor for the 'send_the_request' class
send_the_request::send_the_request(boost::asio::io_context& io) : socket(io) {}


// Sends the request to the server and handles retries in case of failure
std::string send_the_request::send_request_to_server(Request_to_server& request, send_the_request& sender) {
    
    std::string status_request = "Failed";
    // Retry counter
    uint8_t TIME = 1;


    try {
        // Load server IP and port from a file named 'transfer.info'
        std::ifstream transfer_info("transfer.info");
        std::string ip;
        std::string port;
        std::string the_first_line;
        if (transfer_info.is_open()) {
            std::getline(transfer_info, the_first_line);
            size_t pos = the_first_line.find(":");
            if (pos != std::string::npos) {
                ip = the_first_line.substr(0, pos);
                port = the_first_line.substr(pos + 1);
            }
            else {
                throw std::runtime_error("Error: transfer.info file is not in the right format");
                std::abort();
            }
            transfer_info.close();
        }
        else {
            throw std::runtime_error("Error: transfer.info file is not open");
            std::abort();
        }
        std::string the_request = request.prepare_for_sending();
        std::string code_request = extract_request_code(the_request);
        // If sending a file request (code 828), handle retries if server responds with an error
        if (code_request == "828") {
            status_request = process_request(ip, port, the_request, code_request, TIME);
            if (status_request == "Failed") {
                std::cout << "server responded with an error" << std::endl;
                TIME++;
            }
            else {
				std::cout << "The request was sent successfully" << std::endl;
				std::cout << "---------------------------------\n" << std::endl;
			}
        }
        else {
            status_request = process_request(ip, port, the_request, code_request, TIME);

            if (status_request == "Failed") {
                std::cout << "server responded with an error" << std::endl;
                TIME++;

                process_request(ip, port, the_request, code_request, TIME);
            }
			else {

				std::cout << "The request was sent successfully" << std::endl;
				std::cout << "---------------------------------\n" << std::endl;
			}

        }
       
    }
    catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
    }
    return status_request;//the response from the server

}

// General request processing method to handle communication with the server
std::string send_the_request::process_request(const std::string& ip, const std::string& port, const std::string& the_request, const std::string& code_request, const uint8_t& TIME) {
    std::string status = "Success";
    if(TIME > NUM_OF_TRIALS){
        std::cout<< "The server did not respond at the last time" << std::endl;
        // Terminate if maximum trials exceeded
		std::abort();
	}
    try {
        boost::asio::io_context io_context;
        boost::asio::ip::tcp::socket socket(io_context);
        boost::asio::ip::tcp::resolver resolver(io_context);
        auto endpoints = resolver.resolve(ip, port);
        boost::asio::connect(socket, endpoints);
        boost::asio::write(socket, boost::asio::buffer(the_request)); 
        std::string response = read_response(socket);
        status = response;
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return "Failed";
    }
    return status;
}

// Read the server's response from the socket
std::string send_the_request::read_response(boost::asio::ip::tcp::socket& socket) {
    boost::asio::streambuf response;
    boost::asio::read_until(socket, response, "\n");

    std::istream response_stream(&response);
    std::string full_response;
    std::string chunk;
    while (std::getline(response_stream, chunk)) {
        full_response += chunk + "\n"; // הוספת שורה חדשה לשמירה על הפסקאות
    }

    return full_response;
}


// Constructor for Request_to_server
Request_to_server::Request_to_server(std::string client_id, uint8_t version, uint16_t code, uint32_t payload_size, const std::string& payload)
    : client_id(client_id), version(version), code(code), payload_size(payload_size), payload(payload) {}

// Constructor for Registration
Registration::Registration(std::string client_id, uint8_t version, uint16_t code, uint32_t payload_size, const std::string& Name)
    : Request_to_server(client_id, version, code, payload_size, create_payload({ Name }, payload_size)), Name(Name) {}

std::string Registration::prepare_for_sending() {
    return Request_to_server::prepare_for_sending();
}
// Constructor for Sending_public_key
Sending_public_key::Sending_public_key(std::string client_id, uint8_t version, uint16_t code, size_t payload_size, const std::string& Name, const std::string& public_key)
    : Request_to_server(client_id, version, code, payload_size, create_payload({ Name, public_key }, payload_size)), Name(Name), public_key(public_key) {}

std::string Sending_public_key::prepare_for_sending() {
    return Request_to_server::prepare_for_sending();
}

// Constructor for login_again
login_again::login_again(std::string client_id, uint8_t version, uint16_t code, uint32_t payload_size, const std::string& Name)
    : Request_to_server(client_id, version, code, payload_size, create_payload({ Name }, payload_size)), Name(Name) {}

std::string login_again::prepare_for_sending() {
    return Request_to_server::prepare_for_sending();
}

// Constructor for Sending_file
Sending_file::Sending_file(std::string client_id, uint8_t version, uint16_t code, size_t payload_size, size_t content_size, size_t orig_file_size, const uint8_t& packet_number, const uint8_t& total_packet, const std::string& file_name, const std::string& file_content)
    : Request_to_server(client_id, version, code, payload_size, create_payload({ std::to_string(content_size),
            std::to_string(orig_file_size),std::to_string(packet_number),std::to_string(total_packet),file_name,file_content }, payload_size)),
    content_size(content_size), orig_file_size(orig_file_size), packet_number(packet_number), total_packet(total_packet), file_name(file_name), file_content(file_content) {}

std::string Sending_file::prepare_for_sending() {
    return Request_to_server::prepare_for_sending();
}

// Constructor for CRC_normal
CRC_normal::CRC_normal(
    std::string client_id, uint8_t version, uint16_t code, uint32_t payload_size, const std::string& file_name)
    : Request_to_server(client_id, version, code, payload_size, create_payload({ file_name }, payload_size)), file_name(file_name) {}

std::string CRC_normal::prepare_for_sending() {
    return Request_to_server::prepare_for_sending();
}

// Constructor for CRC_not_normal
CRC_not_normal::CRC_not_normal(std::string client_id, uint8_t version, uint16_t code, uint32_t payload_size, const std::string& file_name
) : Request_to_server(client_id, version, code, payload_size, create_payload({ file_name }, payload_size)), file_name(file_name) {}

std::string CRC_not_normal::prepare_for_sending() {
    return Request_to_server::prepare_for_sending();
}

// Constructor for CRC_end
CRC_end::CRC_end(std::string client_id, uint8_t version, uint16_t code, uint32_t payload_size, const std::string& file_name)
    : Request_to_server(client_id, version, code, payload_size, create_payload({ file_name }, payload_size)), file_name(file_name) {}

std::string CRC_end::prepare_for_sending() {
    return Request_to_server::prepare_for_sending();
}

std::string ServerResponse::create_payload(const std::vector<std::string>& fields, uint32_t payload_size) {
    std::ostringstream ss;
    if (payload_size < fields.size()) {
        std::cerr << "Error: payload_size is smaller than the number of fields" << std::endl;
        return "";
    }
    for (const auto& field : fields) {
        ss << field << "\n";
    }
    return ss.str();
}

ServerResponse::ServerResponse(uint8_t version, uint16_t code, uint32_t payload_size, const std::string& payload)
    : version(version), code(code), payload_size(payload_size), payload(payload) {}

Registration_successful::Registration_successful(uint8_t version, uint16_t code, uint32_t payload_size, const std::string& CLIENT_ID)
    : ServerResponse(version, code, payload_size, create_payload({ CLIENT_ID }, payload_size)), CLIENT_ID(CLIENT_ID) {}

Registration_failed::Registration_failed(uint8_t version, uint16_t code, uint32_t payload_size, const std::string& payload)
    : ServerResponse(version, code, payload_size, create_payload({ }, payload_size)) {}

Public_key_received_AES_sent::Public_key_received_AES_sent(uint8_t version, uint16_t code, uint32_t payload_size, const std::string& CLIENT_ID, const std::string& AES)
    : ServerResponse(version, code, payload_size, create_payload({ CLIENT_ID, AES }, payload_size)), AES(AES), CLIENT_ID(CLIENT_ID) {}

file_vlid::file_vlid(uint8_t version, uint16_t code, uint32_t payload_size, const std::string& CLIENT_ID, const std::string& CONTENT_SIZE, const std::string& FILE_NAME, const std::string& CKSUM)
    : ServerResponse(version, code, payload_size, create_payload({ CLIENT_ID, CONTENT_SIZE, FILE_NAME, CKSUM }, payload_size)), CLIENT_ID(CLIENT_ID), CONTENT_SIZE(CONTENT_SIZE), FILE_NAME(FILE_NAME), CKSUM(CKSUM) {}

Confirmation_receiving_message::Confirmation_receiving_message(uint8_t version, uint16_t code, uint32_t payload_size, const std::string& CLIENT_ID)
    : ServerResponse(version, code, payload_size, create_payload({ CLIENT_ID }, payload_size)), CLIENT_ID(CLIENT_ID) {}

reconnecting::reconnecting(uint8_t version, uint16_t code, uint32_t payload_size, const std::string& CLIENT_ID, const std::string& AES)
    : ServerResponse(version, code, payload_size, create_payload({ CLIENT_ID, AES }, payload_size)), CLIENT_ID(CLIENT_ID), AES(AES) {}

reconnecting_failled::reconnecting_failled(uint8_t version, uint16_t code, uint32_t payload_size, const std::string& CLIENT_ID)
    : ServerResponse(version, code, payload_size, create_payload({ CLIENT_ID }, payload_size)), CLIENT_ID(CLIENT_ID) {}

Error_general::Error_general(uint8_t version, uint16_t code, uint32_t payload_size, const std::string& ERROR_TEXT)
    : ServerResponse(version, code, payload_size, create_payload({ ERROR_TEXT }, payload_size)) {}

