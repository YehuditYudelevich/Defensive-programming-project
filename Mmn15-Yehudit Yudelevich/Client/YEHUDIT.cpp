#include "RSA.cpp"
#include "client.cpp"




int main() {
	std::cout << "-----------------------------------------------" << std::endl;
	std::cout << " The client started..." << std::endl;
	std::cout << "-----------------------------------------------" << std::endl;

	Client client;
	try {
		if (!client.file_exists("me.info")) {

			client.read_transfer_file();
			client.send_registration_request();
			std::string public_key;
			std::cout << "move to generate RSA key\n";
			public_key = generate_RSA_key();

			client.send_public_key(public_key);
			std::cout << "finish to send public key and accept the aes\n" << std::endl;
		}
		else {
			std::cout << "the file me.info already exists we movw to reconnect\n";
			client.read_me_file();
			client.send_recconected();

		}
		
		std::cout << "-----------------------------------------------" << std::endl;
		client.send_file();



	}
	catch (std::exception& e) {
		std::cerr << "Exception in main: " << e.what() << std::endl;
	}
	return 0;
}

