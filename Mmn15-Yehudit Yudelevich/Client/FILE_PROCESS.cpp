#include "FILE_PROCESS.H"


std::string FileUtil::get_path_to_file() {
    std::string path;
    std::string line;
    // Open the transfer.info file
    std::ifstream file("transfer.info");
    if (file.is_open()) {
        // Skip the first two lines and get the third line (the file path)
        std::getline(file, line);
        std::getline(file, line);
        std::getline(file, path);
        file.close();
    }
    else {
        // Throw an exception if the file cannot be opened
        throw std::runtime_error("\nError opening transfer.info\n");
    }
    return path;
}

std::string FileUtil::get_file_content(std::string file_path) {
    std::string content;
    // Open the file in binary mode
    std::ifstream file(file_path, std::ios::binary);
    if (file.is_open()) {
        std::stringstream buffer;
        // Read the entire file content into the stringstream
        buffer << file.rdbuf(); 
        content = buffer.str();
        file.close();
    }
    else {
        // Throw an exception if the file cannot be opened
        throw std::runtime_error("\nError opening file\n");
    }
    return content;
}
std::string FileUtil::get_file_name(std::string file_path) {
	std::string file_name;
    // Find the last occurrence of '/'
	size_t last_slash = file_path.find_last_of('/');
    // Extract the file name after the last slash
	if (last_slash != std::string::npos) {
		file_name = file_path.substr(last_slash + 1);
	}
	else {
        // If no slash, the entire path 
		file_name = file_path;
	}
	return file_name;
}