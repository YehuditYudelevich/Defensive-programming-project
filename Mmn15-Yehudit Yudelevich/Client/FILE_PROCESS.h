#pragma once

#include <string>
#include <fstream>
#include <iostream>
#include <sstream>



class FileUtil {
public:
	/**
	 * @brief Retrieves the file path from the "transfer.info" file.
	 * This function reads the "transfer.info" file and extracts the path to the file
	 * that needs to be processed. It reads the first two lines and returns the third line,
	 * which contains the file path.
	 * @return std::string The path to the file.
	 * @throws std::runtime_error If the "transfer.info" file cannot be opened.
	 */
	static std::string get_path_to_file();

	/**
	 * @brief Reads the content of the specified file and returns it as a string.
	 * This function opens the file at the specified path in binary mode and reads its
	 * entire content into a string. It uses a stringstream to handle the reading.
	 * @param file_path The path to the file to read.
	 * @return std::string The file content.
	 * @throws std::runtime_error If the file cannot be opened.
	 */
	static std::string get_file_content(std::string file_path);

	/**
	 * @brief Extracts the file name from the given file path.
	 * This function takes a file path and returns the file name by finding the last
	 * occurrence of a '/' character (indicating a directory) and returning everything
	 * after it. If no '/' is found, the full file path is returned.
	 * @param file_path The full path to the file.
	 * @return std::string The file name extracted from the path.
	 */
	static std::string get_file_name(std::string file_path);
	
};