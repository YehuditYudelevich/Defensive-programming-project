import socket
import selectors
from protocol import * 
import logging
import uuid
from AES import *
from decode import *
import os
from CRC import *
import re
from datetime import datetime
logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger()
MAX_LENGTH = 1024
SERVER_VERSION = 3
DEFAULT_PORT = 1256  
HEADER = 42
SIZE_OF_ID = 16
SIZE_OF_VERSION = 1
SIZE_OF_CODE = 4
SIZE_OF_PAYLOAD_SIZE = 4
SIZE_OF_CLIENT_NAME = 255
SIZE_OF_FILE_NAME = 255
SIZE_OF_PUBLIC_KEY_AND_NAME = 416
SIZE_OF_ACCEPTED_FILE = 3000


class Server:
    def __init__(self):
        self.sel = selectors.DefaultSelector()
    
    @staticmethod
    #function that reads the port from the file
    def read_the_port():
        try:
            with open("port.info", "r") as file:
                port = int(file.read())  
        except FileNotFoundError:
            print("Invalid port number in port.info, using default port.")
            port = DEFAULT_PORT
        except ValueError:
            print("Invalid port number in port.info, using default port.")
            port = DEFAULT_PORT
        return port

    #function that accepts the login of the client
    def accept_login(self,conn: socket.socket) -> str:
        print("----------------------------------\n")
        print("started accept login")
        data = conn.recv(SIZE_OF_CLIENT_NAME)
        if not data:
            print("No data received from client.")
            return None
        print("generating unique id for the client")
        client_id = generate_unique_id()
        reg_succ = Registration_successful(client_id)
        packed_data = reg_succ.pack()
        version = packed_data[0]
        code = int.from_bytes(packed_data[1:3], byteorder='little')
        payload_size = int.from_bytes(packed_data[3:7], byteorder='little')
        
        string_answer=handle_the_answer(version, code, payload_size, client_id, None, None, None, None)
        print("Sending a registration confirmation from the server to the client.\n")
        print("----------------------------------\n")
        conn.sendall(string_answer.encode('utf-8'))
        return client_id

    #function that saves the AES key in the client folder
    def save_AES_key(self,client_id:str,AES):
        #decode the client_id from bytes to str
        if isinstance(client_id, bytes):
            client_id = client_id.decode('utf-8')
        directory = client_id
        #create the directory if it does not exist
        if not os.path.exists(directory):
            os.makedirs(directory)
        file_path = os.path.join(directory, 'AES_key')
        with open(file_path, 'wb') as file:
            file.write(AES)
        print(f'AES key was created in folder {client_id}')

    #function that accepts the public key from the client
    def accept_public_key(self,client_id:str,conn: socket.socket)->str:
        print("----------------------------------\n")
        print("started accept public key ")
        data=conn.recv(SIZE_OF_PUBLIC_KEY_AND_NAME)
        if not data:
            raise ValueError("No data received from client.")
        name=data[0:255]
        public_key=data[256:]
        data = data.split(b'\n')
        if public_key[0] == 0x00:
            public_key = public_key[1:]
        self.save_public_key(client_id,public_key)
        print("----------------------------------\n")
        
    
        print("generating AES key for the client\n")
        print("move to save AES key in the client folder\n")
        #generate the AES key
        AES=create_aes_key()
        self.save_AES_key(client_id, AES)
        print("move to encode the AES key with the public key\n")
        #encrypt the AES key with the public key
        AES_ENCRYPTED=encrypt_with_RSA(public_key,AES)
        print("the AES key was encrypted with the public key\n")
        pub_rec= Public_key_received_AES_sent( client_id,AES_ENCRYPTED)
        packed_data = pub_rec.pack()
        version = packed_data[0]
        code = int.from_bytes(packed_data[1:3], byteorder='little')
        payload_size = int.from_bytes(packed_data[3:7], byteorder='little')
        client_id, aes_key = pub_rec.unpack_payload()
        string_answer=handle_the_answer(version, code, payload_size, client_id, None, None, None, None)
        print("sending the AES key to the client\n")
        print("---------------------------------------------\n")
        conn.sendall(string_answer.encode('utf-8')+aes_key)
        return aes_key

    #function that saves the public key in the client folder
    def save_public_key(self,client_id,public_key):
        #decode the client_id from bytes to str
        client_id = client_id.decode('utf-8')
        directory = client_id
        #create the directory if it does not exist
        if not os.path.exists(directory):
            os.makedirs(directory)
        #create the file path
        file_path = os.path.join(directory, "public_key")
        with open(file_path, 'wb') as file:
            file.write(public_key)
        print("----------------------------------\n")

    #function that imports the public key from the client folder
    def import_public_key(self,client_id):
        print("started import public key")
        #decode the client_id from bytes to str
        client_id = client_id.decode('utf-8')
        directory = client_id
        #create the directory if it does not exist
        file_path = os.path.join(directory, "public_key")
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"The public key file does not exist in the folder: {directory}")
        with open(file_path, 'rb') as file:
            public_key = file.read()
        print("public key was imported from the client folder\n")
        print("----------------------------------\n")
        return public_key

    #function that validates the file
    def accept_file(self,client_id:str,version,code,payload_size,  conn: socket.socket)->str:
        print("----------------------------------\n")
        print("started accept file")
        data=conn.recv(SIZE_OF_ACCEPTED_FILE)
        if not data:
            raise ValueError("No data received from client.")
        #process the data that was received from the client to extract the content size, org size, current packet number, total packets, file name and file content
        data_process = data.split(b'\n')
        content_size = data_process[0]
        org_size = data_process[1]
        current_packet_number = data_process[2]
        total_packets = data_process[3]
        file_name = data_process[4]
        the_length_till_content = len(content_size) + len(org_size) + len(current_packet_number) + len(total_packets) + len(file_name) + 5
        file_content = data[the_length_till_content:]
        #check if the file content ends with a new line
        if file_content.endswith(b'\n'):
            file_content = file_content[:-1]
        print(f"packet number {current_packet_number} out of {total_packets} accepted")
        #write the file before decrypted
        write_the_file_before_decrepted(client_id,file_name,file_content)

        #check if the total packets is equal to the current packet number
        if total_packets==current_packet_number:
            print("The file was received successfully")
            client_id = client_id.decode('utf-8')
            file_after_decode=decoding_the_file(client_id,file_name)
            print("-------------------------------------------------------\n")
        
            file_after_decode1 = file_after_decode.encode('utf-8')
            cksum=memcrc(file_after_decode1)
            print("calculated checksum of the content file...")
            #write the file after decrypted
            write_the_file(client_id,file_name,file_after_decode)
            file_ok =file_vlid(client_id,org_size,file_name,cksum)
            packed_data = file_ok.pack()
            #extract the version, code and payload size from the packed data
            string_answer=handle_the_answer(3, 1603, payload_size, client_id, None, content_size, file_name, cksum)
            #send the file validation request to the client
            print("sending the file validation request to the client\n")
            print("-------------------------------------------------------\n")
            conn.sendall(string_answer.encode('utf-8'))

 
    def reconnecting(self,client_id,conn: socket.socket):
        print("----------------------------------\n")
        print("started reconnecting")
        data=conn.recv(SIZE_OF_CLIENT_NAME)
        if not data:
            raise ValueError("No data received from client.")
        print("move to generate the AES key\n")
        #generate the AES key
        AES=create_aes_key()
        #save the AES key in the client folder
        self.save_AES_key(client_id, AES)
        #import the public key from the client folder
        print("move to import the public key from the client folder\n")
        public_key=self.import_public_key(client_id)
        print("move to encode the AES key with the public key\n")
        AES_ENCRYPTED=encrypt_with_RSA(public_key,AES)
        #send the AES key to the client
        reconnecting_obj = reconnecting(client_id, AES_ENCRYPTED)

        client_id, aes_key = reconnecting_obj.unpack_payload()
        print("sending the AES key to the client\n")
        print("-------------------------------------------------------\n")
        #send the AES key to the client
        string_answer=handle_the_answer(3, 1604, 144, client_id, None, None, None, None)
        conn.sendall(string_answer.encode('utf-8') + AES_ENCRYPTED)

        

    
    #function that accepts the CRC normal
    def accept_crc_ok(self,client_id,conn: socket.socket):
        print("----------------------------------\n")
        print("started accept crc ok")
        data=conn.recv(SIZE_OF_FILE_NAME)
        if not data:
            raise ValueError("No data received from client.")
        print("CRC, OK received, a confirmation message is sent to the client\n")
        string_answer=handle_the_answer(3, 1605, 144, client_id, None, None, None, None)
        conn.sendall(string_answer.encode('utf-8'))

    #function that accepts the CRC not normal
    def accept_crc_error(self,client_id,conn: socket.socket):
        print("----------------------------------\n")
        print("started accept crc error")
        data=conn.recv(SIZE_OF_FILE_NAME)
        if not data:
            raise ValueError("No data received from client.")
        print("Invalid CRC, a send confirmation message was sent to the client")
        string_answer=handle_the_answer(3, 1604, 144, client_id, None, None, None, None)
        conn.sendall(string_answer.encode('utf-8'))

    #function that accepts the CRC end
    def accept_crc_end(self,client_id,conn: socket.socket):
        print("----------------------------------\n")
        print("started accept crc end")
        data=conn.recv(SIZE_OF_FILE_NAME)
        if not data:
            raise ValueError("No data received from client.")
        print("Invalid CRC at the end, a send confirmation message was sent to the client")
        string_answer=handle_the_answer(3, 1606, 144, client_id, None, None, None, None)
        conn.sendall(string_answer.encode('utf-8'))

    #function that starts the server
    def start(self,conn: socket.socket):
        try:
            data = conn.recv(HEADER)
            if not data:
                raise ValueError("No data received from client.")
            data=data.split(b'\n')
            client_id = data[0]
            client_version = data[1]
            client_code = data[2]
            client_code = client_code.decode('utf-8').strip()
            client_payload_size = data[3]
          
            #check the client code and call the appropriate function
            if client_code==request_from_client.Registration.value or client_code=="825":
                self.accept_login(conn)
            elif client_code==request_from_client.Sending_public_key.value or client_code=="826":
                self.accept_public_key(client_id,conn)
            elif client_code==request_from_client.Sending_file.value or client_code=="828": 
                self.accept_file(client_id,client_version,client_code,client_payload_size,conn)
            elif client_code==request_from_client.Login_again.value or client_code=="827":
                self.reconnecting(client_id,conn)
            elif client_code==request_from_client.CRC_normal.value or client_code=="900":
                self.accept_crc_ok(client_id,conn)
            elif client_code==request_from_client.CRC_not_normal.value or client_code=="901":
                self.accept_crc_error(client_id,conn)
            elif client_code==request_from_client.CRC_end.value or client_code=="902":
                self.accept_crc_end(client_id,conn)
            else:
                print("One of the clients left the service") 
                print('closing', conn)
                self.sel.unregister(conn)    
                conn.close()
        except Exception as e:
            print("Error occurred:", e)
        finally:
            print('closing', conn)
        try:
            #check if the connection is still open and close it
            if conn.fileno() != -1:
                self.sel.unregister(conn)  
        except KeyError:
            pass  
        except ValueError:
            pass  
        conn.close()



#function that writes the file before decrypted
def write_the_file_before_decrepted(client_id: bytes, file_name: bytes, file_content):

    #decode the client_id and file_name from bytes to str
    if isinstance(client_id, bytes):
        client_id = client_id.decode('utf-8')
    if isinstance(file_name, bytes):
        file_name = file_name.decode('utf-8')
    file_name = file_name.replace('\0', '') 
    #create the directory if it does not exist
    if not os.path.exists(client_id):
        os.makedirs(client_id)
    #create the file path
    file_path = os.path.join(client_id, file_name)
    #write the file
    with open(file_path, 'wb') as file: 
        file.write(file_content)  
    
   



#function that writes the decrypted file
def write_the_file(client_id, file_name, file_content):
    #decode the client_id and file_name from bytes to str
    file_name = file_name.decode('utf-8')
    file_name = file_name.replace('\0', '')
    directory = client_id
    #create the directory if it does not exist
    if not os.path.exists(directory):
        os.makedirs(directory)
    #create the file path
    file_path = os.path.join(directory, file_name)
    with open(file_path, 'w', encoding='utf-8') as file:  
        file.write(file_content)
    


#function that export the AES key from the client folder
def access_AES_key(client_id: str) -> bytes:
    print("started access_AES_key")
    # Ensure client_id is a string
    if isinstance(client_id, bytes):
        client_id = client_id.decode('utf-8')
    file_path = os.path.join(client_id, 'AES_key')
    with open(file_path, 'rb') as file:
        AES_key = file.read()
    return AES_key

#function that decrypt the file
def decoding_the_file(client_id, file_name) -> str:
    AES=access_AES_key(client_id)
    print("started decoding_the_file")
    if isinstance(client_id, bytes):
        client_id = client_id.decode('utf-8')
        
    if isinstance(file_name, bytes):
        file_name = file_name.decode('utf-8')
        file_name = file_name.replace('\0', '')
    #create the file path
    file_path = os.path.join(client_id, file_name)
    with open(file_path, 'rb') as file:
        file_content = file.read()
        file_content = decrypt_aes(file_content, AES)
        file_content = file_content.decode('utf-8')
    return file_content

#function that handles the answer to the client
def handle_the_answer(version, code, payload_size, client_id,AES_key,content_size,file_name,cksum)->str:
    the_answer=[]
    the_answer.append(version)
    the_answer.append(code)
    the_answer.append(payload_size)
    the_answer.append(client_id)
    if AES_key:
        the_answer.append(AES_key)
    if content_size:
        the_answer.append(content_size)
    if file_name:
        the_answer.append(file_name)
    if cksum:
        the_answer.append(cksum)
    string_answer = " ".join(map(str, the_answer))
    string_answer += '\n'
    return string_answer


   



def main():
    #read the port from the file
    port = Server.read_the_port()
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('127.0.0.1', port))
    server_socket.listen()
    print(f"Server listening on port {port}...")
    #create an instance of the server
    server_instance = Server()

    while True:
        #accept the connection
        client_socket, address = server_socket.accept()
        #register the client socket to the selector
        server_instance.sel.register(client_socket, selectors.EVENT_READ) 
        #start
        server_instance.start(client_socket)
        client_socket.close()


if __name__ == '__main__':
    main()
   


