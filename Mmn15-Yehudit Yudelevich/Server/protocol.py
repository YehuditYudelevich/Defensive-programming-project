import struct
from enum import Enum

SERVER_VERSION = 3
SIZE_OF_HEADER = 7
SIZE_OF_CLIENTID = 16
SIZE_OF_FILE_NAME = 255
SIZE_OF_CKSUM = 4
SIZE_OF_PUBLIC_KEY = 160
CONTENT_SIZE=1024
# Enum representing different request types from the server
class request_from_server(Enum):
    Registration_successful = 1600
    Registration_failed = 1601
    Public_key_received_AES_sent = 1602
    file_vlid = 1603
    Confirmation_receiving_message = 1604
    reconnecting = 1605
    reconnecting_failled = 1606
    Error = 1607
# Enum representing different request types from the client
class request_from_client(Enum):
    Registration = "825"
    Sending_public_key = "826"
    Login_again = "827"
    Sending_file = "828"
    CRC_normal = "900"
    CRC_not_normal = "901"
    CRC_end = "902"

HEADER_STRUCTURE = '<BHI'
# Class for the header, containing version, code, and payload size
class Header:
    def __init__(self, version, code, payload_size):
        self.version = int(version)
        self.code = int(code)
        self.payload_size = int(payload_size)
     # Pack the header into binary format
    def pack(self):
        return struct.pack(HEADER_STRUCTURE, self.version, self.code, self.payload_size)
# Base class for request handling, each request has a header and payload
class Request:
    def __init__(self, header, payload):
        self.header = header
        self.payload = payload
    # Pack the request (pack the header only here, overridden in subclasses for full packing)
    def pack(self):
        return self.header.pack()
# Registration success request  
class Registration_successful(Request):
    def __init__(self, client_id):
         # Create a header for the successful registration
        header = Header(SERVER_VERSION, request_from_server.Registration_successful.value, SIZE_OF_CLIENTID)
        self.client_id = client_id
        super().__init__(header, client_id)  # Empty payload, as client_id is handled in pack()
     # Pack the request by combining the header and the client ID
    def pack(self):
        return self.header.pack() + self.client_id.encode('utf-8')

# Registration failed request
class Registration_failed(Request):
    def __init__(self, error_message):
        # Create a header with the error message length as payload size
        header = Header(SERVER_VERSION, request_from_server.Registration_failed.value, len(error_message))
        super().__init__(header, error_message)
    # Pack the header and error message together
    def pack(self):
        return self.header.pack() + self.payload.encode('utf-8')

# Public key received and AES sent request 
class Public_key_received_AES_sent(Request):
    def __init__(self, client_id, AES_key):
        # Ensure client ID is exactly 16 bytes, pad or truncate as necessary
        if len(client_id) > SIZE_OF_CLIENTID:
            client_id = client_id[:SIZE_OF_CLIENTID]
        else:
            client_id = client_id.ljust(SIZE_OF_CLIENTID, '\x00')  
        
         # Combine client ID and AES key as the payload
        payload = client_id + AES_key
        header = Header(SERVER_VERSION, request_from_server.Public_key_received_AES_sent.value, len(payload))
        super().__init__(header, payload)

    def pack(self):
        # Pack the request by combining the header and payload
        return self.header.pack() + self.payload

    # Unpack the payload to extract client ID and AES key
    def unpack_payload(self):
        client_id = self.payload[:SIZE_OF_CLIENTID].decode('utf-8').rstrip('\x00')  # הסרת רווחים מיותרים
        aes_key = self.payload[SIZE_OF_CLIENTID:]
        return client_id, aes_key

# File validation request
class file_vlid(Request):
    def __init__(self, client_id, content_size, file_name, cksum):
        # Ensure the client ID is encoded properly
        if isinstance(client_id, bytes):
            client_id_bytes = client_id
        else:
            client_id_bytes = client_id.encode('utf-8')
        # Convert content size to integer if necessary
        if isinstance(content_size, bytes):
            content_size = int.from_bytes(content_size, byteorder='little')
        
        # Ensure the file name is encoded properly
        if isinstance(file_name, bytes):
            file_name_bytes = file_name
        else:
            file_name_bytes = file_name.encode('utf-8')
        # Ensure checksum is encoded properly
        if isinstance(cksum, int):
            cksum_bytes = cksum.to_bytes(SIZE_OF_CKSUM, byteorder='little', signed=False)
        else:
            cksum_bytes = cksum
        
        # Create the payload by combining client ID, content size, file name, and checksum
        payload = client_id_bytes.ljust(SIZE_OF_CLIENTID, b'\0') + \
                  content_size.to_bytes(4, byteorder='little') + \
                  file_name_bytes.ljust(SIZE_OF_FILE_NAME, b'\0') + \
                  cksum_bytes.ljust(SIZE_OF_CKSUM, b'\0')

        # Create the header for the file validation request
        header = Header(SERVER_VERSION, request_from_server.file_vlid.value, len(payload))

        # Call the base class constructor with header and payload
        super().__init__(header, payload)

    # Pack the request by combining the packed header and payload
    def pack(self):
        return super().pack() + self.payload
    
    # Unpack the payload to extract client ID, content size, file name, and checksum
    def unpack_payload(self):
        client_id = self.payload[:SIZE_OF_CLIENTID].decode('utf-8').rstrip('\x00')
        content_size = int.from_bytes(self.payload[SIZE_OF_CLIENTID:SIZE_OF_CLIENTID+4], byteorder='little')
        file_name = self.payload[SIZE_OF_CLIENTID+4:SIZE_OF_CLIENTID+4+SIZE_OF_FILE_NAME].decode('utf-8').rstrip('\x00')
        cksum = int.from_bytes(self.payload[SIZE_OF_CLIENTID+4+SIZE_OF_FILE_NAME:SIZE_OF_CLIENTID+4+SIZE_OF_FILE_NAME+SIZE_OF_CKSUM], byteorder='little')
        return client_id, content_size, file_name, cksum
    
# Confirmation receiving message request      
class Confirmation_receiving_message(Request):
    def __init__(self,client_id):
        header=Header(SERVER_VERSION,request_from_server.Confirmation_receiving_message,SIZE_OF_CLIENTID)
        super().__init__(header,client_id)
     # Pack the request by padding the client ID to 16 bytes and combining with the header
    def pack(self):
        return super().pack()+self.client_id.encode('utf-8').ljust(SIZE_OF_CLIENTID,b'\0')

# Reconnecting request
class reconnecting(Request):
    def __init__(self,client_id,AES_key):
         # Create header for reconnecting
        header=Header(SERVER_VERSION,request_from_server.reconnecting.value,len(AES_key)+SIZE_OF_CLIENTID)
        self.client_id = client_id
        self.AES_key = AES_key
        super().__init__(header,client_id)
    
    # Pack the request by combining the client ID and AES key with the header
    def pack(self):
        return super().pack()+self.client_id.encode('utf-8')+self.AES_key
    # Unpack the payload to extract client ID and AES key
    def unpack_payload(self):
        client_id = self.payload[:SIZE_OF_CLIENTID]
        AES_key = self.payload[SIZE_OF_CLIENTID:]
        return client_id, AES_key

# Reconnecting failed request 
class reconnecting_failled(Request):
    def __init__(self):
        # Create header for failed reconnect
        header=Header(SERVER_VERSION,request_from_server.reconnecting_failled,0)
        super().__init__(header,b' error')
    def pack(self):
        return super().pack()
# Error request
class Error(Request):
    def __init__(self):
        header=Header(SERVER_VERSION,request_from_server.Error,0)
        super().__init__(header,b' error')
    def pack(self):
        return super().pack()
# Function to remove padding (null bytes) from the data
def remove_padding(data: bytes)->bytes:
    end_of_info = data.find(b'\0')
    return data[:end_of_info] 

