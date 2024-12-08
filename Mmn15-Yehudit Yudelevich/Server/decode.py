import os
#generate_unique_id function that generates a unique id for the client 
def generate_unique_id():
    random_bytes = os.urandom(16)
    hex_representation = ''.join([f'{byte:02x}' for byte in random_bytes])
    
    return hex_representation
