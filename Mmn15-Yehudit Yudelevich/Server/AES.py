from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import unpad, pad
import secrets
SIZE_OF_AES_KEY=32

# Encrypt the plaintext using the AES key.
def encrypt_with_RSA(public_key, aes_key: bytes):
    try:
        # Import the RSA public key.
        rsa_key = RSA.import_key(public_key)
        # Encrypt the AES key with the RSA public key.
        encryption = PKCS1_OAEP.new(rsa_key)
        # Encrypt the AES key using the RSA public key.
        encrypted_key = encryption.encrypt(aes_key)
        return encrypted_key

    except ValueError as e:
        print(f"RSA key format is not supported: {e}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None

 # Generate a random AES key.   
def create_aes_key()->bytes:
    # Generate a random AES key using the secrets module.
    aes_key = secrets.token_bytes(SIZE_OF_AES_KEY)
    return aes_key


# Encrypt the plaintext using the AES key.
def decrypt_aes(ciphertext: str, key: bytes)->bytes:
    # Create a new AES cipher in CBC mode with a zeroed IV (for simplicity).
    cipher = AES.new(key, AES.MODE_CBC, bytes(AES.block_size))
    # Decrypt the ciphertext and remove the padding.
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext


