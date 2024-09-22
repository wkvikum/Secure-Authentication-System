
from Crypto.Cipher import DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode
from Crypto.Hash import SHA256

class KeyFactory:

    @staticmethod
    def encrypt_message(message, public_key_path):
        with open(public_key_path, "rb") as pub_file:
            public_key = RSA.import_key(pub_file.read())

        des_key = get_random_bytes(8)  # DES requires an 8-byte key
        cipher_des = DES.new(des_key, DES.MODE_EAX)
        ciphertext, tag = cipher_des.encrypt_and_digest(message.encode('utf-8'))

        cipher_rsa = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)
        enc_des_key = cipher_rsa.encrypt(des_key)

        return {
            'enc_des_key': b64encode(enc_des_key).decode('utf-8'),
            'nonce': b64encode(cipher_des.nonce).decode('utf-8'),
            'ciphertext': b64encode(ciphertext).decode('utf-8'),
            'tag': b64encode(tag).decode('utf-8')
        }

    @staticmethod
    def decrypt_message(encrypted_data, private_key_path):
        with open(private_key_path, "rb") as priv_file:
            private_key = RSA.import_key(priv_file.read())

        enc_des_key = b64decode(encrypted_data['enc_des_key'])
        nonce = b64decode(encrypted_data['nonce'])
        ciphertext = b64decode(encrypted_data['ciphertext'])
        tag = b64decode(encrypted_data['tag'])

        cipher_rsa = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
        des_key = cipher_rsa.decrypt(enc_des_key)

        cipher_des = DES.new(des_key, DES.MODE_EAX, nonce=nonce)
        decrypted_message = cipher_des.decrypt_and_verify(ciphertext, tag).decode('utf-8')

        return decrypted_message

if __name__ == "__main__":
    public_key_path = "public_key.pem"
    private_key_path = "private_key.pem"
    message = "This is a test message."

    encrypted_data = KeyFactory.encrypt_message(message, public_key_path)
    print(f"Encrypted Data: {encrypted_data}")

    decrypted_message = KeyFactory.decrypt_message(encrypted_data, private_key_path)
    print(f"Decrypted Message: {decrypted_message}")
