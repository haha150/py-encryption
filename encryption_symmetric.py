import base64
import json
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from encryption import Encryption


class SymmetricEncryption(Encryption):
    def __init__(self):
        self.key = None
        self.session_key = None
        self.nonce = None

    def generate_key(self, strength):
        self.session_key = get_random_bytes(strength)
        self.key = AES.new(self.session_key, AES.MODE_EAX)
        self.nonce = self.key.nonce
        return self.key, base64.b64encode(self.session_key).decode('utf-8'), base64.b64encode(self.nonce).decode('utf-8')

    def load_key(self, session_key, nonce):
        self.session_key = base64.b64decode(session_key.encode('utf-8'))
        self.nonce = base64.b64decode(nonce.encode('utf-8'))
        self.key = AES.new(self.session_key, AES.MODE_EAX, nonce=self.nonce)

    def save_key(self, path):
        raise NotImplementedError

    def encrypt(self, data):
        self.__check_key()
        if isinstance(data, dict):
            encrypted, tag = self.key.encrypt_and_digest(json.dumps(data).encode('utf-8'))
        elif isinstance(data, str):
            encrypted, tag = self.key.encrypt_and_digest(data.encode('utf-8'))
        else:
            raise ValueError('Data type not supported!')
        return base64.b64encode(encrypted).decode('utf-8'), base64.b64encode(tag).decode('utf-8')

    def decrypt(self, data, tag):
        self.__check_key()
        cipher = AES.new(self.session_key, AES.MODE_EAX, self.nonce)
        _data = base64.b64decode(data.encode('utf-8'))
        _tag = base64.b64decode(tag.encode('utf-8'))
        decrypted = cipher.decrypt_and_verify(_data, _tag)
        return decrypted.decode('utf-8')

    def __check_key(self):
        if not self.key:
            raise FileNotFoundError('Create/load public key before using this method.')
