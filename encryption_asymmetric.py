import os
import base64
import json
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA512
try:
    from encryption import Encryption
except ModuleNotFoundError:
    from token_generator.encryption import Encryption


class AsymmetricEncryption(Encryption):
    def __init__(self):
        self.private_key = None
        self.public_key = None
        self.signing_key = None
        self.verification_key = None

    def generate_key(self, strength):
        self.private_key = RSA.generate(strength)
        self.public_key = self.private_key.publickey()
        self.signing_key = PKCS1_v1_5.new(rsa_key=self.private_key)
        self.verification_key = PKCS1_v1_5.new(rsa_key=self.public_key)
        return self.public_key, self.private_key

    def load_keypair(self, path):
        self.__check_dir(path)
        self.private_key = RSA.import_key(self.__read_key(f'{path}/private_key.pem'))
        self.public_key = RSA.import_key(self.__read_key(f'{path}/public_key.pem'))
        self.signing_key = PKCS1_v1_5.new(rsa_key=self.private_key)
        self.verification_key = PKCS1_v1_5.new(rsa_key=self.public_key)

    def load_private_key(self, path):
        if os.path.isfile(path):
            self.private_key = RSA.import_key(self.__read_key(path))
        else:
            self.private_key = RSA.import_key(path)
        self.signing_key = PKCS1_v1_5.new(rsa_key=self.private_key)

    def load_public_key(self, path):
        if os.path.isfile(path):
            self.public_key = RSA.import_key(self.__read_key(path))
        else:
            self.public_key = RSA.import_key(path)
        self.verification_key = PKCS1_v1_5.new(rsa_key=self.public_key)

    def save_keypair(self, path):
        self.__check_public_key()
        self.__check_private_key()
        self.__check_dir(path)
        private_key = self.__save_key(self.private_key.export_key().decode(), f'{path}/private_key.pem')
        public_key = self.__save_key(self.public_key.export_key().decode(), f'{path}/public_key.pem')
        return public_key, private_key

    def save_private_key(self, path):
        self.__check_private_key()
        return self.__save_key(self.private_key.export_key().decode(), f'{path}/private_key.pem')

    def save_public_key(self, path):
        self.__check_public_key()
        return self.__save_key(self.public_key.export_key().decode(), f'{path}/public_key.pem')

    def encrypt(self, data):
        self.__check_public_key()
        cipher = PKCS1_OAEP.new(key=self.public_key)
        if isinstance(data, dict):
            encrypted = cipher.encrypt(json.dumps(data).encode('utf-8'))
        elif isinstance(data, str):
            encrypted = cipher.encrypt(data.encode('utf-8'))
        else:
            raise ValueError('Data type not supported!')
        return base64.b64encode(encrypted).decode('utf-8')

    def decrypt(self, data):
        self.__check_private_key()
        decipher = PKCS1_OAEP.new(key=self.private_key)
        _data = base64.b64decode(data.encode('utf-8'))
        decrypted = decipher.decrypt(_data)
        return decrypted.decode('utf-8')

    def sign(self, data):
        self.__check_signing_key()
        if isinstance(data, dict):
            _hash = SHA512.new(json.dumps(data).encode('utf-8'))
        elif isinstance(data, str):
            _hash = SHA512.new(data.encode('utf-8'))
        else:
            raise ValueError('Data type not supported!')
        signature = self.signing_key.sign(_hash)
        return base64.b64encode(signature).decode('utf-8')

    def verify_signature(self, data, signature):
        self.__check_verification_key()
        _hash = SHA512.new(data.encode('utf-8'))
        _signature = base64.b64decode(signature.encode('utf-8'))
        return self.verification_key.verify(_hash, _signature)

    def __check_dir(self, path):
        if not os.path.isdir(path):
            raise NotADirectoryError(f'Not a directory: {path}')

    def __check_public_key(self):
        if not self.public_key:
            raise FileNotFoundError('Create/load public key before using this method.')

    def __check_private_key(self):
        if not self.private_key:
            raise FileNotFoundError('Create/load private key before using this method.')

    def __check_signing_key(self):
        if not self.signing_key:
            raise FileNotFoundError('Create/load private key before using this method.')

    def __check_verification_key(self):
        if not self.verification_key:
            raise FileNotFoundError('Create/load private key before using this method.')

    def __save_key(self, pem, path):
        try:
            with open(path, 'w') as file:
                file.write(pem)
                return path
        except OSError as error:
            raise FileNotFoundError(f'Failed to save key: {error}')

    def __read_key(self, path):
        try:
            with open(path, 'r') as file:
                return file.read()
        except OSError as error:
            raise FileNotFoundError(f'Failed to read key: {error}')
