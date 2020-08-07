from abc import ABC, abstractmethod


class Encryption(ABC):

    @abstractmethod
    def generate_key(self, strength):
        raise NotImplementedError

    @abstractmethod
    def encrypt(self, data):
        raise NotImplementedError

    @abstractmethod
    def decrypt(self, data):
        raise NotImplementedError
