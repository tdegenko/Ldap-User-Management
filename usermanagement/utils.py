import hashlib, binascii
import hmac
import Crypto.Hash.MD4


class LDAPUtils:
    @classmethod
    def ntlmv1(cls, pw):
        return binascii.hexlify(Crypto.Hash.MD4.MD4Hash(pw.encode("utf-16le")).digest())

    @classmethod
    def ntlmv2(cls, pw, user=None, domain=None):
        v1Hash = cls._ntlmv1(pw)
        data = (user.upper() + domain.upper()).encode("utf-16le")
        return binascii.hexlify(hmac.new(v1Hash, data).digest())
