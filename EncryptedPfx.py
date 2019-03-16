from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.kbkdf import (
    CounterLocation, KBKDFHMAC, Mode,
)
from pyasn1.type.univ import ObjectIdentifier, OctetString
from pyasn1.codec.der.decoder import decode as der_decode
from pyasn1.codec.der.encoder import encode
from utils import die, new_guid
import sys
import struct


class EncryptedPFX():
    def __init__(self, blob_path, key_path, debug=False):
        self.pfx_path = blob_path
        self.DEBUG = debug
        with open(key_path, 'rb') as infile:
            self.decryption_key = infile.read()
        with open(self.pfx_path, 'rb') as infile:
            self._raw = infile.read()
        self.decode()

    def decrypt_pfx(self):
        self._derive_keys(self.decryption_key)
        self._verify_ciphertext()

        backend = default_backend()
        iv = self.iv.asOctets()
        cipher = Cipher(algorithms.AES(self.encryption_key), modes.CBC(iv), backend=backend)
        decryptor = cipher.decryptor()
        plain_pfx = decryptor.update(self.ciphertext) + decryptor.finalize()

        if self.DEBUG:
            sys.stderr.write("Decrypted PFX: {0}\n".format(plain_pfx))
        return plain_pfx

    def _verify_ciphertext(self):
        backend = default_backend()
        h = hmac.HMAC(self.mac_key, hashes.SHA256(), backend=backend)
        stream = self.iv.asOctets() + self.ciphertext
        h.update(stream)
        mac_code = h.finalize()

        if mac_code != self.mac:
            sys.stderr.write("Calculated MAC did not match anticipated MAC\n")
            sys.stderr.write("Calculated MAC: {0}\n".format(mac_code))
            sys.stderr.write("Expected MAC: {0}\n".format(self.mac))
            die()
        if self.DEBUG:
            sys.stderr.write("MAC Calculated over IV and Ciphertext: {0}\n".format(mac_code))

    def _derive_keys(self, password=None):
        label = encode(self.encryption_oid) + encode(self.mac_oid)
        context = self.nonce.asOctets()
        backend = default_backend()

        kdf = KBKDFHMAC(
            algorithm=hashes.SHA256(),
            mode=Mode.CounterMode,
            length=48,
            rlen=4,
            llen=4,
            location=CounterLocation.BeforeFixed,
            label=label,
            context=context,
            fixed=None,
            backend=backend
        )

        key = kdf.derive(password)
        if self.DEBUG:
            sys.stderr.write("Derived key: {0}\n".format(key))

        self.encryption_key = key[0:16]
        self.mac_key = key[16:]

    def _decode_octet_string(self, remains=None):
        if remains:
            buff = remains
        else:
            buff = self._raw[8:]
        octet_string, remains = der_decode(buff, OctetString())

        return octet_string, remains

    def _decode_length(self, buff):
        bytes_read = 1
        length_initial = buff[0]
        if length_initial < 127:
            length = length_initial

        else:
            length_initial &= 127
            input_arr = []
            for x in range(0, length_initial):
                input_arr.append(buff[x + 1])
                bytes_read += 1
            length = input_arr[0]
            for x in range(1, length_initial):
                length = input_arr[x] + (length << 8)

        if self.DEBUG:
            sys.stderr.write("Decoded length: {0}\n".format(length))
        return length, buff[bytes_read:]

    def _decode_groupkey(self):
        octet_stream, remains = self._decode_octet_string()

        guid = new_guid(octet_stream)

        if self.DEBUG:
            sys.stderr.write("Decoded GroupKey GUID {0}\n".format(guid))
        return guid, remains

    def _decode_authencrypt(self, buff):
        _, remains = der_decode(buff, ObjectIdentifier())
        mac_oid, remains = der_decode(remains, ObjectIdentifier())
        encryption_oid, remains = der_decode(remains, ObjectIdentifier())

        if self.DEBUG:
            sys.stderr.write("Decoded Algorithm OIDS\n Encryption Algorithm OID: {0}\n MAC Algorithm OID: {1}\n".format(encryption_oid, mac_oid))
        return encryption_oid, mac_oid, remains

    def decode(self):
        version = struct.unpack('>I', self._raw[0:4])[0]

        if version != 1:
            sys.stderr.write("Version should be 1   .\n")
            die()

        method = struct.unpack('>I', self._raw[4:8])[0]

        if method != 0:
            sys.stderr.write("Not using EncryptThenMAC. Currently only EncryptThenMAC is supported.")
            die()

        self.guid, remains = self._decode_groupkey()

        self.encryption_oid, self.mac_oid, remains = self._decode_authencrypt(remains)

        self.nonce, remains = self._decode_octet_string(remains)

        if self.DEBUG:
            sys.stderr.write("Decoded nonce: {0}\n".format(self.nonce.asOctets()))

        self.iv, remains = self._decode_octet_string(remains)

        if self.DEBUG:
            sys.stderr.write("Decoded IV: {0}\n".format(self.iv.asOctets()))

        self.mac_length, remains = self._decode_length(remains)

        if self.DEBUG:
            sys.stderr.write("Decoded MAC length: {0}\n".format(self.mac_length))

        self.ciphertext_length, remains = self._decode_length(remains)

        if self.DEBUG:
            sys.stderr.write("Decoded Ciphertext length: {0}\n".format(self.ciphertext_length))

        self.ciphertext = remains[:self.ciphertext_length - self.mac_length]

        if self.DEBUG:
            sys.stderr.write("Decoded Ciphertext: {0}\n".format(self.ciphertext))

        self.mac = remains[self.ciphertext_length - self.mac_length:]

        if self.DEBUG:
            sys.stderr.write("Decoded MAC: {0}\n".format(self.mac))
