# Author: Eric Miramontes
# Date:   4/18/2019
# Course: CS 4480, University of Utah, School of Computing
# Copyright: CS 4480 and Eric Miramontes - This work may not be copied for use in Academic Coursework.
#
# I, Eric Miramontes, certify that I wrote this code from scratch and did not copy it in part or whole from
# another source.  Any references used in the completion of the assignment are cited in my written work.
#
# File Contents
#
#    This is a client program where the client (Alice) sends an encrypted message to the server (Bob) after
#    after receiving Bob's signed public key. (This program assumes RSA keys of size 2048)

import sys
import pprint
from socket import *
import hashlib
import base64
import json
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def main():
    if len(sys.argv) != 7:
        print('Incorrect number of arguments')
        return

    # for use with pycharm
    # host = '127.0.0.1'
    # port = 65432

    if sys.argv[2] != '-port':
        print('port tag missing')
        return

    # host and port user wishes to connect to
    host = sys.argv[1]
    port = int(sys.argv[3])

	# message type can be either a text message or a file.
    message_type = sys.argv[5]
    if message_type == '-message':
        message = sys.argv[6].encode()
    elif message_type == '-file':
        file_name = sys.argv[6]
        message = open(file_name, 'rb').read()
    else:
        print('Incorrect message tag.  Must be -message or -file')
        return

	# load public certificate
    cert_key_pub = serialization.load_pem_public_key(
        open(sys.argv[4], 'rb').read(),
        backend=default_backend()
    )

    # s is the client socket
    with socket(AF_INET, SOCK_STREAM) as s:
        print('1) Attempting to open connection to Bob at',
              host, 'on port', port)
        s.connect((host, port))

        print('2) Connected. Sending "Hello"')
        s.sendall(b'Hello')

		# recieve Bob's encrypted digest
        data = s.recv(1024)
        bob_digest = json.loads(data)

        print('3) Received')
        pp = pprint.PrettyPrinter(indent=4)
        pp.pprint(bob_digest)
		
		# check that the digest indeed came from bob
        if bob_digest['name'] != 'bob':
            print('\n4) Did not receive response from Bob.\nCommunication Over')
            return

		# verify the signature in Bob's digest
        cert_key_pub.verify(
            base64.b64decode(bob_digest['signature'].encode()),
            eval(bob_digest['pub_key']),
            padding.PSS(
                mgf = padding.MGF1(hashes.SHA256()),
                salt_length = padding.PSS.MAX_LENGTH),
            hashes.SHA256())
			
		# load Bob's public key
        bob_pub = serialization.load_pem_public_key(
            eval(bob_digest['pub_key']),
            backend=default_backend()
        )

		# create random 32 byte symmetric AES key and 16 byte nonce,
		# then generate symmetric cipher
        global key
        key = os.urandom(32)
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

		# pad the message so its length is a multiple of 32 (the size of an AES block),
		# and then calculate its sha256 hash
        message = pad_bytes(message)
        message_hash = hashlib.sha256(message).hexdigest().encode()
		
        global encrypter
        encrypter = cipher.encryptor()
		
		# encrypt padded message
        global cipher_text
        cipher_text= encrypter.update(message) + encrypter.finalize()

		# encrypt hash of the padded message
        encrypter = cipher.encryptor()
        global cipher_hash
        cipher_hash = encrypter.update(message_hash) + encrypter.finalize()

		# encrypt the key and nonce with Bob's public key
        encrypted_key = bob_pub.encrypt(
            key + iv,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None)
        )

		# create python object of Alice's message that contains the message, hash, and key
        if message_type == '-message':
            alice_message = {
                'message': base64.b64encode(cipher_text).decode(),
                'verify': base64.b64encode(cipher_hash).decode(),
                'key': base64.b64encode(encrypted_key).decode()}
            print('\n4) Sending the encoded message:')
            pp.pprint(alice_message)
            print()
		# if the message is a file encrypt and include the file name
        elif message_type == '-file':
            name_bytes = pad_bytes(file_name.encode())
            encrypter = cipher.encryptor()
            cipher_name = encrypter.update(name_bytes) + encrypter.finalize()

            alice_message = {
                'file_name': base64.b64encode(cipher_name).decode(),
                'contents': base64.b64encode(cipher_text).decode(),
                'verify': base64.b64encode(cipher_hash).decode(),
                'key': base64.b64encode(encrypted_key).decode()}
            print('\n4) Sending the encoded file')

		# send Alice's message to Bob
        s.sendall(json.dumps(alice_message).encode())

        print('5) Communication Over\n--------------------------------------\n\n')


# Helper function to pad a byte array with whitespace
def pad_bytes(message):
    message_mod = len(message) % 32
    for x in range(32 - message_mod):
        message = message + b' '
    return message


if __name__ == "__main__":
    main()
