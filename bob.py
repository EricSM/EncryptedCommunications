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
#    This is a server program where the server (Bob) receives an encrypted message from a client (Alice)
#    after sending his signed public key (This program assumes RSA keys of size 2048).

import sys
import pprint
import base64
from socket import *
import hashlib
import json
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# communications with a client Alice after they connect with Bob
def new_client(conn, digest):
    with conn:
		# receive greeting from Alice
        greeting = conn.recv(6)
        if greeting != b'Hello':
            return

        print('2) Sending Digest Information')
        pp = pprint.PrettyPrinter(indent=4)
        pp.pprint(digest)
        conn.sendall(json.dumps(digest).encode())

        print('\n3) Awaiting private communication')
        message_data = b''
        while True:
            data = conn.recv(1024)
            message_data += data
            if not data:
                break

        print('4) Received message from Alice')
        message = json.loads(message_data)

        if 'message' in message:
            pp.pprint(message)
            encrypted_contents = base64.b64decode(message['message'].encode())
        elif 'file_name' in message and 'contents' in message:
            encrypted_name = base64.b64decode(message['file_name'].encode())
            encrypted_contents = base64.b64decode(message['contents'].encode())
        else:
            print('Invalid Message')
            return

        encrypted_verify = base64.b64decode(message['verify'].encode())
        encrypted_key = base64.b64decode(message['key'].encode())

		# load Bob's private key
        bob_priv = serialization.load_pem_private_key(
            open(sys.argv[3], 'rb').read(),
            password=None,
            backend=default_backend()
        )

		# decrypt the symmetric AES key and nonce sent by Alice
        key_iv = bob_priv.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

		# extract the key and nonce and create the cipher
        key = key_iv[0:32]
        iv = key_iv[32:48]
        cipher = Cipher(algorithms.AES(key),
                        modes.CBC(iv), backend=default_backend())
						
		# decrypt the contents and hash of the message
        decrypter = cipher.decryptor()
        contents = decrypter.update(encrypted_contents) + decrypter.finalize()
        decrypter = cipher.decryptor()
        message_hash = decrypter.update(encrypted_verify) + decrypter.finalize()

		# if alice sent a file, decrypt the file name and save the file
        if 'file_name' in message:
            decrypter = cipher.decryptor()
            file_name_bytes = decrypter.update(encrypted_name) + decrypter.finalize()
            file_name = file_name_bytes.decode().strip()

            print('5) Alice Sent a File -', file_name)
            file = open(file_name, 'wb')
            file.write(contents)
            file.close()
            print('   File Saved.')
		# otherwise, just display the message
        else:
            print('\n5) Secret Message Decoded:')
            print(contents.decode())

		# calculate the hash of the contents and compare it with the provided hash
        if message_hash == hashlib.sha256(contents).hexdigest().encode():
            print('6) Message Hash Checks Out!')
        else:
            print('6) WARNING: Cannot Verify Message!')

# server listens for clients who want to connect
def main():
    if len(sys.argv) != 6:
        print('Incorrect number of arguments')
        return

    if sys.argv[1] != '-port':
        print('port tag missing')
        return

    host = '127.0.0.1'
    # listening port provided by user
    port = int(sys.argv[2])
    # port = 65432  # for use with pycharm

	# load Bob's private certificate
    cert_key_priv = serialization.load_pem_private_key(
        open(sys.argv[5], 'rb').read(),
        password=None,
        backend=default_backend()
    )

	# load Bob's public key file
    pub_file = open(sys.argv[4], 'rb').read()

	# sign Bob's public key with his private signature
    signature = cert_key_priv.sign(
        pub_file,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )

	# create an object of Bob's digest, containing his name, public key, and its signature
    digest = {
        'name': 'bob',
        'pub_key': repr(pub_file),
        'signature': base64.b64encode(signature).decode()}

	# open a socket and listen on localhost at the user specified port
    with socket(AF_INET, SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()

        while True:
            print('--------------------------------------')
            print('1) Waiting For Connection on', host, 'port', port)
			
			# accept connection
            conn, addr = s.accept()
            print('2) Connected from', conn)
            new_client(conn, digest)
            print('--------------------------------------\n\n')


if __name__ == "__main__":
    main()
