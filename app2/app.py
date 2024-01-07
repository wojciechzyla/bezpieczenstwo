from flask import Flask, request, jsonify
from Crypto.Cipher import AES
import os
import base64
import logging
import json

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
ENCRYPTION_KEY = bytes(os.environ.get('ENCRYPTION_KEY', 'MbQeThWmZq4t6w9z'), "utf-8")


def encrypt_data(data, key):
    header = b"header"
    cipher = AES.new(key, AES.MODE_GCM)
    cipher.update(header)
    encrypted_data, tag = cipher.encrypt_and_digest(data.encode("utf-8"))

    encrypted_data = base64.b64encode(encrypted_data).decode('utf-8')
    nonce = base64.b64encode(cipher.nonce).decode('utf-8')
    tag = base64.b64encode(tag).decode('utf-8')
    return encrypted_data, nonce, tag


def decrypt_data(encrypted_data, key, nonce, tag):
    try:
        header = b"header"
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        cipher.update(header)
        decrypted_data = cipher.decrypt_and_verify(encrypted_data, tag)
        return decrypted_data
    except Exception as e:
        logging.error(f"Decryption error: {str(e)}")
        return None


@app.route('/process', methods=['POST'])
def process_data():
    encrypted_data = request.json.get('data')
    nonce = request.json.get('nonce')
    tag = request.json.get('tag')
    encrypted_data = base64.b64decode(encrypted_data)
    nonce = base64.b64decode(nonce)
    tag = base64.b64decode(tag)

    if encrypted_data is None:
        return jsonify({'error': 'Invalid request'}), 400

    decrypted_data = decrypt_data(encrypted_data, ENCRYPTION_KEY, nonce, tag)

    if decrypted_data is None:
        return jsonify({'error': 'Decryption failed'}), 500

    decrypted_data = decrypted_data.decode("utf-8")

    response_message = f"Hello user {json.loads(decrypted_data)['username']}"
    encrypted_response, nonce, tag = encrypt_data(json.dumps({"message": response_message}), ENCRYPTION_KEY)

    return jsonify({'data': encrypted_response, 'nonce': nonce, 'tag': tag}), 200


if __name__ == '__main__':
    app.run(port=5001)
