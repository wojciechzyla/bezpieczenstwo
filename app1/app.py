#!/usr/bin/python
# -*- coding: utf-8 -*-
from flask import Flask, jsonify, request
from flask_jwt_extended import (JWTManager, create_access_token, create_refresh_token,
                                jwt_required, get_jwt_identity, get_jwt, verify_jwt_in_request, decode_token)
from datetime import timedelta
import logging
from functools import wraps
from flask_sqlalchemy import SQLAlchemy
import os
from Crypto.Cipher import AES
import base64
import json
import requests

DB_NAME = os.getenv("DB_NAME", "smart_travel")
DB_HOST = os.getenv("DB_HOST", "0.0.0.0:5432")
DB_USERNAME = os.getenv("DB_USERNAME", "st_backend")
DB_PASSWORD = os.getenv("DB_PASSWORD", "abdj24AfwF#$1cw#4fq3d")
ACCESS_TOKEN_EXPIRES_MIN = int(os.getenv("ACCESS_TOKEN_EXPIRES_MIN", "2"))
REFRESH_TOKEN_EXPIRES_MIN = int(os.getenv("REFRESH_TOKEN_EXPIRES_MIN", "6"))
APP2_URL = os.getenv("APP2_URL")
ENCRYPTION_KEY = bytes(os.environ.get('ENCRYPTION_KEY'), "utf-8")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

app.config['JWT_SECRET_KEY'] = 'your-secret-key'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=ACCESS_TOKEN_EXPIRES_MIN)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(minutes=REFRESH_TOKEN_EXPIRES_MIN)
app.config['SQLALCHEMY_DATABASE_URI'] = f'postgresql://{DB_USERNAME}:{DB_PASSWORD}@{DB_HOST}/{DB_NAME}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


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



class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)

    # One-to-Many relationship with documents
    documents = db.relationship('Document', backref='user', lazy=True)


# Document Model
class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


jwt = JWTManager(app)


# Token blacklist (used for logout)
blacklist = set()


# Custom decorator to log the remote address only if @jwt_required() fails
def log_remote_address(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            verify_jwt_in_request()
        except:
            ip_address = request.environ.get("HTTP_X_FORWARDED_FOR", request.remote_addr)
            logger.info(f"Failed request: failed validation for endpoint {request.path} from address: {ip_address}")
        # You can perform additional actions here before @jwt_required()
        result = fn(*args, **kwargs)
        return result

    return wrapper


@jwt.token_in_blocklist_loader
def check_if_token_is_revoked(jwt_header, jwt_payload: dict):
    jti = jwt_payload["jti"]
    return jti in blacklist

# Endpoint to create a new user
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    login = data.get('login')
    password = data.get('password')

    existinguser = User.query.filter_by(login=login, password=password).first()
    if existinguser:
        return jsonify({'message': 'Username already exists'}), 400

    new_user = User(login=login, password=password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User created successfully'}), 201


# Endpoint to login and get an access token and a refresh token
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    login = data.get('login')
    password = data.get('password')

    existinguser = User.query.filter_by(login=login, password=password).first()
    if not existinguser:
        ip_address = request.environ.get("HTTP_X_FORWARDED_FOR", request.remote_addr)
        logger.info(f"Failed request: failed login from address: {ip_address}")
        return jsonify({'message': 'Invalid credentials'}), 401

    access_token = create_access_token(identity=existinguser.id)
    refresh_token = create_refresh_token(identity=existinguser.id)

    return jsonify({'access_token': access_token, 'refresh_token': refresh_token}), 200


# Endpoint to refresh an access token using a refresh token
@app.route('/refresh', methods=['POST'])
@log_remote_address
@jwt_required(refresh=True)
def refresh():
    current_user = get_jwt_identity()
    new_access_token = create_access_token(identity=current_user)
    return jsonify({'access_token': new_access_token}), 200


# Endpoint to logout (add the token to the blacklist)
@app.route('/logout', methods=['DELETE'])
@log_remote_address
@jwt_required()
def logout():
    jti = get_jwt()['jti']
    refresh_token = decode_token(request.json["refresh_token"])['jti']
    blacklist.add(jti)
    blacklist.add(refresh_token)
    return jsonify({'message': 'Successfully logged out'}), 200


# Endpoint to get the user's name (requires authentication)
@app.route('/user', methods=['GET'])
@log_remote_address
@jwt_required()
def get_user():
    current_user = get_jwt_identity()
    existinguser = User.query.filter_by(id=current_user).first()
    return jsonify({'login': existinguser.login}), 200


@app.route('/between-apps-communication', methods=['GET'])
@log_remote_address
@jwt_required()
def between_apps_communication():
    current_user = get_jwt_identity()
    existinguser = User.query.filter_by(id=current_user).first()
    encrypted_data, nonce, tag = encrypt_data(json.dumps({"username": existinguser.login}), ENCRYPTION_KEY)

    logging.info("Sending request to processing app")
    response = requests.post(f"http://{APP2_URL}/process", json={'data': encrypted_data, 'nonce': nonce, 'tag': tag})
    if response.status_code != 200:
        return jsonify({'error': 'We are facing some problems'}), 500

    encrypted_data = response.json().get('data')
    nonce = response.json().get('nonce')
    tag = response.json().get('tag')
    encrypted_data = base64.b64decode(encrypted_data)
    nonce = base64.b64decode(nonce)
    tag = base64.b64decode(tag)

    decrypted_result = decrypt_data(encrypted_data, ENCRYPTION_KEY, nonce, tag)

    if decrypted_result is None:
        return jsonify({'error': 'We are facing some problems'}), 500

    decrypted_result = decrypted_result.decode("utf-8")
    return jsonify({'message': decrypted_result}), 200

if __name__ == '__main__':
    app.run(debug=True)
