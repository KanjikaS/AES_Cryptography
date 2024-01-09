from flask import Flask, render_template, request
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import os

app = Flask(__name__)

# Replace this key with a strong and secure key (must be 16, 24, or 32 bytes long)
secret_key = b'MbQeThWmZq4t6w9z'
def encrypt_text(text, key):
    cipher = AES.new(key, AES.MODE_CBC)
    cipher_text = cipher.encrypt(pad(text.encode('utf-8'), AES.block_size))
    return {
        'cipher_text': base64.b64encode(cipher_text).decode('utf-8'),
        'iv': base64.b64encode(cipher.iv).decode('utf-8')
    }

def decrypt_text(cipher_text, iv, key):
    cipher = AES.new(key, AES.MODE_CBC, base64.b64decode(iv))
    decrypted_text = unpad(cipher.decrypt(base64.b64decode(cipher_text)), AES.block_size)
    return decrypted_text.decode('utf-8')


def decrypt_cfb_func(cipher_text,iv, key):
    decrypt_cipher = AES.new(key, AES.MODE_CFB, iv=iv)
    decrypted_data = decrypt_cipher.decrypt(cipher_text)
    return decrypted_data

@app.route('/')
def index():
    return "hello"

@app.route('/encrypt', methods=['POST'])
def encrypt():
    text_to_encrypt = request.form['text_to_encrypt']
    encrypted_data = encrypt_text(text_to_encrypt, secret_key)
    return encrypted_data

@app.route('/decrypt', methods=['POST'])
def decrypt():
    cipher_text = request.form['cipher_text']
    iv = request.form['iv']
    decrypted_data = decrypt_text(cipher_text, iv, secret_key)
    return decrypted_data

@app.route('/encrypt-cfb', methods=['POST'])
def encrypt_cfb():
    text_to_encrypt = request.form['text_to_encrypt']
    cipher = AES.new(secret_key, AES.MODE_CFB)

    encrypted_data =cipher.encrypt(text_to_encrypt.encode())
    iv = cipher.iv
    response = {
        'cipher_text': base64.b64encode(encrypted_data).decode('utf-8'),
        'iv':base64.b64encode(cipher.iv).decode('utf-8')
    }
    return response
@app.route('/decrypt-cfb', methods=['POST'])
def decrypt_cfb():
    cipher_text = request.form['cipher_text']
    iv = request.form['iv']
    decrypted_data = decrypt_cfb_func(cipher_text, iv, secret_key)
    response = {
        'plaintext ':decrypted_data
        
    }
    return response
    

if __name__ == '__main__':
    app.run(debug=True)
