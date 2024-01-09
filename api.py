from flask import Flask, render_template, request
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import os

app = Flask(__name__)
secret_key = b'MbQeThWmZq4t6w9z'

@app.route('/')
def index():
    return "hello"

@app.route('/encrypt-cbc', methods=['POST'])
def encrypt_cbc():
    text_to_encrypt = request.form['text_to_encrypt']
    cipher = AES.new(secret_key, AES.MODE_CBC)
    cipher_text = cipher.encrypt(pad(text_to_encrypt.encode('utf-8'), AES.block_size))
    return {
        'cipher_text': base64.b64encode(cipher_text).decode('utf-8'),
        'iv': base64.b64encode(cipher.iv).decode('utf-8')
    }

@app.route('/decrypt-cbc', methods=['POST'])
def decrypt_cbc():
    cipher_text = request.form['cipher_text']
    iv = request.form['iv']
    cipher = AES.new(secret_key, AES.MODE_CBC, base64.b64decode(iv))
    decrypted_text = unpad(cipher.decrypt(base64.b64decode(cipher_text)), AES.block_size)
    return decrypted_text.decode('utf-8')


@app.route('/encrypt-cfb', methods=['POST'])
def encrypt_cfb():
    text_to_encrypt = request.form['text_to_encrypt']
    cipher = AES.new(secret_key, AES.MODE_CFB)
    cipher_text = cipher.encrypt(text_to_encrypt.encode("utf-8"))
    return {
        'cipher_text': base64.b64encode(cipher_text).decode('utf-8'),
        'iv': base64.b64encode(cipher.iv).decode('utf-8')
    }

@app.route('/decrypt-cfb', methods=['POST'])
def decrypt_cfb():
    cipher_text = request.form['cipher_text']
    iv = request.form['iv']
    decrypt_cipher = AES.new(secret_key, AES.MODE_CFB, iv=base64.b64decode(iv))
    decrypted_text = decrypt_cipher.decrypt(base64.b64decode(cipher_text))
    return decrypted_text.decode('utf-8')

if __name__ == '__main__':
    app.run(debug=True)