import json
from Crypto.Cipher import DES
from Crypto.Util.Padding import unpad
import binascii
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

from flask import Flask, render_template, request
import jwt

import os
from flask import Flask, render_template, request, flash, redirect, url_for, send_file
from werkzeug.utils import secure_filename

# import time
import datetime


from PIL import Image

def encrypt(plain_text, key):
    # Generate a random initialization vector (IV)
    iv = get_random_bytes(DES.block_size)
    
    # Create a DES cipher object with the provided key and mode of operation
    cipher = DES.new(key, DES.MODE_CBC, iv)
    
    # Pad the plain text to match the block size
    padded_plain_text = pad(plain_text.encode('utf-8'), DES.block_size)
    
    # Encrypt the padded plain text
    cipher_text = cipher.encrypt(padded_plain_text)
    
    # Combine the IV and cipher text for final encrypted output
    encrypted_output = iv + cipher_text
    
    # Return the encrypted output as bytes
    return encrypted_output.hex()

# # Plain text and key
# plain_text = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Inp1bGZhbiIsImRhdGEiOiI1MDAwMCJ9.kbNzTN2RlZwdZ6xB8HMd4F_lptTYt9WNhfgL3DU2vW4"
# key = b'duaPuluh'

# # Encrypt the plain text
# encrypted_text = encrypt(plain_text, key)

# # Print the encrypted text as hex
# print(encrypted_text.hex())



def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']



##decrypt##

def decrypt(cipher_text, key):
    # Convert the hexadecimal string to bytes
    cipher_bytes = binascii.unhexlify(cipher_text)
    
    # Extract the initialization vector (IV) from the cipher text
    iv = cipher_bytes[:DES.block_size]
    
    # Create a DES cipher object with the provided key, mode of operation, and IV
    cipher = DES.new(key.encode('utf-8'), DES.MODE_CBC, iv)
    
    # Decrypt the cipher text
    decrypted_bytes = cipher.decrypt(cipher_bytes[DES.block_size:])
    
    # Remove the padding from the decrypted text
    unpadded_bytes = unpad(decrypted_bytes, DES.block_size)
    
    # Return the decrypted text as a string
    return unpadded_bytes.decode('utf-8')




 



## EOF Hiding
def hide_message(image_path, message):
    # Baca gambar
    image = Image.open(image_path)
    width, height = image.size

    # Konversi pesan menjadi bit
    binary_message = ''.join(format(ord(char), '08b') for char in message)

    # Tambahkan penanda akhir pesan (EOF)
    binary_message += '1111111111111110'

    # Periksa apakah pesan terlalu panjang untuk disisipkan dalam gambar
    max_message_length = width * height
    if len(binary_message) > max_message_length:
        raise ValueError("Pesan terlalu panjang untuk disisipkan dalam gambar.")

    # Ubah piksel dalam gambar
    pixels = image.load()
    index = 0
    for y in range(height):
        for x in range(width):
            r, g, b = pixels[x, y]

            # Ubah bit terakhir dari setiap komponen warna
            if index < len(binary_message):
                r = r & 0xFE | int(binary_message[index])
                index += 1
            if index < len(binary_message):
                g = g & 0xFE | int(binary_message[index])
                index += 1
            if index < len(binary_message):
                b = b & 0xFE | int(binary_message[index])
                index += 1

            # Simpan piksel yang telah diubah
            pixels[x, y] = (r, g, b)

    # Simpan gambar yang telah dimodifikasi
    # output_image_path = "images/output_"+image_path+".png"
    # image_path = image_path.split('/')
    unix_timestamp = str(datetime.datetime.timestamp(datetime.datetime.now())*1000)
    output_image_path = "images/"+unix_timestamp+".png"
    print(output_image_path)
    image.save(output_image_path)
    print("Pesan berhasil disisipkan dalam gambar: " + output_image_path)
    output_image_path2 = output_image_path.split("/")
    return output_image_path2[1]


##get images
def download_file(filename):
    try:
        return send_file(f"{app.config['IMAGE_ENCRYPT_FOLDER']}/{filename}", as_attachment=True)
    except FileNotFoundError:
        flash('Image not found', 'error')
        return redirect(url_for('home'))

app = Flask(__name__)
app.config['SECRET_KEY'] = 'super-secret-key'
# app.config['JWT_SECRET_KEY'] = 'jwt-super-secret-key'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = 600  # Token expiration time in seconds
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['UPLOAD_TO_DECRYPT'] = 'decrypt_this'
app.config['ALLOWED_EXTENSIONS'] = {'jpg', 'jpeg', 'png'}
app.config['IMAGE_ENCRYPT_FOLDER'] = 'images'

@app.route('/', methods=['GET', 'POST'])
def generate_jwt():
    if request.method == 'POST':
        expiration_time = str(datetime.datetime.now() + datetime.timedelta(seconds=app.config['JWT_ACCESS_TOKEN_EXPIRES']))
        payload = {
            'username': request.form.get('username'),
            'data': request.form.get('data'),
            'exp_time': expiration_time
        }
        header = {
            'alg': 'HS256',
            'typ': 'JWT'
        }
        token = jwt.encode(payload, app.config['SECRET_KEY'], headers=header, algorithm='HS256')
        print(request.form.get('key'))
        key = bytes(request.form.get('key'), encoding='utf-8')
        print(key)
        
        token_hasil_encrypt = encrypt(token, key)

        if 'file' not in request.files:
            flash('No file part', 'error')
            return redirect(request.url)
        file = request.files['file']
        # If the user does not select a file, browser submits an empty file
        if file.filename == '':
            flash('No selected file', 'error')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            # Save the uploaded file to the UPLOAD_FOLDER directory
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            flash('File uploaded successfully!', 'success')
            # return redirect(url_for('uploaded_file', filename=filename))
        else:
            flash('Invalid file format', 'error')

        print(filename)

        path_image_encrypt = hide_message(("uploads/"+filename), token_hasil_encrypt)
        print(path_image_encrypt)
        return render_template('token4.html', token=token_hasil_encrypt, file_path=path_image_encrypt)
    
    return render_template('generateJWT4.html')





@app.route('/download/<filename>')
def download_file(filename):
    try:
        return send_file(f"{app.config['IMAGE_ENCRYPT_FOLDER']}/{filename}", as_attachment=True)
    except FileNotFoundError:
        flash('Image not found', 'error')
        return redirect(url_for('home'))









def extract_message(image_path):
    # Baca gambar
    image = Image.open(image_path)
    width, height = image.size

    # Mengekstraksi pesan dari piksel gambar
    binary_message = ''
    for y in range(height):
        for x in range(width):
            r, g, b = image.getpixel((x, y))

            # Mendapatkan bit terakhir dari setiap komponen warna
            binary_message += str(r & 1)
            binary_message += str(g & 1)
            binary_message += str(b & 1)

    # Mencari penanda akhir pesan (EOF)
    eof_index = binary_message.find('1111111111111110')
    if eof_index == -1:
        raise ValueError("Tidak dapat menemukan penanda akhir pesan (EOF). Pesan mungkin tidak ada.")

    # Mengonversi bit pesan ke dalam karakter
    message = ''
    for i in range(0, eof_index, 8):
        char_bits = binary_message[i:i+8]
        char = chr(int(char_bits, 2))
        message += char

    return message



def decrypt(cipher_text, key):
    # Convert the hexadecimal string to bytes
    cipher_bytes = binascii.unhexlify(cipher_text)
    
    # Extract the initialization vector (IV) from the cipher text
    iv = cipher_bytes[:DES.block_size]
    
    # Create a DES cipher object with the provided key, mode of operation, and IV
    cipher = DES.new(key.encode('utf-8'), DES.MODE_CBC, iv)
    
    # Decrypt the cipher text
    decrypted_bytes = cipher.decrypt(cipher_bytes[DES.block_size:])
    
    # Remove the padding from the decrypted text
    unpadded_bytes = unpad(decrypted_bytes, DES.block_size)
    
    # Return the decrypted text as a string
    return unpadded_bytes.decode('utf-8')


def show_payload(hasil_decrypt):
    token = hasil_decrypt
    try:
        decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        payload = decoded_token
        # expiration_time = 
        flash(f'Payload: {payload}', 'success')
    except jwt.ExpiredSignatureError:
        flash('Token has expired', 'error')
    except (jwt.InvalidTokenError, KeyError):
        flash('Invalid token', 'error')
    print(payload)
    return payload
    

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        key_decrypt = request.form.get('key_decrypt')
        print(key_decrypt)

        if 'file' not in request.files:
            flash('No file part', 'error')
            return redirect(request.url)
        file = request.files['file']
        # If the user does not select a file, browser submits an empty file
        if file.filename == '':
            flash('No selected file', 'error')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            # Save the uploaded file to the UPLOAD_FOLDER directory
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_TO_DECRYPT'], filename))
            flash('File uploaded successfully!', 'success')
            # print(filename)
            # return redirect(url_for('uploaded_file', filename=filename))
        else:
            flash('Invalid file format', 'error')
        
        print(filename)

        pesan = extract_message(app.config['UPLOAD_TO_DECRYPT']+"/"+filename)

        print("hasil stegano: " + pesan)

        hasil_decrypt = decrypt(pesan, key_decrypt)

        print('decrypt: '+hasil_decrypt)

        payload = show_payload(hasil_decrypt)

        return render_template('payload.html', username=payload["username"], data=payload["data"], batas_waktu=payload["exp_time"])
        
    return render_template('login2.html')


if __name__ == '__main__':
    app.run()
