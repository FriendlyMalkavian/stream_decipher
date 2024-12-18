from flask import Flask, render_template, request
from stream import stream_cipher, stream_decipher

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    encrypted_message = None
    key = None
    force_decrypted_message = None
    decrypted_message = None

    if request.method == 'POST':
        if 'encrypt' in request.form:
            message = request.form['message']
            encrypted_message, key = stream_cipher(message)
            force_decrypted_message = stream_decipher(encrypted_message, key)
        elif 'decrypt' in request.form:
            encrypted_message = request.form['encrypted_message']
            key = request.form['key']
            decrypted_message = stream_decipher(encrypted_message, key)

    return render_template('index.html', 
                           encrypted_message=encrypted_message, 
                           key=key, 
                           force_decrypted_message=force_decrypted_message, 
                           decrypted_message=decrypted_message)

if __name__ == '__main__':
    app.run(debug=True)

