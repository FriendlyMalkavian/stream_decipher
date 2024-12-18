from gost import cipher

def stream_cipher(msg):
    k = ''
    for i in range(len(msg)):
        k += str(cipher(bytes(msg[i], 'utf-8')))
    key = ''.join(format(ord(i), '08b') for i in k)
    c_msg = ''.join(format(ord(i), '08b') for i in msg)
    sub_msg = ''
    for g in range(0, len(c_msg)):
        sub_msg += str(int(c_msg[g]) ^ int(key[g]))
    res_msg = ''
    for i in range(0, len(sub_msg), 8):
        byte = sub_msg[i:i+8]
        res_msg += chr(int(byte, 2))  # Преобразуем 8 бит в символ
    return res_msg, key
def stream_decipher(msg, key):
    c_msg = ''.join(format(ord(i), '08b') for i in msg)
    sub_msg = ''
    for g in range(0, len(c_msg)):
        sub_msg += str(int(c_msg[g]) ^ int(key[g]))
    res_msg = ''
    for i in range(0, len(sub_msg), 8):
        byte = sub_msg[i:i+8]
        res_msg += chr(int(byte, 2))  # Преобразуем 8 бит в символ
    return res_msg
