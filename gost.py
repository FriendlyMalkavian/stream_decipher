# Таблица подстановки id-Gost28147-89-CryptoPro-A-ParamSet
TABLE = [
    [9, 6, 3, 2, 8, 11, 1, 7, 10, 4, 14, 15, 0, 13, 5],
    [3, 7, 14, 9, 8, 10, 15, 0, 5, 2, 6, 12, 4, 13, 1],
    [14, 4, 6, 2, 11, 3, 13, 8, 12, 5, 10, 0, 7, 1, 9],
    [14, 7, 10, 12, 13, 1, 3, 9, 0, 2, 11, 4, 15, 8, 5],
    [11, 5, 1, 9, 8, 13, 15, 0, 4, 2, 3, 12, 7, 10, 6],
    [3, 10, 13, 12, 1, 2, 0, 11, 7, 5, 9, 4, 8, 15, 6],
    [1, 13, 2, 9, 7, 10, 6, 0, 8, 4, 5, 15, 3, 11, 14],
    [11, 10, 15, 5, 0, 12, 14, 8, 6, 3, 9, 1, 7, 13, 4]
]

keyForCipherDecipher = b'1234567890abcdef1234567890abcdef'

def swapTABLE(value):
    result = 0
    for i in range(8):
        nibble = (value >> (4 * i)) & 0xF
        sbox_row = i
        # Проверка на выход за пределы таблицы подстановки
        if sbox_row < len(TABLE):
            if nibble < len(TABLE[sbox_row]):
                result |= TABLE[sbox_row][nibble] << (4 * i) #конкатенация

    return result

def F(R, Qj):
    R = (R + Qj) % (2**32)
    R = swapTABLE(R)
    R = ((R << 11) | (R >> (32 - 11))) % (2**32)
    return R

def cipher_gost(block, keys):
    L, R = block >> 32, block & 0xFFFFFFFF
    for i in range(1, 33):
        j = (i - 1) % 8 if i < 25 else (32 - i) % 8
        Qj = keys[j]
        V = R
        R = F(R, Qj) ^ L
        L = V
    return (L << 32) | R

def decipher_gost(block, keys):
    L, R = block >> 32, block & 0xFFFFFFFF
    for i in range(1, 33):
        j = (i - 1) % 8 if i <= 8 else (32 - i) % 8
        Qj = keys[j]
        V = L
        L = F(L, Qj) ^ R
        R = V
    return (L << 32) | R

def generate_keys(keyForCipherDecipher):
        return [int.from_bytes(keyForCipherDecipher[i:i + 4], 'big') for i in range(0, 32, 4)]

keys = generate_keys(keyForCipherDecipher)

def cipher(text, keys=keys):
    blocks = [int.from_bytes(text[i:i + 8], 'big') for i in range(0, len(text), 8)]

    ciphertext = b''
    
    for block in blocks:
        encrypted_block = cipher_gost(block, keys)
        ciphertext += encrypted_block.to_bytes(8, 'big')
    
    return ciphertext

def decipher(ciphertext, keys=keys):
    keys = generate_keys(keyForCipherDecipher)
    decrypted_text = b''
    for block in [int.from_bytes(ciphertext[i:i + 8], 'big') for i in range(0, len(ciphertext), 8)]:
        decrypted_block = decipher_gost(block, keys)
        decrypted_text += decrypted_block.to_bytes(8, 'big')
    decrypted_text = decrypted_text.replace(b'\x00', b'')
    return decrypted_text.decode(errors="ignore")
       
#Hi = EHi-1 (Mi) (+)Mi - выбранная функция хэширования 
def hash(message):
    h = 0  # Начальный хэш
    for i in range(0, len(message), 8):
        Mi = message[i:i + 8]  # Текущий блок сообщения
        if len(Mi) < 8:
            Mi += b'\x00' * (8 - len(Mi))  # Дополняем до 8 байт
        hi = cipher(Mi, keys)  # Шифруем текущий блок(EHi)
        h ^= int.from_bytes(hi, 'big')  # Побитовая сумма с текущим хэшом
    return h.to_bytes(8, 'big')

ciphered_msg = cipher(b'zycie jest bez sensu i wszyscy zginiemy')
result = decipher(ciphered_msg)

# print(hash(ciphered_msg))
# print(hash(b'zycie jest bez sensu i wszyscy zginiemy'))
# print(ciphered_msg.hex())
# print(result)
# print(hash(result.encode('utf-8')))