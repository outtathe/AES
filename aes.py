from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    return ciphertext

def decrypt(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext

# Пример использования
key = get_random_bytes(16)  # Генерация случайного 128-битного ключа
plaintext = b'Hello, AES!'  # Исходный текст

ciphertext = encrypt(plaintext, key)
decrypted_text = decrypt(ciphertext, key)

print("Ciphertext:", ciphertext)
print("Decrypted text:", decrypted_text.decode())
