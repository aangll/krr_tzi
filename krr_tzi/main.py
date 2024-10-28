from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from typing import Tuple, Dict
import time


# Генерація пари ключів RSA
def generate_keys(bit_length: int) -> Tuple[rsa.RSAPublicKey, rsa.RSAPrivateKey]:
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=bit_length,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return public_key, private_key


# Шифрування повідомлення за допомогою відкритого ключа RSA
def encrypt_message(public_key: rsa.RSAPublicKey, message: str) -> bytes:
    encrypted = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted


# Розшифрування повідомлення за допомогою закритого ключа RSA
def decrypt_message(private_key: rsa.RSAPrivateKey, encrypted_message: bytes) -> str:
    decrypted = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted.decode()


# Аналіз захищеності шифрування
def analyze_security(public_key: rsa.RSAPublicKey, message: str) -> Dict[str, any]:
    analysis = {}

    # Вимірюємо час шифрування
    start_time = time.time()
    encrypted_message = encrypt_message(public_key, message)
    encryption_time = time.time() - start_time

    # Оцінка міцності ключа на основі його розміру
    key_size = public_key.key_size
    if key_size >= 2048:
        key_strength = "Висока"
    elif 1024 <= key_size < 2048:
        key_strength = "Середня"
    else:
        key_strength = "Низька"

    analysis["encryption_time"] = encryption_time
    analysis["key_size"] = key_size
    analysis["key_strength"] = key_strength
    analysis["encrypted_message"] = encrypted_message

    return analysis


# Приклади використання функцій
if __name__ == "__main__":
    # Генеруємо ключі
    public_key, private_key = generate_keys(2048)

    # Повідомлення для тесту
    message = "My name is Anhelina"

    # Шифруємо повідомлення
    encrypted_message = encrypt_message(public_key, message)
    print("Зашифроване повідомлення:", encrypted_message)

    # Розшифровуємо повідомлення
    decrypted_message = decrypt_message(private_key, encrypted_message)
    print("Розшифроване повідомлення:", decrypted_message)

    # Аналіз захищеності
    security_analysis = analyze_security(public_key, message)
    print("Аналіз захищеності:", security_analysis)
