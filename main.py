import flet as ft
import base64
import hashlib
import random
import time
import smtplib
from email.message import EmailMessage
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from PIL import Image
import io
import numpy as np
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# ------------------ VIGENERE ------------------
def vigenere_encrypt(text, key):
    result = ""
    key = key.upper()
    k = 0
    for char in text.upper():
        if char.isalpha():
            shift = ord(key[k % len(key)]) - 65
            result += chr((ord(char) - 65 + shift) % 26 + 65)
            k += 1
        else:
            result += char
    return result

def vigenere_decrypt(cipher, key):
    result = ""
    key = key.upper()
    k = 0
    for char in cipher.upper():
        if char.isalpha():
            shift = ord(key[k % len(key)]) - 65
            result += chr((ord(char) - 65 - shift) % 26 + 65)
            k += 1
        else:
            result += char
    return result

# ------------------ AES TEXT ------------------
def aes_encrypt(message, password):
    key = hashlib.sha256(password.encode()).digest()
    iv = b"0000000000000000"
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    pad_len = 16 - (len(message) % 16)
    padded_message = message + chr(pad_len) * pad_len
    ct = encryptor.update(padded_message.encode()) + encryptor.finalize()
    return base64.b64encode(ct).decode(), base64.b64encode(iv).decode(), base64.b64encode(key).decode()

def aes_decrypt(ciphertext_b64, password):
    key = hashlib.sha256(password.encode()).digest()
    iv = b"0000000000000000"
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    ct = base64.b64decode(ciphertext_b64)
    decrypted = decryptor.update(ct) + decryptor.finalize()
    pad_len = decrypted[-1]
    return decrypted[:-pad_len].decode()

# ------------------ RSA ------------------
def generate_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()
    ).decode()
    pub = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    return priv, pub

def rsa_encrypt(public_key_pem, message):
    public_key = serialization.load_pem_public_key(public_key_pem.encode())
    ciphertext = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            padding.MGF1(hashes.SHA256()),
            hashes.SHA256(),
            None
        )
    )
    return base64.b64encode(ciphertext).decode()

def rsa_decrypt(private_key_pem, ciphertext_b64):
    private_key = serialization.load_pem_private_key(private_key_pem.encode(), None)
    ciphertext = base64.b64decode(ciphertext_b64)
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            padding.MGF1(hashes.SHA256()),
            hashes.SHA256(),
            None
        )
    )
    return plaintext.decode()

# ------------------ EMAIL 2FA ------------------
GMAIL_USER = os.getenv("GMAIL_USER", "your_account@gmail.com")      # Loaded from .env
GMAIL_APP_PASSWORD = os.getenv("GMAIL_APP_PASSWORD", "your_app_password")  # Loaded from .env
verification_codes = {}  # email: (code, expiry)

def send_2fa_code(to_email):
    code = str(random.randint(100000, 999999))
    expiry = time.time() + 180  # 3 minutes
    verification_codes[to_email] = (code, expiry)
    msg = EmailMessage()
    msg["Subject"] = "Votre code de vérification 2FA"
    msg["From"] = GMAIL_USER
    msg["To"] = to_email
    msg.set_content(f"Bonjour !\n\nVotre code de vérification est : {code}\nIl expire dans 3 minutes.")
    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
        smtp.login(GMAIL_USER, GMAIL_APP_PASSWORD)
        smtp.send_message(msg)

def verify_2fa_code(to_email, input_code):
    if to_email not in verification_codes:
        return False
    code, expiry = verification_codes[to_email]
    if time.time() > expiry:
        del verification_codes[to_email]
        return False
    if input_code == code:
        del verification_codes[to_email]
        return True
    return False

# ------------------ AES IMAGE ------------------
def aes_encrypt_bytes(data, password):
    key = hashlib.sha256(password.encode()).digest()
    iv = b"0000000000000000"
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    pad_len = 16 - (len(data) % 16)
    data += bytes([pad_len]) * pad_len

    return encryptor.update(data) + encryptor.finalize()

def aes_decrypt_bytes(data, password):
    key = hashlib.sha256(password.encode()).digest()
    iv = b"0000000000000000"
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()

    decrypted = decryptor.update(data) + decryptor.finalize()
    pad_len = decrypted[-1]
    return decrypted[:-pad_len]

def encrypted_bytes_to_noise_png(enc_bytes):
    size = int(len(enc_bytes) ** 0.5) + 1
    padded = enc_bytes + b"\x00" * (size*size - len(enc_bytes))
    arr = np.frombuffer(padded, dtype=np.uint8).reshape((size, size))
    rgb = np.stack([arr, arr, arr], axis=2)
    img = Image.fromarray(rgb.astype(np.uint8), "RGB")
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    return buffer.getvalue()

# ------------------ FLET GUI ------------------
def main(page: ft.Page):
    page.title = "Crypto + Gmail 2FA + Image AES"
    page.scroll = "auto"

    # ---------- VIGENERE ----------
    vig_inp = ft.TextField(label="Texte")
    vig_key = ft.TextField(label="Clé")
    vig_out = ft.TextField(label="Résultat", multiline=True)
    def do_vig_encrypt(e):
        vig_out.value = vigenere_encrypt(vig_inp.value, vig_key.value)
        page.update()
    def do_vig_decrypt(e):
        vig_out.value = vigenere_decrypt(vig_inp.value, vig_key.value)
        page.update()
    vigenere_tab = ft.Column([
        vig_inp, vig_key,
        ft.Row([ft.ElevatedButton("Chiffrer", on_click=do_vig_encrypt),
                ft.ElevatedButton("Déchiffrer", on_click=do_vig_decrypt)]),
        vig_out
    ])

    # ---------- AES TEXT ----------
    aes_msg = ft.TextField(label="Message")
    aes_pwd = ft.TextField(label="Mot de passe", password=True)
    aes_out_ct = ft.TextField(label="Ciphertext Base64", multiline=True)
    aes_out_key = ft.TextField(label="Key SHA256", multiline=True)
    aes_out_decrypted = ft.TextField(label="Message déchiffré", multiline=True)
    def do_aes_encrypt(e):
        ct, iv, key = aes_encrypt(aes_msg.value, aes_pwd.value)
        aes_out_ct.value = ct
        aes_out_key.value = key
        page.update()
    def do_aes_decrypt(e):
        try:
            aes_out_decrypted.value = aes_decrypt(aes_out_ct.value, aes_pwd.value)
        except:
            aes_out_decrypted.value = "Erreur"
        page.update()
    aes_tab = ft.Column([
        aes_msg, aes_pwd,
        ft.Row([ft.ElevatedButton("Chiffrer AES", on_click=do_aes_encrypt),
                ft.ElevatedButton("Déchiffrer AES", on_click=do_aes_decrypt)]),
        aes_out_ct, aes_out_key, aes_out_decrypted
    ])

    # ---------- RSA ----------
    rsa_priv = ft.TextField(label="Clé privée", multiline=True)
    rsa_pub = ft.TextField(label="Clé publique", multiline=True)
    rsa_msg = ft.TextField(label="Message")
    rsa_ct = ft.TextField(label="Ciphertext (Base64)", multiline=True)
    rsa_out = ft.TextField(label="Déchiffré", multiline=True)
    def do_gen_keys(e):
        priv, pub = generate_rsa_keys()
        rsa_priv.value = priv
        rsa_pub.value = pub
        page.update()
    def do_rsa_encrypt(e):
        rsa_ct.value = rsa_encrypt(rsa_pub.value, rsa_msg.value)
        page.update()
    def do_rsa_decrypt(e):
        try:
            rsa_out.value = rsa_decrypt(rsa_priv.value, rsa_ct.value)
        except:
            rsa_out.value = "Erreur"
        page.update()
    rsa_tab = ft.Column([
        ft.ElevatedButton("Générer clés RSA", on_click=do_gen_keys),
        rsa_priv, rsa_pub, rsa_msg,
        ft.Row([ft.ElevatedButton("Chiffrer RSA", on_click=do_rsa_encrypt),
                ft.ElevatedButton("Déchiffrer RSA", on_click=do_rsa_decrypt)]),
        rsa_ct, rsa_out
    ])

    # ---------- EMAIL 2FA ----------
    email_input = ft.TextField(label="Votre email")
    code_input = ft.TextField(label="Entrez le code reçu")
    result_text = ft.Text("")
    def send_code(e):
        try:
            send_2fa_code(email_input.value)
            result_text.value = "✔ Code envoyé ! Vérifiez votre email."
        except Exception as ex:
            result_text.value = f"❌ Erreur: {ex}"
        page.update()
    def verify_code(e):
        if verify_2fa_code(email_input.value, code_input.value):
            result_text.value = "✔ Code valide ! Login autorisé."
        else:
            result_text.value = "❌ Code invalide ou expiré."
        page.update()
    email_tab = ft.Column([
        email_input,
        ft.Row([ft.ElevatedButton("Envoyer Code 2FA", on_click=send_code)]),
        code_input,
        ft.Row([ft.ElevatedButton("Vérifier Code", on_click=verify_code)]),
        result_text
    ])

    # ---------- IMAGE AES ----------
    image_original = None
    encrypted_bytes = None
    img_display = ft.Image()
    image_password = ft.TextField(label="Mot de passe AES")

    def img_picker_result(e: ft.FilePickerResultEvent):
        nonlocal image_original, encrypted_bytes
        if e.files:
            file_path = e.files[0].path
            with open(file_path, "rb") as f:
                image_original = f.read()
            encrypted_bytes = None
            img_display.src_base64 = base64.b64encode(image_original).decode()
            page.update()

    img_picker = ft.FilePicker(on_result=img_picker_result)
    page.overlay.append(img_picker)

    def pick_image(e):
        img_picker.pick_files(allow_multiple=False)

    def encrypt_image(e):
        nonlocal encrypted_bytes
        if image_original is None or not image_password.value:
            return
        encrypted_bytes = aes_encrypt_bytes(image_original, image_password.value)
        noise_png = encrypted_bytes_to_noise_png(encrypted_bytes)
        img_display.src_base64 = base64.b64encode(noise_png).decode()
        page.update()

    def decrypt_image(e):
        nonlocal encrypted_bytes
        if encrypted_bytes is None or not image_password.value:
            return
        decrypted = aes_decrypt_bytes(encrypted_bytes, image_password.value)
        img_display.src_base64 = base64.b64encode(decrypted).decode()
        page.update()

    image_tab = ft.Column([
        ft.ElevatedButton("Sélectionner image", on_click=pick_image),
        image_password,
        ft.Row([
            ft.ElevatedButton("Chiffrer", on_click=encrypt_image),
            ft.ElevatedButton("Déchiffrer", on_click=decrypt_image),
        ]),
        img_display
    ])

    # ---------- TABS ----------
    tabs = ft.Tabs(
        tabs=[
            ft.Tab(text="Vigenère", content=vigenere_tab),
            ft.Tab(text="AES", content=aes_tab),
            ft.Tab(text="RSA", content=rsa_tab),
            ft.Tab(text="Email 2FA", content=email_tab),
            ft.Tab(text="Image AES", content=image_tab),
        ],
        expand=1
    )

    page.add(tabs)

ft.app(target=main)
