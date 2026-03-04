import os
import time
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk
from tkinter import font as tkfont
import cv2
import numpy as np
from PIL import Image, ImageTk
from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing.image import img_to_array

from utils.crypto_utils import (
    generate_aes_key,
    aes_encrypt_bytes,
    aes_decrypt_bytes,
    generate_rsa_keypair,
    rsa_encrypt_bytes,
    rsa_decrypt_bytes
)

# ------------------- GLOBALS -------------------
aes_key = None
rsa_encrypted_aes_key = None
enc_img_b64 = None
selected_img = None
img_shape = None

# Load Tamper Detection CNN
IMG_SIZE = (128, 128)
model_path = "models/tamper_model.h5"
if not os.path.exists(model_path):
    messagebox.showerror("Error", f"Model file not found: {model_path}")
    exit()
tamper_model = load_model(model_path)

# Generate RSA keypair once
PUBLIC_BIN, PRIVATE_BIN = generate_rsa_keypair()
PUBLIC_HEX = PUBLIC_BIN.hex()
PRIVATE_HEX = PRIVATE_BIN.hex()


# ------------------- UTILS -------------------
def cv2_to_tk(cv_img, size=(200, 200)):
    cv_img = cv2.resize(cv_img, size)
    rgb = cv2.cvtColor(cv_img, cv2.COLOR_BGR2RGB)
    im = Image.fromarray(rgb)
    return ImageTk.PhotoImage(im)


def get_tamper_probabilities(cv_img):
    img_resized = cv2.resize(cv_img, IMG_SIZE)
    img_rgb = cv2.cvtColor(img_resized, cv2.COLOR_BGR2RGB)
    img_array = img_to_array(img_rgb) / 255.0
    img_array = np.expand_dims(img_array, axis=0)

    prob = tamper_model.predict(img_array)[0][0]  # single sigmoid output
    tampered_prob = prob * 100
    authentic_prob = 100 - tampered_prob
    return authentic_prob, tampered_prob


# ------------------- GUI FUNCTIONS -------------------
def select_image():
    global selected_img, img_shape
    path = filedialog.askopenfilename(filetypes=[("Images", "*.jpg *.jpeg *.png *.bmp")])
    if not path:
        return
    selected_img = cv2.imread(path)
    if selected_img is None:
        messagebox.showerror("Error", "Could not open image.")
        return

    img_shape = selected_img.shape
    lbl_orig_img.img_ref = cv2_to_tk(selected_img)
    lbl_orig_img.config(image=lbl_orig_img.img_ref)

    lbl_enc_img.config(image="")
    lbl_dec_img.config(image="")
    txt_console.delete("1.0", tk.END)
    txt_console.insert(tk.END, "Image selected successfully.\n")


def encrypt_image():
    global aes_key, rsa_encrypted_aes_key, enc_img_b64, selected_img
    if selected_img is None:
        messagebox.showwarning("Warning", "Please select an image first.")
        return

    start_time = time.time()

    # AES & RSA encryption
    aes_key = generate_aes_key()
    rsa_encrypted_aes_key = rsa_encrypt_bytes(aes_key, PUBLIC_BIN)
    _, buffer = cv2.imencode(".png", selected_img)
    enc_img_b64 = aes_encrypt_bytes(buffer.tobytes(), aes_key)

    # Display encrypted preview as static noise
    enc_preview = np.random.randint(0, 256, img_shape, dtype=np.uint8)
    lbl_enc_img.img_ref = cv2_to_tk(enc_preview)
    lbl_enc_img.config(image=lbl_enc_img.img_ref)

    # Encryption time
    end_time = time.time()
    txt_console.insert(tk.END, f"Encryption time: {end_time - start_time:.3f} seconds\n")

    # Tamper detection probabilities
    authentic_prob, tampered_prob = get_tamper_probabilities(selected_img)
    progress_auth['value'] = authentic_prob
    progress_tamper['value'] = tampered_prob
    txt_console.insert(tk.END, f"Authentic Probability: {authentic_prob:.2f}%\n")
    txt_console.insert(tk.END, f"Tampered Probability: {tampered_prob:.2f}%\n\n")
    txt_console.insert(tk.END, "Image encrypted successfully.\n")

    # Display AES & RSA keys
    txt_keys.delete("1.0", tk.END)
    txt_keys.insert(tk.END, f"AES Key (hex): {aes_key.hex()}\n")
    txt_keys.insert(tk.END, f"RSA Public Key (hex): {PUBLIC_HEX}\n")
    txt_keys.insert(tk.END, f"RSA Private Key (hex): {PRIVATE_HEX}\n")
    txt_keys.insert(tk.END, f"RSA Encrypted AES Key (hex, truncated): {rsa_encrypted_aes_key.hex()[:80]}...\n")


def decrypt_image():
    global enc_img_b64, rsa_encrypted_aes_key
    if enc_img_b64 is None or rsa_encrypted_aes_key is None:
        messagebox.showwarning("Warning", "Please encrypt the image first.")
        return

    user_aes_hex = simpledialog.askstring("AES Key Required", "Enter AES key (hex):")
    if not user_aes_hex:
        return
    user_rsa_priv_hex = simpledialog.askstring("RSA Private Key Required", "Enter RSA Private key (hex):")
    if not user_rsa_priv_hex:
        return

    start_time = time.time()
    try:
        recovered_aes_key = rsa_decrypt_bytes(rsa_encrypted_aes_key, bytes.fromhex(user_rsa_priv_hex))
        if recovered_aes_key != bytes.fromhex(user_aes_hex):
            messagebox.showerror("Error", "AES key mismatch! Cannot decrypt.")
            return

        dec_img_bytes = aes_decrypt_bytes(enc_img_b64, recovered_aes_key)
        dec_array = np.frombuffer(dec_img_bytes, dtype=np.uint8)
        dec_img = cv2.imdecode(dec_array, cv2.IMREAD_COLOR)

        lbl_dec_img.img_ref = cv2_to_tk(dec_img)
        lbl_dec_img.config(image=lbl_dec_img.img_ref)

        end_time = time.time()
        txt_console.insert(tk.END, f"Decryption time: {end_time - start_time:.3f} seconds\n")

        authentic_prob, tampered_prob = get_tamper_probabilities(dec_img)
        progress_auth['value'] = authentic_prob
        progress_tamper['value'] = tampered_prob
        txt_console.insert(tk.END, f"Authentic Probability: {authentic_prob:.2f}%\n")
        txt_console.insert(tk.END, f"Tampered Probability: {tampered_prob:.2f}%\n\n")
        txt_console.insert(tk.END, "Image decrypted successfully.\n")

    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed: {e}")


# ------------------- GUI -------------------
root = tk.Tk()
root.title("Hybrid Secure Image Transmission (AES + RSA)")
root.configure(bg="#e6f2ff")

heading_font = tkfont.Font(family="Helvetica", size=16, weight="bold")
lbl_heading = tk.Label(root, text="Hybrid Secure Image Transmission",
                       font=heading_font, bg="#e6f2ff", fg="black")
lbl_heading.pack(pady=10)

frm = tk.Frame(root, padx=10, pady=10, bg="#e6f2ff")
frm.pack()

# Buttons
btn_select = tk.Button(frm, text="Select Image", command=select_image,
                       width=20, height=2, bg="#004080", fg="white", font=("Arial", 10, "bold"))
btn_select.grid(row=0, column=0, padx=5, pady=5)
btn_encrypt = tk.Button(frm, text="Encrypt", command=encrypt_image,
                        width=20, height=2, bg="#006600", fg="white", font=("Arial", 10, "bold"))
btn_encrypt.grid(row=0, column=1, padx=5, pady=5)
btn_decrypt = tk.Button(frm, text="Decrypt", command=decrypt_image,
                        width=20, height=2, bg="#800000", fg="white", font=("Arial", 10, "bold"))
btn_decrypt.grid(row=0, column=2, padx=5, pady=5)

# Image frames
img_frame = tk.Frame(frm, bg="#e6f2ff")
img_frame.grid(row=1, column=0, columnspan=3)
title_font = tkfont.Font(family="Arial", size=11, weight="bold")
lbl_orig_title = tk.Label(img_frame, text="Original Image", font=title_font, bg="#e6f2ff")
lbl_orig_title.grid(row=0, column=0, padx=10, pady=(0, 5))
lbl_enc_title = tk.Label(img_frame, text="Encrypted Image", font=title_font, bg="#e6f2ff")
lbl_enc_title.grid(row=0, column=1, padx=10, pady=(0, 5))
lbl_dec_title = tk.Label(img_frame, text="Decrypted Image", font=title_font, bg="#e6f2ff")
lbl_dec_title.grid(row=0, column=2, padx=10, pady=(0, 5))
lbl_orig_img = tk.Label(img_frame, bg="#e6f2ff")
lbl_orig_img.grid(row=1, column=0, padx=10)
lbl_enc_img = tk.Label(img_frame, bg="#e6f2ff")
lbl_enc_img.grid(row=1, column=1, padx=10)
lbl_dec_img = tk.Label(img_frame, bg="#e6f2ff")
lbl_dec_img.grid(row=1, column=2, padx=10)

# Probability bars
prob_frame = tk.Frame(frm, bg="#e6f2ff")
prob_frame.grid(row=2, column=0, columnspan=3, pady=(5, 10))
lbl_auth = tk.Label(prob_frame, text="Authentic Probability:", font=("Arial", 10, "bold"), bg="#e6f2ff")
lbl_auth.grid(row=0, column=0, sticky="w", padx=5)
progress_auth = ttk.Progressbar(prob_frame, length=250, maximum=100)
progress_auth.grid(row=0, column=1, padx=5)
lbl_tamper = tk.Label(prob_frame, text="Tampered Probability:", font=("Arial", 10, "bold"), bg="#e6f2ff")
lbl_tamper.grid(row=1, column=0, sticky="w", padx=5)
progress_tamper = ttk.Progressbar(prob_frame, length=250, maximum=100)
progress_tamper.grid(row=1, column=1, padx=5)

# Keys display
lbl_keys = tk.Label(frm, text="Keys (Hex):", font=("Arial", 10, "bold"), bg="#e6f2ff")
lbl_keys.grid(row=3, column=0, sticky="w", pady=5)
txt_keys = tk.Text(frm, width=80, height=6, bg="white", fg="black")
txt_keys.grid(row=4, column=0, columnspan=3, pady=5)

# Console log
txt_console = tk.Text(frm, width=80, height=14, bg="white", fg="black")
txt_console.grid(row=5, column=0, columnspan=3, pady=10)

root.mainloop()
