import tkinter as tk
from tkinter import messagebox
import random
import string

# Generate a random cipher key (substitution cipher)
def generate_cipher_key():
    alphabet = string.ascii_lowercase
    shuffled_alphabet = random.sample(alphabet, len(alphabet))
    cipher_key = dict(zip(alphabet, shuffled_alphabet))  # Map each letter to another letter
    return cipher_key

# Encrypt function using the custom cipher
def encrypt(text, cipher_key):
    encrypted_text = ''.join([cipher_key.get(c, c) for c in text.lower()])  # Encrypt each character
    return encrypted_text

# Decrypt function using the custom cipher (reverse the cipher)
def decrypt(text, cipher_key):
    # Reverse the cipher key to map encrypted letters back to original ones
    reverse_cipher_key = {v: k for k, v in cipher_key.items()}
    decrypted_text = ''.join([reverse_cipher_key.get(c, c) for c in text])  # Decrypt each character
    return decrypted_text

# Encrypt and show result
def on_encrypt():
    text = entry.get()
    if text:
        cipher_key = generate_cipher_key()  # Generate a random cipher key
        encrypted_text = encrypt(text, cipher_key)
        encrypted_label.config(text="Encrypted Text: " + encrypted_text)
        decrypt_button.config(state=tk.NORMAL)  # Enable the decrypt button
        decrypt_button.config(command=lambda: on_decrypt(encrypted_text, cipher_key))  # Set decryption function
    else:
        messagebox.showerror("Input Error", "Please enter some text to encrypt.")

# Decrypt and show result
def on_decrypt(encrypted_text, cipher_key):
    decrypted_text = decrypt(encrypted_text, cipher_key)
    decrypted_label.config(text="Decrypted Text: " + decrypted_text)

# Create the main window
root = tk.Tk()
root.title("IXR CIPHER ENCRYPTER / DECRYPTER")

# Set up the window size and background colour
root.geometry("700x600")
root.config(bg="#232526")

# Title label
title_label = tk.Label(root, text="IXR CIPHER", font=("Helvetica", 22, "bold"), fg="#fff", bg="#232526")
title_label.pack(pady=30)

# Text input field
entry_label = tk.Label(root, text="Enter text to encrypt:", font=("Helvetica", 14), fg="#fff", bg="#232526")
entry_label.pack(pady=5)

entry = tk.Entry(root, width=50, font=("Helvetica", 14), bg="#333", fg="#fff", relief="flat", bd=2)
entry.pack(pady=10)

# Hover effects for buttons
def on_enter(e):
    e.config(bg="#00b4ff", fg="#fff")

def on_leave(e):
    e.config(bg="#007bb5", fg="#fff")

# Encrypt Button
encrypt_button = tk.Button(root, text="Encrypt", width=20, font=("Helvetica", 14, "bold"), bg="#007bb5", fg="#fff", relief="raised", bd=5, command=on_encrypt)
encrypt_button.bind("<Enter>", on_enter)
encrypt_button.bind("<Leave>", on_leave)
encrypt_button.pack(pady=20)

# Encrypted text display
encrypted_label = tk.Label(root, text="Encrypted Text: ", font=("Helvetica", 12), fg="#fff", bg="#232526", wraplength=600)
encrypted_label.pack(pady=10)

# Decrypt Button (Initially disabled)
decrypt_button = tk.Button(root, text="Decrypt", width=20, font=("Helvetica", 14, "bold"), bg="#e74c3c", fg="#fff", relief="raised", bd=5, state=tk.DISABLED)
decrypt_button.bind("<Enter>", on_enter)
decrypt_button.bind("<Leave>", on_leave)
decrypt_button.pack(pady=20)

# Decrypted text display
decrypted_label = tk.Label(root, text="Decrypted Text: ", font=("Helvetica", 12), fg="#fff", bg="#232526", wraplength=600)
decrypted_label.pack(pady=10)

# Footer
footer_label = tk.Label(root, text="Created by IXRMTT", font=("Helvetica", 10), fg="#bbb", bg="#232526")
footer_label.pack(side=tk.BOTTOM, pady=10)

# Start the Tkinter event loop
root.mainloop()
