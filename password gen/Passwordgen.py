import os
import random
import string
import tkinter as tk
from tkinter import messagebox
from datetime import datetime
from cryptography.fernet import Fernet

# === SETTINGS ===
LOG_FILE = "password_log.txt"
KEY_FILE = "secret.key"
MAX_LOG_ENTRIES = 100

# === ENCRYPTION SETUP ===
def load_or_create_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as key_file:
            key = key_file.read()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as key_file:
            key_file.write(key)
    return Fernet(key)

fernet = load_or_create_key()

def encrypt(text):
    return fernet.encrypt(text.encode()).decode()

def decrypt(token):
    return fernet.decrypt(token.encode()).decode()

# === PASSWORD GENERATOR ===
def generate_password(length=12, use_uppercase=True, use_digits=True, use_special=True):
    lower = string.ascii_lowercase
    upper = string.ascii_uppercase if use_uppercase else ''
    digits = string.digits if use_digits else ''
    special = string.punctuation if use_special else ''
    
    all_characters = lower + upper + digits + special
    
    if not all_characters:
        return "Error: No character set selected!"
    
    password = ''.join(random.choice(all_characters) for _ in range(length))
    return password

# === LOGGING FUNCTIONS ===
def log_password(password):
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            lines = f.readlines()
    else:
        lines = []
    
    # Decrypt existing passwords for duplicate checking
    existing_passwords = []
    for line in lines:
        try:
            decrypted = decrypt(line.strip().split('] ')[1])
            existing_passwords.append(decrypted)
        except Exception:
            continue

    if password in existing_passwords:
        print("Duplicate password detected, not logging.")
        return
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    encrypted_password = encrypt(password)
    new_entry = f"[{timestamp}] {encrypted_password}\n"
    lines.append(new_entry)
    
    if len(lines) > MAX_LOG_ENTRIES:
        lines = lines[-MAX_LOG_ENTRIES:]
    
    with open(LOG_FILE, "w") as f:
        f.writelines(lines)

def view_log():
    try:
        with open(LOG_FILE, "r") as f:
            lines = f.readlines()
        
        if not lines:
            messagebox.showinfo("Password Log", "The log is currently empty.")
            return
        
        decrypted_entries = []
        for line in lines:
            if '] ' in line:
                timestamp, encrypted_part = line.split('] ')
                timestamp = timestamp.strip('[')
                try:
                    decrypted_password = decrypt(encrypted_part.strip())
                    decrypted_entries.append(f"[{timestamp}] {decrypted_password}")
                except Exception:
                    decrypted_entries.append(f"[{timestamp}] [Decryption Failed]")
        
        log_window = tk.Toplevel(root)
        log_window.title("Password Log")
        log_window.geometry("500x400")
        
        text_area = tk.Text(log_window, wrap="word")
        text_area.pack(expand=True, fill="both")
        text_area.insert("1.0", "\n".join(decrypted_entries))
        text_area.config(state="disabled")
        
    except FileNotFoundError:
        messagebox.showinfo("Password Log", "No log file found yet!")

def clear_log():
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w") as f:
            f.truncate(0)
        messagebox.showinfo("Clear Log", "Password log has been cleared.")

# === BUTTON FUNCTIONS ===
def generate():
    try:
        length = int(length_entry.get())
        if length < 1:
            messagebox.showerror("Error", "Password length must be at least 1.")
            return
    except ValueError:
        messagebox.showerror("Error", "Invalid length input.")
        return
    
    use_uppercase = uppercase_var.get()
    use_digits = digits_var.get()
    use_special = special_var.get()
    
    password = generate_password(length, use_uppercase, use_digits, use_special)
    
    result_label.config(text=f"Generated Password: {password}")
    
    # Save to log
    if "Error" not in password:
        log_password(password)

def copy_to_clipboard():
    password = result_label.cget("text").replace("Generated Password: ", "")
    if password and "Error" not in password:
        root.clipboard_clear()
        root.clipboard_append(password)
        root.update()
        messagebox.showinfo("Copy", "Password copied to clipboard!")

def close_app():
    root.destroy()

# === GUI SETUP ===
root = tk.Tk()
root.title("Secure Password Generator")
root.geometry("400x400")

tk.Label(root, text="Password Length:").pack(pady=5)
length_entry = tk.Entry(root)
length_entry.pack()
length_entry.insert(0, "12")

uppercase_var = tk.BooleanVar()
digits_var = tk.BooleanVar()
special_var = tk.BooleanVar()

tk.Checkbutton(root, text="Include Uppercase Letters", variable=uppercase_var).pack()
tk.Checkbutton(root, text="Include Numbers", variable=digits_var).pack()
tk.Checkbutton(root, text="Include Special Characters", variable=special_var).pack()

generate_button = tk.Button(root, text="Generate Password", command=generate)
generate_button.pack(pady=5)

copy_button = tk.Button(root, text="Copy Password", command=copy_to_clipboard)
copy_button.pack(pady=5)

view_log_button = tk.Button(root, text="View Password Log", command=view_log)
view_log_button.pack(pady=5)

clear_log_button = tk.Button(root, text="Clear Password Log", command=clear_log)
clear_log_button.pack(pady=5)

result_label = tk.Label(root, text="", wraplength=380)
result_label.pack(pady=10)

exit_button = tk.Button(root, text="Exit", command=close_app)
exit_button.pack(pady=5)

root.mainloop()
