import tkinter as tk
from tkinter import messagebox
import string


def generate_shift_values(keyword, k, m):
    shift_values = []
    for char in keyword:
        if char.isupper():
            if char in string.ascii_uppercase:
                shift_values.append((ord(char) - 65 + k) % m)
            elif char in 'АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ':
                shift_values.append((ord(char) - 1040 + k) % m)
        elif char.islower():
            if char in string.ascii_lowercase:
                shift_values.append((ord(char) - 97 + k) % m)
            elif char in 'абвгдеёжзийклмнопрстуфхцчшщъыьэюя':
                shift_values.append((ord(char) - 1072 + k) % m)
        else:
            shift_values.append(0)
    return shift_values


def caesar_cipher_with_keyword(text, keyword, k, decrypt=False):
    result = ""
    m = 32 if any(c in 'абвгдеёжзийклмнопрстуфхцчшщъыьэюяАБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ' for c in text) else 26
    shift_values = generate_shift_values(keyword, k, m)
    keyword_length = len(shift_values)

    for i in range(len(text)):
        char = text[i]
        shift = shift_values[i % keyword_length]
        if decrypt:
            shift = -shift

        if char.isupper():
            if char in string.ascii_uppercase:
                result += chr((ord(char) + shift - 65) % 26 + 65)
            elif char in 'АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ':
                result += chr((ord(char) + shift - 1040) % 32 + 1040)
        elif char.islower():
            if char in string.ascii_lowercase:
                result += chr((ord(char) + shift - 97) % 26 + 97)
            elif char in 'абвгдеёжзийклмнопрстуфхцчшщъыьэюя':
                result += chr((ord(char) + shift - 1072) % 32 + 1072)
        else:
            result += char
    return result


def is_valid_char(c, alphabet):
    return all(char in alphabet for char in c)


def validate_entry(*args):
    text = keyword_entry.get()
    if is_valid_char(text, string.ascii_letters):
        m = 26
    elif is_valid_char(text, 'абвгдеёжзийклмнопрстуфхцчшщъыьэюяАБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ'):
        m = 32
    else:
        messagebox.showerror("Неправильный ввод", "Введите только латиницу или только кириллицу.")
        keyword_entry.delete(0, tk.END)
        return
    try:
        k = int(k_entry.get())
        if not (0 <= k <= m - 1):
            raise ValueError
    except ValueError:
        messagebox.showerror("Неправильный ввод", f"K должно быть целым числом в пределах от 0 до {m - 1}")
        return


def encrypt():
    validate_entry()
    keyword = keyword_entry.get().strip()
    k = int(k_entry.get())
    message = message_entry.get("1.0", tk.END).strip()
    encrypted_message = caesar_cipher_with_keyword(message, keyword, k)
    result_entry.delete("1.0", tk.END)
    result_entry.insert(tk.END, encrypted_message)


def decrypt():
    validate_entry()
    keyword = keyword_entry.get().strip()
    k = int(k_entry.get())
    message = message_entry.get("1.0", tk.END).strip()
    decrypted_message = caesar_cipher_with_keyword(message, keyword, k, decrypt=True)
    result_entry.delete("1.0", tk.END)
    result_entry.insert(tk.END, decrypted_message)


app = tk.Tk()
app.title("Шифр Цезаря с ключом-словом и числом")

tk.Label(app, text="Ключевое слово:").grid(row=0, column=0, padx=10, pady=10)
keyword_entry = tk.Entry(app)
keyword_entry.grid(row=0, column=1, padx=10, pady=10)

tk.Label(app, text="K:").grid(row=1, column=0, padx=10, pady=10)
k_entry = tk.Spinbox(app, from_=0, to=32)
k_entry.grid(row=1, column=1, padx=10, pady=10)

tk.Label(app, text="Сообщение:").grid(row=2, column=0, padx=10, pady=10)
message_entry = tk.Text(app, height=5, width=30)
message_entry.grid(row=2, column=1, padx=10, pady=10)

encrypt_button = tk.Button(app, text="Зашифровать", command=encrypt)
encrypt_button.grid(row=3, column=0, padx=10, pady=10)

decrypt_button = tk.Button(app, text="Расшифровать", command=decrypt)
decrypt_button.grid(row=3, column=1, padx=10, pady=10)

tk.Label(app, text="Результат:").grid(row=4, column=0, padx=10, pady=10)
result_entry = tk.Text(app, height=5, width=30)
result_entry.grid(row=4, column=1, padx=10, pady=10)

app.mainloop()
