import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
import pyotp
import uuid

# Guardamos la llave en un archivo
def save_key(key_path, key):
    with open(key_path, 'wb') as f:
        f.write(key)

# Cargamos la llave desde un archivo, esto se puede cambiar por ej usando una base de datos...
def load_key(key_path):
    with open(key_path, 'rb') as f:
        return f.read()

# Ciframos el archivo
def enc_file(path_file, key, key_name):
    cipher = AES.new(key, AES.MODE_EAX)
    with open(path_file, 'rb') as f:
        date = f.read()
    ciphertext, tag = cipher.encrypt_and_digest(date)
    # Guardamos el archivo cifrado con el nombre de la llave
    encrypted_file_path = f"{path_file}.{key_name}.enc"
    with open(encrypted_file_path, 'wb') as f:
        [f.write(x) for x in (cipher.nonce, tag, ciphertext)]
    os.remove(path_file)  # Se elimina el archivo original
    return encrypted_file_path  # Se devuelve al ruta del archivo cifrado

# Descifrando el archivo
def desenc_file(path_file, key):
    with open(path_file, 'rb') as f:
        nonce, tag, ciphertext = [f.read(x) for x in (16, 16, -1)]
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    date = cipher.decrypt_and_verify(ciphertext, tag)

    # Se vuelve a colocar el nombre del archivo original
    original_file_path = path_file.rsplit('.', 2)[0]
    with open(original_file_path, 'wb') as f:
        f.write(date)
    os.remove(path_file)

# Generando un código OTP
def generate_otp():
    clave_base32 = pyotp.random_base32()  # Generar una clave base32 para OTP
    totp = pyotp.TOTP(clave_base32)
    return totp.now()  # Se devuelve el código OTP

class App:
    def __init__(self, root):
        self.root = root
        self.root.title("SkyCrypt")

        # Esto esta demás es para que no maximizen la ventana
        self.root.resizable(False, False)

        # Variables
        self.key = None
        self.code_otp = None
        self.key_name = None
        self.intentos = 3  # Contador de intentos puedes poner lo que desees

        # Acciones
        self.btn_enc = tk.Button(root, text="Cifrar Archivo", command=self.enc)
        self.btn_enc.pack(pady=15, padx=15)

        self.btn_desenc = tk.Button(root, text="Descifrar Archivo", command=self.desenc)
        self.btn_desenc.pack(pady=15, padx=15)

        # Información :v
        self.text_copyright = tk.Text(root, height=4)
        self.text_copyright.pack()
        self.text_copyright.insert(tk.END, "Created by Joaquin Centurión\nGithub: https://github.com/JkDevArg \nLinkedin: https://www.linkedin.com/in/joaquincenturion/ \nSkyCrypt v1.0")
        self.text_copyright.config(state=tk.DISABLED)
        self.text_copyright.tag_configure("copyright", foreground="grey")
        self.text_copyright.tag_add("copyright", "1.0", "end")

        self.root.mainloop()

    def enc(self):
        path_file = filedialog.askopenfilename(title="Seleccionar archivo para cifrar")
        if path_file:
            # Generando llave única y código OTP
            self.key = get_random_bytes(32)  # AES-256
            self.key_name = str(uuid.uuid4())  # Nombre único para la llave
            self.code_otp = generate_otp()  # Código OTP

            # Se guarda la llave en un archivo con extensión .key
            key_path = f"{self.key_name}.key"
            save_key(key_path, self.key)

            # Cifrando el archivo...
            encrypted_file_path = enc_file(path_file, self.key, self.key_name)

            # Se muestra en la terminal el OTP como prueba, esto se puede enviar por cualquier tipo de medio
            print(f"Código OTP para descifrar: {self.code_otp}")
            print(f"Llave guardada en: {key_path}")
            print(f"Archivo cifrado guardado en: {encrypted_file_path}")

            messagebox.showinfo("Éxito", "Archivo cifrado correctamente.")

    def desenc(self):
        path_file = filedialog.askopenfilename(title="Seleccionar archivo para descifrar")
        if path_file:
            # Se valida que el archivo a descifrar tenga la extensión .enc
            if not path_file.endswith('.enc'):
                messagebox.showerror("Error", "El archivo no es válido para descifrar. Debe tener la extensión .enc")
                return

            # Extraemos el nombre de la llave
            key_name = path_file.split('.')[-2]
            key_path = f"{key_name}.key"

            # La llave existe?
            if not os.path.exists(key_path):
                messagebox.showerror("Error", "No se encontró la llave para descifrar este archivo.")
                return

            # Cargando la llave...
            key = load_key(key_path)

            # Validando el código OTP...
            insert_code = simpledialog.askstring("Código OTP", "Ingrese el código OTP:")
            if insert_code == self.code_otp:
                desenc_file(path_file, key)
                # Se borra la llave después de descifrar el archivo
                os.remove(key_path)
                messagebox.showinfo("Éxito", "Archivo descifrado correctamente.")
            else:
                self.intentos -= 1  # Se reduce el número de intentos
                if self.intentos > 0:
                    messagebox.showwarning("Error", f"Código OTP incorrecto. Te quedan {self.intentos} intentos.")
                else:
                    # Si se agotan los intentos, se borra el archivo cifrado
                    os.remove(path_file)
                    os.remove(key_path)
                    messagebox.showerror("Error", "Intentos fallidos, archivo borrado.")

if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()