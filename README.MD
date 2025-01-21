# SkyCrypt 🔐

SkyCrypt es una aplicación de cifrado y descifrado de archivos desarrollada en Python. Utiliza el algoritmo **AES-256** para cifrar archivos de manera segura y genera un código **OTP** (One-Time Password) para validar el descifrado. ¡Protege tus archivos confidenciales con SkyCrypt! 🚀

---

## Características principales ✨

- **Cifrado seguro**: Utiliza el algoritmo AES-256 para cifrar archivos.
- **Código OTP**: Genera un código de un solo uso para validar el descifrado.
- **Llave dinámica**: Cada archivo cifrado tiene una llave única.
- **Interfaz gráfica**: Fácil de usar con una interfaz amigable.
- **Protección contra fuerza bruta**: Si se superan 3 intentos fallidos, el archivo cifrado se borra permanentemente. 🛡️

---

## Requisitos 📋

- Python 3.8 o superior.
- Bibliotecas necesarias:
  - `pycryptodome` (para el cifrado AES).
  - `pyotp` (para generar códigos OTP).
  - `tkinter` (para la interfaz gráfica).

---

## Instalación 🛠️

1. Clona este repositorio:

    ```bash
    git clone https://github.com/JkDevArg/SkyCrypt.git
    cd SkyCrypt
    ```

2. Crea un entorno virtual (opcional pero recomendado):

    ```bash
    python -m venv venv
    ```

    Activa el entorno virtual:

    ```bash
    source venv/bin/activate
    ```

    Instala las dependencias:

    ```bash
    pip install -r requirements.txt
    ```

    Ejecuta la aplicación:

    ```bash
    python main.py
    ```

---

## Uso 🖥️

Cifrar un archivo:

- Haz clic en "Cifrar Archivo".

- Selecciona el archivo que deseas cifrar.

- El archivo se cifrará y se generará un código OTP.

- Guarda el código OTP en un lugar seguro. 🔑

Descifrar un archivo:

- Haz clic en "Descifrar Archivo".

- Selecciona el archivo cifrado (con extensión .enc).

- Ingresa el código OTP generado durante el cifrado.

- Si el código es correcto, el archivo se descifrará y se restaurará a su estado original. ✅

Protección contra fuerza bruta:

- Si ingresas un código OTP incorrecto 3 veces, el archivo cifrado se borrará permanentemente. 🚫

---

## Demo 🎥

[Ver video demo](https://youtu.be/XpkSnRKor5g)

---

## Contribuciones 🤝

¡Las contribuciones son bienvenidas! Si deseas mejorar SkyCrypt, sigue estos pasos:

Haz un fork del repositorio.

Crea una rama con tu nueva funcionalidad (git checkout -b nueva-funcionalidad).

Realiza tus cambios y haz commit (git commit -m 'Añadir nueva funcionalidad').

Haz push a la rama (git push origin nueva-funcionalidad).

Abre un Pull Request.

---

## Contacto 📩

Developer: Joaquin Centurión

GitHub: [JkDevArg](https://github.com/JkDevArg)

LinkedIn: [Joaquin Centurión](https://www.linkedin.com/in/joaquincenturion/)
