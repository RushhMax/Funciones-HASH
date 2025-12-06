# main_gui.py
# Calculadora Hash con interfaz moderna usando ttkbootstrap

import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import messagebox

# ===========================
# IMPORTAR FUNCIONES
# ===========================
from sha1 import sha1
from md4 import md4_hash
from md5 import md5_hash
<<<<<<< HEAD
from sha256 import sha256_hash
=======
#from sha256 import sha256_hash
from sha3 import sha3_256
from hmac_custom import hmac_custom

>>>>>>> 3731a376c20b6021e01a0d347b973b5aab2a8521

# ===========================
# VALIDACIÓN GENERAL
# ===========================

def validar_entrada(texto: str):
    if not isinstance(texto, str):
        raise TypeError("La entrada debe ser texto (str).")
    if texto.strip() == "":
        raise ValueError("La entrada no puede estar vacía.")
    return texto


# ===========================
# FUNCIÓN PRINCIPAL DE CÁLCULO
# ===========================

def calcular_hash():
    texto = entrada_texto.get("1.0", "end").strip()
    algoritmo = seleccion_algo.get()

    try:
        validar_entrada(texto)

        # MD4
        if algoritmo == "MD4":
            resultado = md4_hash(texto)

        # MD5
        elif algoritmo == "MD5":
            resultado = md5_hash(texto)
<<<<<<< HEAD
        elif algoritmo == "SHA-256":
            resultado = sha256_hash(texto)
=======

        # SHA-1
        elif algoritmo == "SHA-1":
            resultado = sha1(texto)

        # SHA-256
        #elif algoritmo == "SHA-256":
         #   resultado = sha256_hash(texto)

        # SHA-3 (Keccak-256)
        elif algoritmo == "SHA-3":
            resultado = sha3_256(texto)

        # HMAC con SHA-256
        elif algoritmo == "HMAC (SHA-256)":
            clave = "clave_secreta"  # puedes hacer un cuadro adicional si quieres
            resultado = hmac_custom(clave, texto, "sha256")

        # HMAC con MD5
        elif algoritmo == "HMAC (MD5)":
            clave = "clave_secreta"
            resultado = hmac_custom(clave, texto, "md5")

>>>>>>> 3731a376c20b6021e01a0d347b973b5aab2a8521
        else:
            messagebox.showerror("Error", "Seleccione un algoritmo válido.")
            return

        # Mostrar resultado
        salida_hash.configure(state="normal")
        salida_hash.delete("1.0", "end")
        salida_hash.insert("end", resultado)
        salida_hash.configure(state="disabled")

    except Exception as e:
        messagebox.showerror("Error", str(e))


# ===========================
# INTERFAZ
# ===========================

app = ttk.Window(
    title="Calculadora Hash",
    themename="cyborg",  # otros: darkly, journal, flatly, vapor, litera, minty
    size=(700, 480)
)

ttk.Label(app, text="Calculadora de Funciones Hash", font=("Segoe UI", 18, "bold")).pack(pady=10)

# Selector de algoritmo
frame_top = ttk.Frame(app)
frame_top.pack(pady=10)

ttk.Label(frame_top, text="Algoritmo:", font=("Segoe UI", 12)).grid(row=0, column=0, padx=10)

seleccion_algo = ttk.StringVar()

combo_algo = ttk.Combobox(
    frame_top,
    textvariable=seleccion_algo,
    values=[
        "MD4",
        "MD5",
        "SHA-1",
        "SHA-256",
        "SHA-3",
        "HMAC (SHA-256)",
        "HMAC (MD5)"
    ],
    width=25,
    state="readonly"
)
combo_algo.grid(row=0, column=1, padx=5)
combo_algo.current(0)

# Cuadro de entrada
ttk.Label(app, text="Ingrese texto:", font=("Segoe UI", 12)).pack()

entrada_texto = ttk.Text(app, height=5, width=75, font=("Consolas", 11))
entrada_texto.pack(pady=5)

# Botón calcular
ttk.Button(app, text="Calcular Hash", bootstyle=PRIMARY, command=calcular_hash).pack(pady=10)

# Cuadro de salida
ttk.Label(app, text="Resultado:", font=("Segoe UI", 12)).pack()

salida_hash = ttk.Text(app, height=3, width=75, font=("Consolas", 11))
salida_hash.pack(pady=5)
salida_hash.configure(state="disabled")

app.mainloop()
