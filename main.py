# main_gui.py
# Calculadora Hash con interfaz moderna usando ttkbootstrap

import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import messagebox

# Importar tus funciones
from sha1 import sha1
from md4 import md4_hash
from md5 import md5_hash
from sha256 import sha256_hash

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


        if algoritmo == "SHA-1":
            resultado = sha1(texto)
        elif algoritmo == "MD4":
            resultado = md4_hash(texto)
        elif algoritmo == "MD5":
            resultado = md5_hash(texto)
        elif algoritmo == "SHA-256":
            resultado = sha256_hash(texto)
        else:
            messagebox.showerror("Error", "Seleccione un algoritmo")
            return

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
    size=(650, 430)
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
    values=["MD4", "MD5", "SHA-1", "SHA-256"],
    width=20,
    state="readonly"
)
combo_algo.grid(row=0, column=1, padx=5)
combo_algo.current(0)

# Cuadro de entrada
ttk.Label(app, text="Ingrese texto:", font=("Segoe UI", 12)).pack()

entrada_texto = ttk.Text(app, height=5, width=70, font=("Consolas", 11))
entrada_texto.pack(pady=5)

# Botón calcular
ttk.Button(app, text="Calcular Hash", bootstyle=PRIMARY, command=calcular_hash).pack(pady=10)

# Cuadro de salida
ttk.Label(app, text="Resultado:", font=("Segoe UI", 12)).pack()

salida_hash = ttk.Text(app, height=2, width=70, font=("Consolas", 11))
salida_hash.pack(pady=5)
salida_hash.configure(state="disabled")

app.mainloop()
