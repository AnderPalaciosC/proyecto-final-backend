# test_cart.py
from flask import Flask, session
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = '2163'

with app.test_request_context():
    # Inicializar el carrito
    session['cart'] = {}

    # Añadir un producto
    producto_id = 1
    cantidad = 2
    if producto_id in session['cart']:
        session['cart'][producto_id] += cantidad
    else:
        session['cart'][producto_id] = cantidad

    # Imprimir el carrito
    print("Contenido del carrito:", session.get('cart'))