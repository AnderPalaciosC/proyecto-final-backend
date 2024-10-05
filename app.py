from flask import Flask, render_template, redirect, url_for, request, session, flash, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_cors import CORS
from flask_session import Session
from werkzeug.security import generate_password_hash, check_password_hash
import mysql.connector, re, os
import pandas as pd
from werkzeug.utils import secure_filename

app = Flask(__name__)

UPLOAD_FOLDER = 'uploads/'
ALLOWED_EXTENSIONS = {'csv', 'xlsx'}

app.secret_key = '2163'
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SECRET_KEY'] = '2163'
app.config['SESSION_PERMANENT'] = False
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
Session(app)
CORS(app, supports_credentials=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Configuración de Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Crear un modelo de usuario
class User(UserMixin):
    def __init__(self, id, rol=None, username=None, email=None):
        self.id = id
        self.rol = rol  # Agregar el rol
        self.username = username  # Agregar otros atributos, como el nombre de usuario
        self.email = email  # Incluir el email si se necesita

    def get_id(self):
        return str(self.id)

    @property
    def is_authenticated(self):
        # Devuelve True siempre que el ID del usuario esté presente
        return self.id is not None

@login_manager.user_loader
def load_user(user_id):
    cnx = get_db_connection()  # Asegurarse que se esta usando la función correcta para obtener la conexión a la base de datos
    cursor = cnx.cursor(dictionary=True)
    
    # Consultar la base de datos para obtener la información del usuario
    cursor.execute('SELECT id, rol, username, email FROM usuarios WHERE id = %s', (user_id,))
    user_data = cursor.fetchone()
    cnx.close()

    if user_data:
        # Retornar el objeto User con los datos del usuario autenticado, incluyendo el rol y otros atributos
        return User(
            user_data['id'],
            rol=user_data.get('rol'),  # Obtenemos el rol del usuario
            username=user_data.get('username'),  # Incluir el nombre de usuario
            email=user_data.get('email')  # Incluir el email
        )
    return None

# Configuración de la conexión a la base de datos MySQL
config = {
    'user': 'root',
    'password': '2163',
    'host': '127.0.0.1',
    'database': 'tienda_apc'
}

def get_db_connection():
    connection = mysql.connector.connect(
        host=config['host'],
        user=config['user'],
        password=config['password'],
        database=config['database']
    )
    return connection

def guardar_carrito_usuario(user_id, carrito):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM user_cart WHERE user_id = %s', (user_id,))
    for producto_id, cantidad in carrito.items():
        cursor.execute('INSERT INTO user_cart (user_id, producto_id, cantidad) VALUES (%s, %s, %s)', (user_id, producto_id, cantidad))
    conn.commit()
    cursor.close()
    conn.close()

def cargar_carrito_usuario(user_id):
    conn = None
    try:
        conn = get_db_connection()  # Conexión a la base de datos
        cursor = conn.cursor(dictionary=True)

        # Obtener los productos y cantidades del carrito del usuario
        cursor.execute('SELECT producto_id, cantidad FROM user_cart WHERE user_id = %s', (user_id,))
        carrito = {str(item['producto_id']): item['cantidad'] for item in cursor.fetchall()}

        return carrito if carrito else {}

    except Exception as e:
        print(f"Error al cargar el carrito del usuario {user_id}: {e}")
        return {}

    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

# Función para validar correo electrónico
def es_correo_valido(correo):
    regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(regex, correo)

# Función para validar contraseñas seguras
def es_contrasena_segura(contrasena):
    if len(contrasena) < 8:
        return False
    if not any(char.isdigit() for char in contrasena):
        return False
    if not any(char.isalpha() for char in contrasena):
        return False
    return True

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/check_session', methods=['GET'])
def check_session():
    if current_user.is_authenticated:
        return jsonify({
            "_fresh": current_user.is_authenticated,
            "cart": session.get('cart', {})
        })
    else:
        return jsonify({
            "_fresh": False,
            "cart": session.get('cart', {})
        })

@app.route('/profile')
def profile():
    return render_template('profile.html')

@app.route('/api/check_session', methods=['GET'])
def api_check_session():
    if current_user.is_authenticated:
        return jsonify({
            'usuario': {
                'id': current_user.id,
                'nombre': current_user.nombre if hasattr(current_user, 'nombre') else 'Usuario',
                'email': current_user.email if hasattr(current_user, 'email') else 'Sin email',
                'rol': current_user.rol if hasattr(current_user, 'rol') else 'usuario'
            }
        }), 200
    else:
        return jsonify({'usuario': None}), 200

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        cnx = get_db_connection()
        cursor = cnx.cursor(dictionary=True)
        cursor.execute('SELECT id, password FROM usuarios WHERE username = %s', (username,))
        user = cursor.fetchone()
        if user and check_password_hash(user['password'], password):
            login_user(User(user['id']))
            session['cart'] = cargar_carrito_usuario(user['id'])
            session.modified = True
            flash('Sesión iniciada correctamente.', 'success')
            cnx.close()
            return redirect(url_for('profile'))
        cnx.close()
        flash('Usuario o contraseña incorrectos', 'danger')
        return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.json
    email = data.get('email') 
    password = data.get('password')

    cnx = get_db_connection()
    cursor = cnx.cursor(dictionary=True)
    
    # Verificar si el usuario existe en la base de datos usando el correo
    cursor.execute('SELECT id, password_hash FROM usuarios WHERE email = %s', (email,))
    user = cursor.fetchone()
    
    if user and check_password_hash(user['password_hash'], password):
        # Crear el objeto de usuario para Flask-Login
        usuario_obj = User(user['id'])
        login_user(usuario_obj)  # Iniciar la sesión del usuario

        # Cargar el carrito del usuario después de iniciar sesión
        carrito_usuario = cargar_carrito_usuario(user['id'])
        if carrito_usuario:
            session['cart'] = carrito_usuario  # Guardar el carrito del usuario en la sesión
        else:
            session['cart'] = []  # Si no hay carrito guardado, iniciar uno vacío

        session.modified = True  # Asegurar que Flask sepa que la sesión ha sido modificada

        # Cerrar la conexión a la base de datos
        cursor.close()
        cnx.close()
        
        return jsonify({'message': 'Sesión iniciada correctamente'}), 200
    
    # Cerrar la conexión a la base de datos en caso de error
    cursor.close()
    cnx.close()
    
    return jsonify({'error': 'Correo o contraseña incorrectos'}), 401

@app.route('/logout')
@login_required
def logout():
    if 'cart' in session:
        guardar_carrito_usuario(current_user.id, session['cart'])
    session.pop('cart', None)
    session.modified = True
    logout_user()
    flash('Has cerrado sesión.', 'info')
    return redirect(url_for('home'))

@app.route('/api/logout', methods=['POST'])
@login_required
def api_logout():
    if 'cart' in session:
        # Guardar el carrito en la base de datos si es necesario
        guardar_carrito_usuario(current_user.id, session['cart'])
    
    # Vaciar el carrito y cerrar sesión
    session.pop('cart', None)
    session.modified = True  # Asegurar que Flask sepa que la sesión ha sido modificada
    logout_user()
    
    return jsonify({'message': 'Cierre de sesión exitoso'})

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']  # Recibir el campo de email
        password = request.form['password']
        confirm_password = request.form['confirm_password']  # Recibir la confirmación de contraseña
        
        # Validación de que las contraseñas coincidan
        if password != confirm_password:
            flash('Las contraseñas no coinciden', 'danger')
            return redirect(url_for('register'))
        
        hashed_password = generate_password_hash(password)
        
        cnx = get_db_connection()
        cursor = cnx.cursor()
        
        try:
            cursor.execute(
                'INSERT INTO usuarios (username, email, password_hash) VALUES (%s, %s, %s)',
                (username, email, hashed_password)
            )
            cnx.commit()
            flash('Usuario registrado correctamente', 'success')
            return redirect(url_for('login'))
        except mysql.connector.Error as err:
            cnx.rollback()
            flash(f"Error: {err}", 'danger')
        finally:
            cursor.close()
            cnx.close()

    return render_template('register.html')

@app.route('/productos')
def productos():
    try:
        cnx = get_db_connection()
        cursor = cnx.cursor(dictionary=True)
        cursor.execute('SELECT * FROM productos')
        productos = cursor.fetchall()
        cursor.close()
        cnx.close()
        return render_template('productos.html', productos=productos)
    except mysql.connector.Error as err:
        flash(f"Error: {err}", 'danger')
        return redirect(url_for('home'))

@app.route('/api/productos', methods=['GET'])
def api_productos():
    try:
        # Conexión a la base de datos
        cnx = get_db_connection()
        cursor = cnx.cursor(dictionary=True)

        # Consulta para obtener productos con variantes, imágenes y descripciones desde la tabla productos
        cursor.execute("""
            SELECT p.id, p.nombre, p.precio, p.imagen, p.descripcion,
                GROUP_CONCAT(CONCAT_WS('-', pv.color, pv.capacidad, pv.stock) SEPARATOR ',') AS variantes
            FROM productos p
            LEFT JOIN producto_variantes pv ON p.id = pv.producto_id
            GROUP BY p.id
        """)

        productos = cursor.fetchall()

        for producto in productos:
            print(f"Procesando producto: {producto}")

            # Asegurarse de que producto['variantes'] no sea None
            if producto['variantes'] and isinstance(producto['variantes'], str):
                print(f"Variantes encontradas: {producto['variantes']}")
                producto['variantes'] = producto['variantes'].split(',')
                producto['stock_variantes'] = {
                    f"{variante.split('-')[0]}-{variante.split('-')[1]}": int(variante.split('-')[2]) 
                    for variante in producto['variantes']
                }
            else:
                producto['variantes'] = []
                producto['stock_variantes'] = {}
                print("No se encontraron variantes")

        # Cerrar conexión con la base de datos
        cursor.close()
        cnx.close()

        return jsonify(productos)

    except mysql.connector.Error as err:
        print(f"Error en la base de datos: {err}")
        return jsonify({'error': str(err)}), 500
    except Exception as e:
        print(f"Error general: {e}")
        return jsonify({'error': str(e)}), 500
    
@app.route('/api/productos_destacados', methods=['GET'])
def obtener_productos_destacados():
    try:
        cnx = get_db_connection()
        cursor = cnx.cursor(dictionary=True)

        # Asegurar que se obtengan las imágenes desde la tabla productos
        query = '''
            SELECT p.id, p.nombre, p.precio, p.imagen AS imagenes
            FROM productos p
            LIMIT 5
        '''
        cursor.execute(query)
        productos = cursor.fetchall()

        # Cerrar conexión a la base de datos
        cursor.close()
        cnx.close()

        return jsonify(productos)

    except mysql.connector.Error as err:
        print(f"Error en la base de datos: {err}")
        return jsonify({'error': str(err)}), 500
    except Exception as e:
        print(f"Error general: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/add_to_cart/<int:producto_id>', methods=['POST'])
def add_to_cart(producto_id):
    cantidad = request.form.get('cantidad', 1, type=int)
    if 'cart' not in session:
        session['cart'] = {}
    cart = session['cart']
    
    cnx = get_db_connection()
    cursor = cnx.cursor(dictionary=True)
    cursor.execute('SELECT stock FROM productos WHERE id = %s', (producto_id,))
    producto = cursor.fetchone()
    
    cantidad_total = cart.get(str(producto_id), 0) + cantidad
    if cantidad_total > producto['stock']:
        flash(f"No puedes añadir más de {producto['stock']} productos al carrito.", 'error')
        cnx.close()
        return redirect(url_for('productos'))
    
    cart[str(producto_id)] = cantidad_total
    
    # Si el usuario está autenticado, guarda el carrito en la base de datos
    if current_user.is_authenticated:
        cursor.execute('SELECT cantidad FROM user_cart WHERE user_id = %s AND producto_id = %s', (current_user.id, producto_id))
        result = cursor.fetchone()
        if result:
            nueva_cantidad = result['cantidad'] + cantidad
            cursor.execute('UPDATE user_cart SET cantidad = %s WHERE user_id = %s AND producto_id = %s', (nueva_cantidad, current_user.id, producto_id))
        else:
            cursor.execute('INSERT INTO user_cart (user_id, producto_id, cantidad) VALUES (%s, %s, %s)', (current_user.id, producto_id, cantidad))
        cnx.commit()
    
    cnx.close()
    session['cart'] = cart
    session.modified = True
    flash('Producto añadido al carrito con éxito.', 'success')
    return redirect(url_for('carrito'))

@app.route('/api/add_to_cart/<int:producto_id>', methods=['POST'])
def api_add_to_cart(producto_id):
    data = request.get_json()
    cantidad = data.get('cantidad', 1)
    color = data.get('color')
    capacidad = data.get('capacidad')

    if not color or not capacidad:
        return jsonify({'error': 'Debes seleccionar color y capacidad'}), 400

    cnx = get_db_connection()
    cursor = cnx.cursor(dictionary=True)

    query = """
        SELECT stock FROM producto_variantes
        WHERE producto_id = %s AND color = %s AND capacidad = %s
    """
    cursor.execute(query, (producto_id, color, capacidad))
    variante = cursor.fetchone()

    if not variante or variante['stock'] < cantidad:
        cursor.close()
        cnx.close()
        return jsonify({'error': 'No hay stock disponible para la variante seleccionada'}), 400

    if 'cart' not in session:
        session['cart'] = {}

    cart = session['cart']
    cart_key = f"{producto_id}-{color}-{capacidad}"

    if cart_key in cart:
        cart[cart_key]['cantidad'] += cantidad
    else:
        cart[cart_key] = {'cantidad': cantidad, 'color': color, 'capacidad': capacidad}

    session['cart'] = cart
    session.modified = True  # Asegura que la sesión se actualice

    cursor.close()
    cnx.close()

    return jsonify({'message': 'Producto añadido al carrito correctamente'}), 200

@app.route('/carrito')
def carrito():
    if 'cart' not in session:
        session['cart'] = {}
    cart = session['cart']
    productos_con_cantidades = []
    total = 0
    
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    producto_ids = list(cart.keys())
    
    if producto_ids:
        cursor.execute('SELECT * FROM productos WHERE id IN (%s)' % ','.join(['%s'] * len(producto_ids)), producto_ids)
        productos = cursor.fetchall()
        
        for producto in productos:
            producto_id = producto['id']
            cantidad = cart.get(str(producto_id), 0)
            total += producto['precio'] * cantidad
            productos_con_cantidades.append({**producto, 'cantidad': cantidad})
    
    conn.close()
    return render_template('carrito.html', productos=productos_con_cantidades, total=total)

@app.route('/api/carrito', methods=['GET'])
def api_carrito():
    if 'cart' not in session:
        session['cart'] = {}
    
    cart = session['cart']
    productos_con_cantidades = []
    total = 0

    if cart:
        try:
            # Obtener los IDs de los productos en el carrito
            producto_ids = set()  # Utilizar un set para evitar duplicados
            for cart_key in cart.keys():
                producto_id = int(cart_key.split('-')[0])  # Extraer solo el ID del producto
                producto_ids.add(producto_id)

            print(f"IDs de productos en el carrito: {producto_ids}")

            cnx = get_db_connection()
            cursor = cnx.cursor(dictionary=True)

            # Obtener los productos con esos IDs y sus variantes
            formato_ids = ','.join(['%s'] * len(producto_ids))
            query = f'''
                SELECT p.id, p.nombre, p.precio, p.imagen, 
                       v.color, v.capacidad, v.stock
                FROM productos p
                LEFT JOIN producto_variantes v ON p.id = v.producto_id
                WHERE p.id IN ({formato_ids})
            '''
            cursor.execute(query, list(producto_ids))
            productos = cursor.fetchall()

            print(f"Productos obtenidos de la base de datos: {productos}")

            # Mapear los productos del carrito con los productos de la base de datos
            for cart_key, valor in cart.items():
                producto_id, color, capacidad = cart_key.split('-')

                for producto in productos:
                    # Filtrar solo la variante que coincide con la clave del carrito
                    if int(producto_id) == producto['id'] and producto['color'] == color and producto['capacidad'] == capacidad:
                        productos_con_cantidades.append({
                            'id': producto['id'],
                            'nombre': producto['nombre'],
                            'precio': producto['precio'],
                            'cantidad': valor['cantidad'],
                            'stock': producto['stock'],  # Stock por variante
                            'imagen': f"http://localhost:5000/static/images/{producto['imagen']}",  # Ruta completa para la imagen
                            'color': producto['color'],
                            'capacidad': producto['capacidad']
                        })
                        total += producto['precio'] * valor['cantidad']

            cnx.close()

        except Exception as e:
            print(f"Error al obtener productos del carrito: {str(e)}")
            return jsonify({'error': 'Error al obtener los productos del carrito.'}), 500

    print(f"Productos en el carrito: {productos_con_cantidades}")
    print(f"Total del carrito: {total}")

    return jsonify({"productos": productos_con_cantidades, "total": total})

@app.route('/remove_from_cart/<int:producto_id>', methods=['POST'])
def remove_from_cart(producto_id):
    if 'cart' in session:
        cart = session['cart']
        if str(producto_id) in cart:
            del cart[str(producto_id)]
        if current_user.is_authenticated:
            cnx = get_db_connection()
            cursor = cnx.cursor()
            cursor.execute('DELETE FROM user_cart WHERE user_id = %s AND producto_id = %s', (current_user.id, producto_id))
            cnx.commit()
            cnx.close()
        session['cart'] = cart
        flash('Producto eliminado del carrito', 'info')
    return redirect(url_for('carrito'))

@app.route('/api/remove_from_cart/<int:producto_id>', methods=['POST'])
def api_remove_from_cart(producto_id):
    data = request.get_json()
    color = data.get('color')
    capacidad = data.get('capacidad')

    if 'cart' in session:
        cart = session['cart']
        cart_key = f"{producto_id}-{color}-{capacidad}"  # Crear la clave combinada

        if cart_key in cart:
            del cart[cart_key]
            session['cart'] = cart
            session.modified = True  # Marcar la sesión como modificada
            return jsonify({'message': 'Producto eliminado correctamente'}), 200
        else:
            return jsonify({'error': 'Producto no encontrado en el carrito'}), 404

    return jsonify({'error': 'Carrito no encontrado'}), 400

@app.route('/update_cart/<int:producto_id>', methods=['POST'])
def update_cart(producto_id):
    if 'cart' in session:
        cart = session['cart']
        nueva_cantidad = request.form.get('cantidad', type=int)

        # Comprueba si la cantidad es válida
        cnx = get_db_connection()
        cursor = cnx.cursor(dictionary=True)
        cursor.execute('SELECT stock FROM productos WHERE id = %s', (producto_id,))
        producto = cursor.fetchone()
        cnx.close()

        if producto:
            # Valida que la nueva cantidad no supere el stock
            if nueva_cantidad <= producto['stock']:
                print(f'Actualizando producto {producto_id} a {nueva_cantidad} unidades')
                cart[str(producto_id)] = nueva_cantidad
                session['cart'] = cart  # Asegura que la sesión se actualiza

                # Si el usuario está autenticado, también se actualiza en la base de datos
                if current_user.is_authenticated:
                    cnx = get_db_connection()
                    cursor = cnx.cursor()
                    cursor.execute(
                        'UPDATE user_cart SET cantidad = %s WHERE user_id = %s AND producto_id = %s',
                        (nueva_cantidad, current_user.id, producto_id)
                    )
                    cnx.commit()
                    cnx.close()

                flash('Cantidad actualizada correctamente.', 'success')
            else:
                flash(f'No puedes añadir más de {producto["stock"]} unidades al carrito.', 'error')
        else:
            flash('Producto no encontrado.', 'error')

    return redirect(url_for('carrito'))

@app.route('/api/update_cart/<int:producto_id>', methods=['POST'])
def api_update_cart(producto_id):
    data = request.get_json()
    nueva_cantidad = data.get('cantidad')
    color = data.get('color')
    capacidad = data.get('capacidad')

    if nueva_cantidad is None or nueva_cantidad < 1:
        return jsonify({'error': 'Cantidad inválida'}), 400

    if 'cart' not in session:
        return jsonify({'error': 'Carrito no encontrado'}), 400

    cart = session['cart']
    cart_key = f"{producto_id}-{color}-{capacidad}"

    # Conectar a la base de datos para verificar el stock de la variante
    cnx = get_db_connection()
    cursor = cnx.cursor(dictionary=True)

    # Obtener el stock específico para la combinación de color y capacidad
    cursor.execute('''
        SELECT stock FROM producto_variantes 
        WHERE producto_id = %s AND color = %s AND capacidad = %s
    ''', (producto_id, color, capacidad))
    resultado = cursor.fetchone()

    if not resultado:
        return jsonify({'error': 'Variante no encontrada'}), 404

    stock_disponible = resultado['stock']

    # Verificar si el producto con la variante específica está en el carrito
    if cart_key in cart:
        if nueva_cantidad > stock_disponible:
            return jsonify({'error': 'No puedes añadir más productos de los que hay en stock'}), 400

        if nueva_cantidad > 0:
            # Actualiza la cantidad
            cart[cart_key]['cantidad'] = nueva_cantidad
        else:
            # Si la cantidad es 0 o menor, elimina el producto del carrito
            del cart[cart_key]

        session['cart'] = cart
        session.modified = True  # Asegura que la sesión se actualice
        return jsonify({'message': 'Cantidad actualizada correctamente'}), 200
    else:
        return jsonify({'error': 'Producto no encontrado en el carrito'}), 404
    
@app.route('/api/checkout', methods=['POST'])
def api_checkout():
    data = request.get_json()
    direccion = data.get('direccion', {}).get('direccion', '')
    telefono = data.get('telefono', '')
    ciudad = data.get('direccion', {}).get('ciudad', '')
    provincia = data.get('direccion', {}).get('provincia', '')
    codigo_postal = data.get('direccion', {}).get('codigo_postal', '')
    pais = data.get('direccion', {}).get('pais', '')
    metodo_pago = data.get('metodo_pago', '')

    if not direccion or not telefono or not metodo_pago:
        return jsonify({'error': 'Falta información de dirección, teléfono o método de pago'}), 400

    if 'cart' not in session or not session['cart']:
        return jsonify({'message': 'El carrito está vacío'}), 400

    cart = session['cart']
    total = 0
    cnx = get_db_connection()
    cursor = cnx.cursor(dictionary=True)

    for producto_key, producto_data in cart.items():
        producto_id, color, capacidad = producto_key.split('-')
        cantidad = producto_data['cantidad']

        # Cambiado para obtener el precio de la tabla productos
        cursor.execute('SELECT p.precio, v.stock FROM productos p JOIN producto_variantes v ON p.id = v.producto_id WHERE p.id = %s AND v.color = %s AND v.capacidad = %s', 
                       (producto_id, color, capacidad))
        producto = cursor.fetchone()

        if producto:
            if producto['stock'] < cantidad:
                cnx.close()
                return jsonify({'message': f"No hay suficiente stock para el producto {producto['nombre']}."}), 400
            total += producto['precio'] * cantidad

    if current_user.is_authenticated:
        cursor.execute('SELECT id FROM direcciones WHERE user_id = %s AND direccion = %s AND telefono = %s', 
                       (current_user.id, direccion, telefono))
        direccion_existente = cursor.fetchone()

        if not direccion_existente:
            cursor.execute('INSERT INTO direcciones (user_id, direccion, telefono, ciudad, provincia, codigo_postal, pais) VALUES (%s, %s, %s, %s, %s, %s, %s)', 
                           (current_user.id, direccion, telefono, ciudad, provincia, codigo_postal, pais))
            direccion_id = cursor.lastrowid
        else:
            direccion_id = direccion_existente['id']

        cursor.execute('INSERT INTO pedidos (user_id, total, direccion_id, metodo_pago) VALUES (%s, %s, %s, %s)', 
                       (current_user.id, total, direccion_id, metodo_pago))
        pedido_id = cursor.lastrowid

    else:
        cursor.execute('INSERT INTO pedidos (total, direccion_temporal, telefono_temporal, metodo_pago) VALUES (%s, %s, %s, %s)', 
                       (total, direccion, telefono, metodo_pago))
        pedido_id = cursor.lastrowid

    for producto_key, producto_data in cart.items():
        producto_id, color, capacidad = producto_key.split('-')
        cantidad = producto_data['cantidad']

        cursor.execute('INSERT INTO detalles_pedido (pedido_id, producto_id, cantidad, precio) VALUES (%s, %s, %s, %s)', 
                       (pedido_id, producto_id, cantidad, producto['precio']))

        cursor.execute('UPDATE producto_variantes SET stock = stock - %s WHERE producto_id = %s AND color = %s AND capacidad = %s', 
                       (cantidad, producto_id, color, capacidad))

    cnx.commit()
    cnx.close()

    session.pop('cart', None)  # Limpia el carrito después de la compra

    return jsonify({'message': 'Pago realizado con éxito', 'total': total}), 200

@app.route('/historial')
@login_required
def historial():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    # Obtener los pedidos del usuario
    cursor.execute('SELECT * FROM pedidos WHERE user_id = %s', (current_user.id,))
    pedidos = cursor.fetchall()

    # Obtener los detalles de cada pedido
    for pedido in pedidos:
        cursor.execute('SELECT p.nombre, dp.cantidad, dp.precio FROM detalles_pedido dp JOIN productos p ON dp.producto_id = p.id WHERE dp.pedido_id = %s', 
                       (pedido['id'],))
        pedido['detalles'] = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template('historial.html', pedidos=pedidos)

@app.route('/api/buscar_productos', methods=['GET'])
def buscar_productos():
    query = request.args.get('q', '')  # Obtener el parámetro de búsqueda 'q'
    
    # Conectar a la base de datos
    cnx = get_db_connection()
    cursor = cnx.cursor(dictionary=True)
    
    # Buscar productos que coincidan con el nombre o descripción
    cursor.execute("SELECT * FROM productos WHERE nombre LIKE %s OR descripcion LIKE %s", 
                   ('%' + query + '%', '%' + query + '%'))
    
    productos = cursor.fetchall()
    cursor.close()
    cnx.close()
    
    return jsonify(productos)

@app.route('/api/guardar_direccion', methods=['POST'])
@login_required
def guardar_direccion():
    print(f"Usuario autenticado: {current_user.is_authenticated}, ID: {current_user.id}")
    
    data = request.get_json()
    print("Datos recibidos:", data)

    # Procesa la dirección
    direccion = data.get('direccion')
    ciudad = data.get('ciudad')
    provincia = data.get('provincia')
    codigo_postal = data.get('codigo_postal')
    pais = data.get('pais')
    telefono = data.get('telefono')

    # Verifica si los datos son correctos
    if not all([direccion, ciudad, provincia, codigo_postal, pais, telefono]):
        return jsonify({'error': 'Todos los campos son obligatorios'}), 400

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Inserta la nueva dirección
        cursor.execute(
            'INSERT INTO direcciones (usuario_id, direccion, ciudad, provincia, codigo_postal, pais, telefono) '
            'VALUES (%s, %s, %s, %s, %s, %s, %s)',
            (current_user.id, direccion, ciudad, provincia, codigo_postal, pais, telefono)
        )

        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({'message': 'Dirección guardada con éxito'}), 201

    except Exception as e:
        print(f"Error al guardar la dirección: {e}")
        return jsonify({'error': f'Error al guardar la dirección: {str(e)}'}), 500

@app.route('/ruta_protegida')
@login_required
def ruta_protegida():
    return jsonify({'message': 'Usuario autenticado'})

@app.route('/api/obtener_direcciones', methods=['GET'])
@login_required
def obtener_direcciones():
    try:
        user_id = current_user.id

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Buscar direcciones asociadas al usuario
        cursor.execute('SELECT direccion, ciudad, provincia, codigo_postal, pais, telefono FROM direcciones WHERE user_id = %s', (user_id,))
        direcciones = cursor.fetchall()

        cursor.close()
        conn.close()

        return jsonify(direcciones), 200

    except Exception as e:
        return jsonify({'error': f'Error al obtener las direcciones: {str(e)}'}), 500

@app.route('/api/procesar_pago', methods=['POST'])
@login_required
def procesar_pago():
    data = request.get_json()
    metodo_pago = data.get('metodo_pago')
    direccion_id = data.get('direccion_id')
    total = data.get('total')

    # Aquí procesar el pago real, por ejemplo, con PayPal o Apple Pay

    # Simulación del proceso de pago
    if metodo_pago not in ['Apple Pay', 'PayPal', 'Tarjeta de Crédito']:
        return jsonify({'error': 'Método de pago no válido'}), 400

    return jsonify({'message': 'Pago procesado con éxito'})

@app.route('/api/historial_pedidos', methods=['GET'])
@login_required
def historial_pedidos():
    cnx = get_db_connection()
    cursor = cnx.cursor(dictionary=True)

    # Obtener los pedidos del usuario autenticado
    cursor.execute('SELECT * FROM pedidos WHERE user_id = %s ORDER BY fecha DESC', (current_user.id,))
    pedidos = cursor.fetchall()

    # Obtener los detalles de cada pedido
    for pedido in pedidos:
        cursor.execute('SELECT dp.producto_id, p.nombre, dp.cantidad, dp.precio FROM detalles_pedido dp JOIN productos p ON dp.producto_id = p.id WHERE dp.pedido_id = %s', 
                       (pedido['id'],))
        pedido['detalles'] = cursor.fetchall()

    cursor.close()
    cnx.close()

    return jsonify(pedidos)

@app.route('/api/producto', methods=['GET'])
def obtener_producto():
    nombre = request.args.get('nombre')

    if not nombre:
        return jsonify({'error': 'Nombre del producto no proporcionado'}), 400

    cnx = get_db_connection()
    cursor = cnx.cursor(dictionary=True)

    # Buscar el producto basado en el nombre
    cursor.execute('SELECT * FROM productos WHERE nombre = %s', (nombre,))
    producto = cursor.fetchone()

    if not producto:
        cnx.close()
        return jsonify({'error': 'Producto no encontrado'}), 404

    # Obtener las variantes del producto (color, capacidad, etc.)
    cursor.execute('SELECT * FROM producto_variantes WHERE producto_id = %s', (producto['id'],))
    variantes = cursor.fetchall()

    producto['variantes'] = variantes

    cnx.close()
    return jsonify(producto)

@app.route('/api/importar_productos', methods=['POST'])
@login_required  # Asegurarse de que el usuario esté autenticado
def importar_productos():
    if current_user.rol != 'admin':  # Solo permitir a administradores
        return jsonify({'error': 'No tienes permiso para realizar esta acción.'}), 403

    file = request.files.get('file')
    
    if not file:
        return jsonify({'error': 'No se ha proporcionado un archivo.'}), 400
    
    filename = secure_filename(file.filename)

    upload_folder = 'uploads'
    if not os.path.exists(upload_folder):
        os.makedirs(upload_folder)

    filepath = os.path.join(upload_folder, filename)
    file.save(filepath)

    try:
        cnx = get_db_connection()
        cursor = cnx.cursor()

        if filename.endswith('.csv'):
            df = pd.read_csv(filepath)
        elif filename.endswith('.xlsx') or filename.endswith('.xls'):
            df = pd.read_excel(filepath)
        else:
            return jsonify({'error': 'Formato de archivo no compatible. Solo se permiten archivos CSV y Excel.'}), 400

        required_columns = ['nombre', 'descripcion', 'precio', 'imagen_url', 'imagen']
        missing_columns = [col for col in required_columns if col not in df.columns]
        if missing_columns:
            return jsonify({'error': f'Faltan las siguientes columnas requeridas: {missing_columns}'}), 400

        for _, row in df.iterrows():
            cursor.execute('SELECT id FROM productos WHERE nombre = %s', (row['nombre'],))
            existing_product = cursor.fetchone()

            if existing_product:
                cursor.execute('''
                    UPDATE productos
                    SET descripcion = %s, precio = %s, imagen_url = %s, imagen = %s
                    WHERE id = %s
                ''', (row['descripcion'], row['precio'], row['imagen_url'], row['imagen'], existing_product['id']))
            else:
                cursor.execute('''
                    INSERT INTO productos (nombre, descripcion, precio, imagen_url, imagen)
                    VALUES (%s, %s, %s, %s, %s)
                ''', (row['nombre'], row['descripcion'], row['precio'], row['imagen_url'], row['imagen']))

        cnx.commit()

    except Exception as e:
        cnx.rollback()
        return jsonify({'error': str(e)}), 500

    finally:
        if cursor:
            cursor.close()
        if cnx:
            cnx.close()
        if os.path.exists(filepath):
            os.remove(filepath)

    return jsonify({'message': 'Productos importados correctamente.'})

if __name__ == '__main__':
    app.run(debug=True)