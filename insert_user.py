import mysql.connector
from werkzeug.security import generate_password_hash

# Configuración de la conexión a la base de datos
config = {
    'user': 'root',
    'password': '2163',
    'host': '127.0.0.1',
    'database': 'tienda_apc'
}

# Hash de la contraseña
hashed_password = generate_password_hash('testpassword')

# Insertar usuario
cnx = mysql.connector.connect(**config)
cursor = cnx.cursor()
try:
    cursor.execute('INSERT INTO usuarios (username, password) VALUES (%s, %s)', ('testuser', hashed_password))
    cnx.commit()
    print("Usuario insertado correctamente")
except mysql.connector.Error as err:
    print(f"Error: {err}")
finally:
    cursor.close()
    cnx.close()