from werkzeug.security import generate_password_hash

# Definir la contraseña que se quiere hashear
password = '2163'

# Genera el hash de la contraseña
hashed_password = generate_password_hash(password)

# Imprime el hash generado
print(hashed_password)