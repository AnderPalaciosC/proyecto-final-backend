from werkzeug.security import check_password_hash

# Hash de la base de datos
stored_hash = 'scrypt:32768:8:1$QJeUOh1An6siwOOV$4a76cd4ae9ca9531d65c344aac09f536793c0f74efbc085a4fa6cf909ee08bcf4880cc32125a0d1c2cd67c8cdbae1db9ca330e3ecad30e3ef7e4aa3a8edfefe1'

# Verificar la contraseña ingresada por el usuario
if check_password_hash(stored_hash, '2163'):
    print("La contraseña es correcta")
else:
    print("La contraseña es incorrecta")