from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from flask_mysqldb import MySQL
from config import Config
import bcrypt



app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = "clave_secreta"  # Necesario para manejar sesiones

mysql = MySQL(app)


# Función para encriptar las contraseñas
def hash_password(password):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt)

# Función para verificar contraseña
def check_password(password, hashed_password):
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))


@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "Faltan datos"}), 400

    hashed_password = hash_password(password)

    try:
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO usuarios (username, password_hash) VALUES (%s, %s)", (username, hashed_password))
        mysql.connection.commit()
        cur.close()
        return jsonify({"message": "Usuario registrado exitosamente"}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "Faltan datos"}), 400

    cur = mysql.connection.cursor()
    cur.execute("SELECT password_hash FROM usuarios WHERE username = %s", (username,)) 
    user = cur.fetchone()
    print(user)
    cur.close()

    if user and check_password(password, user['password_hash']):
        session['username'] = username  # Almacenar el nombre de usuario en la sesión
       # return redirect(url_for('index'))  # Redirigir a la página principal
        return jsonify({"message": "Acceso permitido"}), 200
    else:
          return jsonify({"error": "Credenciales incorrectas"}), 401
      



@app.route("/logout", methods=["GET"])
def logout():
    session.pop('username', None)  # Eliminamos el usuario de la sesión
    return redirect(url_for('login_form'))  # Redirigimos al formulario de login

@app.route("/login_form", methods=["GET"])
def login_form():
    return render_template("login.html")

@app.route("/", methods=["GET", "POST"])
def index():
    if 'username' not in session:  # Verificamos si el usuario está logueado
        return redirect(url_for('login_form'))  # Redirigimos al login si no está logueado
       #return jsonify({"error": "No autenticado"}), 401

    return render_template("index.html")  # O cualquier archivo HTML que sea la página principal

@app.route("/buscar", methods=["GET"])
def buscar():
    if 'username' not in session:  # Si el usuario no está autenticado
        return jsonify({"error": "No autenticado"}), 401  # Devuelve JSON en lugar de redirigir

    fecha = request.args.get("fecha")
    municipio = request.args.get("municipio")

    if not fecha or not municipio:
        return jsonify({"error": "Faltan parámetros"}), 400  # Devuelve JSON con error

    try:
        cur = mysql.connection.cursor()

        query_calvillo = "SELECT * FROM calvillo WHERE fecha = %s AND municipio = %s"
        cur.execute(query_calvillo, (fecha, municipio))
        resultados_calvillo = cur.fetchall()

        query_sfr = "SELECT * FROM SFR WHERE fecha = %s AND TRIM(LOWER(municipio)) = TRIM(LOWER(%s))"
        cur.execute(query_sfr, (fecha, municipio))
        resultados_sfr = cur.fetchall()

        query_asientos = "SELECT * FROM asientos WHERE fecha = %s AND municipio = %s"
        cur.execute(query_asientos, (fecha, municipio))
        resultados_asientos = cur.fetchall()

        query_llano = "SELECT * FROM llano WHERE fecha = %s AND municipio = %s"
        cur.execute(query_llano, (fecha, municipio))
        resultados_llano = cur.fetchall()

        query_sjg = "SELECT * FROM sjg WHERE fecha = %s AND municipio = %s"
        cur.execute(query_sjg, (fecha, municipio))
        resultados_sjg = cur.fetchall()

        query_aguascalientes = "SELECT * FROM aguascalientes WHERE fecha = %s AND municipio = %s"
        cur.execute(query_aguascalientes, (fecha, municipio))
        resultados_aguascalientes = cur.fetchall()

        query_tepezala= "SELECT * FROM tepezala WHERE fecha = %s AND municipio = %s"
        cur.execute(query_tepezala, (fecha, municipio))
        resultados_tepezala = cur.fetchall()

        query_rinconRomos= "SELECT * FROM rinconRomos WHERE fecha = %s AND municipio = %s"
        cur.execute(query_rinconRomos, (fecha, municipio))
        resultados_rinconRomos = cur.fetchall()

        query_cosio= "SELECT * FROM cosio WHERE fecha = %s AND municipio = %s"
        cur.execute(query_cosio, (fecha, municipio))
        resultados_cosio = cur.fetchall()

        query_pabellonArteaga= "SELECT * FROM pabellonArteaga WHERE fecha = %s AND municipio = %s"
        cur.execute(query_pabellonArteaga, (fecha, municipio))
        resultados_pabellonArteaga = cur.fetchall()

        query_jesusMaria= "SELECT * FROM jesusMaria WHERE fecha = %s AND municipio = %s"
        cur.execute(query_jesusMaria, (fecha, municipio))
        resultados_jesusMaria = cur.fetchall()



        cur.close()

        return jsonify({
            "calvillo": resultados_calvillo,
            "SFR": resultados_sfr,
            "asientos": resultados_asientos,
            #aqui se inicia las otras dos tablas o las tablas restantes 
            "llano": resultados_llano,
            "sjg": resultados_sjg,
            "aguascalientes": resultados_aguascalientes,
            "tepezala": resultados_tepezala,
            #rinconRomos
            "rinconRomos":resultados_rinconRomos,
            #cosio
            "cosio": resultados_cosio,
            "pabellonArteaga":resultados_pabellonArteaga,
            "jesusMaria": resultados_jesusMaria
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500  # Captura errores y devuelve JSON

if __name__ == "__main__":
    app.run(debug=True)
