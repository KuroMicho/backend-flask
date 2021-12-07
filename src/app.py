import bcrypt
from flask import Flask, g, jsonify, request, make_response
from flask_jwt_extended import create_access_token, get_jwt_identity, jwt_required, JWTManager
from flask_jwt_extended.utils import create_refresh_token
from psycopg2 import pool
from flask_bcrypt import Bcrypt
import psycopg2

app = Flask(__name__)

app.config["JWT_SECRET_KEY"] = "super-secret"
app.config['postgreSQL_pool'] = psycopg2.pool.SimpleConnectionPool(1, 20,
                                                                   user="kuromicho",
                                                                   password="123456",
                                                                   host="localhost",
                                                                   port="5432",
                                                                   database="surveys")

jwt = JWTManager(app)
bcrypt = Bcrypt(app)


def get_db():
    if 'db' not in g:
        g.db = app.config['postgreSQL_pool'].getconn()
    return g.db


@app.teardown_appcontext
def close_conn(e):
    db = g.pop('db', None)
    if db is not None:
        app.config['postgreSQL_pool'].putconn(db)


@app.get('/')
def index():
    return 'hello world'


@app.get('/users/<username>')
@jwt_required()
def userByUsername(username):
    current_identity = get_jwt_identity()

    if username == current_identity:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM users WHERE username= %s", (username,))
        result = cursor.fetchone()
        cursor.close()
        return make_response(jsonify({"username": result[0], "email": result[1]}), 200)


def assign_access_refresh_token(username, message):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users WHERE username= %s", (username,))
    result = cursor.fetchone()

    access_token = create_access_token(identity=result[0], fresh=True)
    refresh_token = create_refresh_token(identity=result[0])
    resp = jsonify({"access": access_token, "refresh": refresh_token,
                   "username": result[0]})
    resp.headers.add('Access-Control-Allow-Origin', 'http://localhost:3000')
    resp.headers.add('Access-Control-Allow-Credentials', 'true')
    return resp


@app.post('/login')
def login():
    username = request.json["username"]
    password = request.json["password"]

    if not username:
        return jsonify({
            "errors": "username is required"})
    if not password:
        return jsonify({
            "errors": "password is required"})

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users WHERE username= %s", (username,))
    result = cursor.fetchone()

    if result is not None:
        if result[0] == username:
            pass_correct = bcrypt.check_password_hash(result[2], password)
            if pass_correct:
                return assign_access_refresh_token(username, "Enabled to Access")

            return make_response(jsonify({'error': 'Wrong credentials.'}), 401)

    return make_response(jsonify({'error': 'Author not exists'}), 404)


@app.post('/register')
def register():
    db = get_db()
    cursor = db.cursor()
    username = request.json["username"]
    email = request.json["email"]
    password = request.json["password"]

    if not username:
        return jsonify({
            "errors": "username is required"})
    if not email:
        return jsonify({
            "errors": "email is required"})
    if not password:
        return jsonify({
            "errors": "password is required"})

    pwd_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    cursor.execute('''INSERT INTO users(username, email, password)
        VALUES (%s, %s, %s)''', (
        username,
        email,
        pwd_hash
    ))

    db.commit()
    cursor.close()
    db.close()

    return make_response(jsonify({
        "data": {
            "username": username,
            "email": email
        },
        "msg": "user saved"
    }), 201)


@app.get('/surveys/<username>')
@jwt_required
def getSurveysByUsername(username):
    current_identity = get_jwt_identity()
    if username == current_identity:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM surveys WHERE username=%s", username)
        result = cursor.fetchall()

        return make_response(jsonify({
            result
        }), 200)


@app.post('/surveys')
@jwt_required()
def saveSurvey():
    current_identity = get_jwt_identity()

    title = request.json["title"]
    username = request.json["username"]

    if not title:
        return jsonify({
            "errors": "title is required"})

    if not username:
        return jsonify({
            "errors": "username is required"})

    if username == current_identity:
        db = get_db()
        cursor = db.cursor()

        try:
            cursor.execute('''INSERT INTO surveys(username, title) VALUES(%s,%s)''', (
                username,
                title
            ))

            db.commit()
            cursor.close()
            db.close()
        except:
            return make_response(jsonify({'msg': "something went wrong"}), 500)

        return make_response(jsonify({'msg': "survey created"}), 201)


@app.put('/surveys/update')
@jwt_required()
def updateSurvey(username):
    current_identity = get_jwt_identity()
    if username == current_identity:
        db = get_db()
        cursor = db.cursor()
        title = request.json["title"]

        if not title:
            return jsonify({
                "errors": "title is required"})

        cursor.execute('''UPDATE encuestas set nombre=%s''', (
            title,
        ))


@app.delete('/surveys/delete/<int:survey_id>')
@jwt_required()
def deleteSurvey(survey_id):
    db = get_db()
    cursor = db.cursor()


if __name__ == '__main__':
    app.run(debug=True)
