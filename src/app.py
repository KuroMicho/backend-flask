from flask import Flask, g, jsonify
from psycopg2 import pool
import psycopg2

app = Flask(__name__)
app.config['postgreSQL_pool'] = psycopg2.pool.SimpleConnectionPool(1, 20,
    user = "kuromicho",
    password = "123456",
    host = "localhost",
    port = "5432",
    database = "surveys")

def get_db():
    if 'db' not in g:
        g.db = app.config['postgreSQL_pool'].getconn()
    return g.db

@app.teardown_appcontext
def close_conn(e):
    db = g.pop('db', None)
    if db is not None:
        app.config['postgreSQL_pool'].putconn(db)

@app.route('/')
def index():
    return 'hello world'

@app.route('/users')
def users():
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users;")
    result = cursor.fetchall()
    print(result)
    cursor.close()
    return jsonify(result)
    

if __name__ == '__main__':
    app.run(debug=True)