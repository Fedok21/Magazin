from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Секретный ключ для работы с сессиями


# Функция для создания базы данных (если она еще не создана)
def init_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        lastname TEXT NOT NULL,
                        firstname TEXT NOT NULL,
                        middlename TEXT,
                        gender TEXT NOT NULL,
                        age INTEGER NOT NULL,
                        username TEXT NOT NULL UNIQUE,
                        password TEXT NOT NULL
                    )''')
    conn.commit()
    conn.close()


# Функция для проверки пользователя в базе данных
def authenticate_user(username, password):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT password FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    conn.close()
    if user and check_password_hash(user[0], password):
        return True
    return False


# Главный экран выбора
@app.route('/')
def home():
    return render_template('home.html')


# Страница регистрации
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        lastname = request.form['lastname']
        firstname = request.form['firstname']
        middlename = request.form['middlename']
        gender = request.form['gender']
        age = int(request.form['age'])
        username = request.form['username']
        password = request.form['password']

        # Хешируем пароль
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        # Сохраняем данные в базе данных
        try:
            conn = sqlite3.connect('users.db')
            cursor = conn.cursor()
            cursor.execute('''INSERT INTO users (lastname, firstname, middlename, gender, age, username, password) 
                              VALUES (?, ?, ?, ?, ?, ?, ?)''',
                           (lastname, firstname, middlename, gender, age, username, hashed_password))
            conn.commit()
            conn.close()
            return redirect(url_for('success'))
        except sqlite3.IntegrityError:
            # Логин уже существует
            error_message = "This username is already taken. Please choose another one."
            return render_template('register.html', error_message=error_message)

    return render_template('register.html')


# Страница входа
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if authenticate_user(username, password):
            session['username'] = username  # Сохраняем имя пользователя в сессии
            return redirect(url_for('dashboard'))
        else:
            error_message = "Invalid username or password. Please try again."
            return render_template('login.html', error_message=error_message)

    return render_template('login.html')


# Страница успешной регистрации
@app.route('/success')
def success():
    return render_template('success.html')


# Личный кабинет пользователя
@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        return f"Welcome, {session['username']}! This is your dashboard. <a href='/logout'>Logout</a>"
    return redirect(url_for('login'))


# Выход из учетной записи
@app.route('/logout')
def logout():
    session.pop('username', None)  # Удаляем данные пользователя из сессии
    return redirect(url_for('login'))

@app.route('/view_users')
def view_users():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users')
    users = cursor.fetchall()
    conn.close()
    return '<br>'.join([str(user) for user in users])

# Страница для просмотра всех пользователей
@app.route('/users')
def users():
    if 'username' in session:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users')
        users = cursor.fetchall()
        conn.close()
        return render_template('users.html', users=users)
    return redirect(url_for('login'))


# Запуск приложения
if __name__ == '__main__':
    init_db()  # Инициализируем базу данных при запуске
    app.run(debug=True)
