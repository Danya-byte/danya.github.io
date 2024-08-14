from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3

app = Flask(__name__)
app.secret_key = 'your_secret_key'


# Создание подключения к базе данных
def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn


# Создание таблицы пользователей, если она не существует
def init_db():
    conn = get_db_connection()
    with app.open_resource('schema.sql', mode='r') as f:
        conn.cursor().executescript(f.read())
    conn.commit()
    conn.close()


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        hashed_password = generate_password_hash(password)
        conn = get_db_connection()
        conn.execute('INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
                     (username, email, hashed_password))
        conn.commit()
        conn.close()
        flash('Регистрация прошла успешно', 'success')
        return redirect(url_for('index'))
    return render_template('register.html')


@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()
    if user and check_password_hash(user['password'], password):
        session['username'] = user['username']
        session['role'] = user['role']
        if user['role'] == 'admin':
            return redirect(url_for('admin'))
        else:
            return redirect(url_for('user'))
    else:
        flash('Неверные учетные данные', 'danger')
        return redirect(url_for('index'))


@app.route('/admin')
def admin():
    if 'username' in session and session['role'] == 'admin':
        conn = get_db_connection()
        users = conn.execute('SELECT id, username, email FROM users').fetchall()
        conn.close()
        return render_template('admin.html', users=users)
    else:
        flash('Доступ запрещен', 'danger')
        return redirect(url_for('index'))


@app.route('/user')
def user():
    if 'username' in session:
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (session['username'],)).fetchone()
        conn.close()
        if user:
            return render_template('user.html', user=user)
        else:
            flash('Пользователь не найден', 'danger')
            return redirect(url_for('index'))
    else:
        flash('Доступ запрещен', 'danger')
        return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('role', None)
    flash('Вы вышли из системы', 'success')
    return redirect(url_for('index'))


@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    if 'username' in session and session['role'] == 'admin':
        if request.method == 'POST':
            username = request.form['username']
            email = request.form['email']
            password = request.form['password']
            role = request.form['role']
            hashed_password = generate_password_hash(password)
            conn = get_db_connection()
            conn.execute('UPDATE users SET username = ?, email = ?, password = ?, role = ? WHERE id = ?',
                         (username, email, hashed_password, role, user_id))
            conn.commit()
            conn.close()
            flash('Данные пользователя успешно обновлены', 'success')
            return redirect(url_for('admin'))
        else:
            conn = get_db_connection()
            user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
            conn.close()
            if user:
                return render_template('edit_user.html', user=user)
            else:
                flash('Пользователь не найден', 'danger')
                return redirect(url_for('admin'))
    else:
        flash('Доступ запрещен', 'danger')
        return redirect(url_for('index'))


if __name__ == '__main__':
    init_db()
    app.run(debug=True)
