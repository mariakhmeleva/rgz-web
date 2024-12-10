from flask import Flask, render_template, request, redirect, url_for, session, flash, current_app
from os import path
import sqlite3
import psycopg2
from psycopg2.extras import RealDictCursor
from werkzeug.security import check_password_hash, generate_password_hash
from flask import Blueprint, render_template, request, abort, jsonify, current_app
from os import path
import sqlite3
from datetime import datetime
from psycopg2.extras import RealDictCursor
from werkzeug.security import check_password_hash, generate_password_hash
import sqlite3
from os import path
from dotenv import load_dotenv
import os
app = Flask(__name__)
load_dotenv()

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'G45qw765LpoGGG5')
app.config['DB_TYPE'] = os.getenv('DB_TYPE', 'postgres')
# Функция для подключения к базе данных
def db_connect():
    if current_app.config['DB_TYPE'] == 'postgres':
        conn = psycopg2.connect(
            host='127.0.0.1',
            database='maria_khmeleva_knowledge_base_db',
            user='maria_khmeleva_knowledge_base_db',
            password='123'
        )
        cur = conn.cursor(cursor_factory=RealDictCursor)
    else:
        dir_path = path.dirname(path.realpath(__file__))
        db_path = path.join(dir_path, "database.db")
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
    return conn, cur

# Функция для закрытия соединения с базой данных
def db_close(conn, cur):
    conn.commit()
    cur.close()
    conn.close()

# Главная страница
@app.route('/')
def index():
    conn, cur = db_connect()
    cur.execute("SELECT * FROM products")
    products = cur.fetchall()
    db_close(conn, cur)
    user_login = None
    if session.get('user'):
        conn, cur = db_connect()
        if current_app.config['DB_TYPE'] == 'postgres':
            cur.execute("SELECT login,role FROM users WHERE id = %s", (session['user'],))
        else:
            cur.execute("SELECT login,role FROM users WHERE id = ?", (session['user'],))
        user = cur.fetchone()
        db_close(conn, cur)
        if user:
            user_login = user['login']
            user_role = user.get('role')
            return render_template('index.html', products=products, user_login=user_login,user_role=user_role)

    return render_template('index.html', products=products, user_login=user_login)

# Регистрация пользователя
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if not username or not password or password != confirm_password:
            flash('Invalid input', 'error')
            return redirect(url_for('register'))
        conn, cur = db_connect()
        if current_app.config['DB_TYPE'] == 'postgres':
            cur.execute("SELECT id FROM users WHERE login = %s", (username,))
        else:
            cur.execute("SELECT id FROM users WHERE login = ?", (username,))

        existing_user = cur.fetchone()
        db_close(conn, cur)

        if existing_user:
            flash('Пользователь с таким логином уже существует', 'error')
            return redirect(url_for('register'))
        hashed_password = generate_password_hash(password)

        conn, cur = db_connect()
        if current_app.config['DB_TYPE'] == 'postgres':
            cur.execute("INSERT INTO users (login, password) VALUES (%s, %s)", (username, hashed_password))
        else:   
            cur.execute("INSERT INTO users (login, password) VALUES (?, ?)", (username, hashed_password))

        db_close(conn, cur)

        flash('Registration successful', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

# Авторизация пользователя
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn, cur = db_connect()
        if current_app.config['DB_TYPE'] == 'postgres':
            cur.execute("SELECT * FROM users WHERE login = %s", (username,))
        else:
            cur.execute("SELECT * FROM users WHERE login = ?", (username,))
        user = cur.fetchone()
        db_close(conn, cur)

        if user and check_password_hash(user['password'], password):
            session['user'] = user['id']
            flash('Login successful', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password', 'error')

    return render_template('login.html')

# Выход из аккаунта
@app.route('/logout')
def logout():
    session.pop('user', None)
    flash('You have been logged out', 'success')
    return redirect(url_for('index'))

# Корзина пользователя
@app.route('/cart')
def cart():
    if not session.get('user'):
        flash('Вы не авторизованы', 'error')
        return redirect(url_for('login'))

    user_id = session['user']
    conn, cur = db_connect()
    if current_app.config['DB_TYPE'] == 'postgres':
        cur.execute("""
            SELECT products.id, products.name, products.price
            FROM products
            JOIN cart ON products.id = cart.product_id
            WHERE cart.user_id = %s
        """, (user_id,))
    else:
            cur.execute("""
            SELECT products.id, products.name, products.price
            FROM products
            JOIN cart ON products.id = cart.product_id
            WHERE cart.user_id = ?
        """, (user_id,))
    cart_items = cur.fetchall()
    db_close(conn, cur)

    # Получаем логин и роль пользователя
    user_login = None
    user_role = None
    if session.get('user'):
        conn, cur = db_connect()
        if current_app.config['DB_TYPE'] == 'postgres':
            cur.execute("SELECT login, role FROM users WHERE id = %s", (session['user'],))
        else:
            cur.execute("SELECT login, role FROM users WHERE id = %s", (session['user'],))
        user = cur.fetchone()
        db_close(conn, cur)
        if user:
            user_login = user['login']
            user_role = user['role']

    return render_template('cart.html', cart_items=cart_items, user_login=user_login, user_role=user_role)

# Добавление товара в корзину
@app.route('/add_to_cart/<int:product_id>')
def add_to_cart(product_id):
    if not session.get('user'):
        flash('You need to log in first', 'error')
        return redirect(url_for('login'))

    user_id = session['user']
    conn, cur = db_connect()
    if current_app.config['DB_TYPE'] == 'postgres':
        cur.execute("INSERT INTO cart (user_id, product_id) VALUES (%s, %s)", (user_id, product_id))
    else:
         cur.execute("INSERT INTO cart (user_id, product_id) VALUES (?, ?)", (user_id, product_id))
    db_close(conn, cur)

    flash('Product added to cart', 'success')
    return redirect(url_for('index'))

# Удаление товара из корзины
@app.route('/remove_from_cart/<int:product_id>')
def remove_from_cart(product_id):
    if not session.get('user'):
        flash('You need to log in first', 'error')
        return redirect(url_for('login'))

    user_id = session['user']
    conn, cur = db_connect()
    if current_app.config['DB_TYPE'] == 'postgres':
        cur.execute("DELETE FROM cart WHERE user_id = %s AND product_id = %s", (user_id, product_id))
    else:
        cur.execute("DELETE FROM cart WHERE user_id = ? AND product_id = ?", (user_id, product_id))
    db_close(conn, cur)

    flash('Product removed from cart', 'success')
    return redirect(url_for('cart'))

# Оформление заказа
@app.route('/checkout')
def checkout():
    if not session.get('user'):
        flash('You need to log in first', 'error')
        return redirect(url_for('login'))

    user_id = session['user']
    conn, cur = db_connect()
    if current_app.config['DB_TYPE'] == 'postgres':
        cur.execute("DELETE FROM cart WHERE user_id = %s", (user_id,))
    else:
        cur.execute("DELETE FROM cart WHERE user_id = ?", (user_id,))
    db_close(conn, cur)

    flash('Order placed successfully', 'success')
    return redirect(url_for('index'))


@app.route('/delete_account', methods=['POST'])
def delete_account():
    if not session.get('user'):
        flash('Вы не авторизованы', 'error')
        return redirect(url_for('login'))

    user_id = session['user']

    # Удаляем пользователя из базы данных
    conn, cur = db_connect()
    if current_app.config['DB_TYPE'] == 'postgres':
        cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
    else:
        cur.execute("DELETE FROM users WHERE id = ?", (user_id,))
    db_close(conn, cur)

    # Удаляем пользователя из сессии
    session.pop('user', None)

    flash('Ваш аккаунт успешно удален', 'success')
    return redirect(url_for('index'))


def is_admin():
    if session.get('user'):
        conn, cur = db_connect()
        if current_app.config['DB_TYPE'] == 'postgres':
            cur.execute("SELECT role FROM users WHERE id = %s", (session['user'],))
        else:
            cur.execute("SELECT role FROM users WHERE id = ?", (session['user'],))
        user = cur.fetchone()
        db_close(conn, cur)
        return user and user['role'] == 'admin'
    return False


# Страница администратора
@app.route('/admin')
def admin():
    if not is_admin():
        flash('Доступ запрещен', 'error')
        return redirect(url_for('index'))

    # Получаем список пользователей и товаров
    conn, cur = db_connect()
    if current_app.config['DB_TYPE'] == 'postgres':
        cur.execute("SELECT id, login, role FROM users")
    else:
        cur.execute("SELECT id, login, role FROM users")
    users = cur.fetchall()
    cur.execute("SELECT id, name, price, description FROM products")
    products = cur.fetchall()
    db_close(conn, cur)

    return render_template('admin.html', users=users, products=products)

# Удаление пользователя
@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if not is_admin():
        flash('Доступ запрещен', 'error')
        return redirect(url_for('index'))

    conn, cur = db_connect()
    if current_app.config['DB_TYPE'] == 'postgres':
        cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
    else:
        cur.execute("DELETE FROM users WHERE id = ?", (user_id,))
    db_close(conn, cur)

    flash('Пользователь удален', 'success')
    return redirect(url_for('admin'))

# Удаление товара
@app.route('/admin/delete_product/<int:product_id>', methods=['POST'])
def delete_product(product_id):
    if not is_admin():
        flash('Доступ запрещен', 'error')
        return redirect(url_for('index'))

    conn, cur = db_connect()
    if current_app.config['DB_TYPE'] == 'postgres':
        cur.execute("DELETE FROM products WHERE id = %s", (product_id,))
    else:
        cur.execute("DELETE FROM products WHERE id = ?", (product_id,))
    db_close(conn, cur)

    flash('Товар удален', 'success')
    return redirect(url_for('admin'))

# Добавление товара
@app.route('/admin/add_product', methods=['GET', 'POST'])
def add_product():
    if not is_admin():
        flash('Доступ запрещен', 'error')
        return redirect(url_for('index'))

    if request.method == 'POST':
        name = request.form['name']
        price = request.form['price']
        description = request.form['description']

        conn, cur = db_connect()
        if current_app.config['DB_TYPE'] == 'postgres':
            cur.execute("INSERT INTO products (name, price, description) VALUES (%s, %s, %s)",
                    (name, price, description))
        else:
            cur.execute("INSERT INTO products (name, price, description) VALUES (?, ?, ?)",
                    (name, price, description))
        db_close(conn, cur)

        flash('Товар добавлен', 'success')
        return redirect(url_for('admin'))

    return render_template('add_product.html')