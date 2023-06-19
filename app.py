from flask import Flask, render_template, request, redirect, jsonify, g, flash, url_for
from flask_bcrypt import Bcrypt
from dotenv import load_dotenv
from models import Recipe, User
from flask_login import LoginManager, current_user, login_user, login_required, logout_user
import os
import sqlite3

load_dotenv() 

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')

bcrypt = Bcrypt(app)

DATABASE = 'recipes.db'

login_manager = LoginManager()
login_manager.init_app(app)

def get_db():
    db = getattr(g, '_database', None)

    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.execute('''CREATE TABLE IF NOT EXISTS recipes
                        (id INTEGER PRIMARY KEY AUTOINCREMENT,
                        title TEXT NOT NULL,
                        ingredients TEXT NOT NULL,
                        instructions TEXT NOT NULL,
                        image_address TEXT NOT NULL)''')
        db.execute('''CREATE TABLE IF NOT EXISTS users
                        (id INTEGER PRIMARY KEY AUTOINCREMENT,
                        email VARCHAR(255) NOT NULL,
                        password VARCHAR(255) NOT NULL)''')


    db.row_factory = sqlite3.Row

    return db

@login_manager.user_loader
def load_user(user_id):
    cursor = get_db().cursor()
    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()

    if user is None:
        return None

    return User(user[0], user[1], user[2])

@app.route('/')
def index():
    db = get_db()
    cursor = db.execute('SELECT id, title FROM recipes')
    recipes = [{'id': row[0], 'title': row[1]} for row in cursor.fetchall()]

    is_json = request.args.get('json', False)

    if is_json:
        return jsonify(recipes)
    else:
        return render_template('index.html', recipes=recipes, current_user=current_user)


@app.route('/recipe/<int:recipe_id>')
def recipe(recipe_id):
    db = get_db()
    cursor = db.execute('SELECT * FROM recipes WHERE id = ?', (recipe_id,))
    recipe_data = cursor.fetchone()

    is_json = request.args.get('json', False)

    if recipe_data:
        recipe = Recipe(*recipe_data)

        if is_json:
            return recipe.to_json()
        else:
            return render_template('recipe.html', recipe=recipe)
    else:
        return 'Recipe not found'

@app.route('/recipe/add', methods=['GET', 'POST'])
@login_required
def add_recipe():
    if request.method == 'POST':
        title = request.form['title']
        ingredients = request.form['ingredients']
        instructions = request.form['instructions']
        image_address = request.form['image_address']

        db = get_db()
        db.execute('INSERT INTO recipes (title, ingredients, instructions, image_address) VALUES (?, ?, ?, ?)',
                   (title, ingredients, instructions, image_address))
        db.commit()

        return redirect('/')

    return render_template('add_recipe.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email=?", (email,))
        user = cursor.fetchone()

        if user:
            flash('Email already exists. Please choose a different email.', 'error')
            return redirect('/register')

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        cursor.execute("INSERT INTO users (email, password) VALUES (?, ?)", (email, hashed_password))
        conn.commit()

        flash('Registration successful. You can now log in.', 'success')
        return redirect('/login')

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        cursor = get_db().cursor()
        cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
        user = cursor.fetchone()

        is_valid = bcrypt.check_password_hash(user[2], password)

        if user is None or not is_valid:
            flash('Invalid email or password.', 'error')
            return redirect(url_for('login'))
        

        user_obj = User(user[0], user[1], user[2])
        login_user(user_obj)

        return redirect(url_for('index'))

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out', 'info')
    return redirect('/login')


@login_manager.unauthorized_handler
def unauthorized():
    return render_template('unauthorized.html')



if __name__ == '__main__':
    app.run(debug=True)
