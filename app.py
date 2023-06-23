import uuid
from flask import Flask, render_template, request, redirect, jsonify, g, flash, url_for
from flask_bcrypt import Bcrypt
from dotenv import load_dotenv
from models import Recipe, User
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

from flask_login import LoginManager, current_user, login_user, login_required, logout_user
import os
import sqlite3

load_dotenv() 

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')
sendgrid_api_key = os.getenv('SENDGRID_API_KEY')

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
                        image_address TEXT NOT NULL,
                        user_id VARCHAR(36) NOT NULL,
                        FOREIGN KEY (user_id) REFERENCES users(id))''')
        db.execute('''CREATE TABLE IF NOT EXISTS users
                        (id VARCHAR(36) PRIMARY KEY,
                        email VARCHAR(255) NOT NULL,
                        password VARCHAR(255) NOT NULL)''')


    db.row_factory = sqlite3.Row

    return db

def get_user(email):
    cursor = get_db().cursor()
    cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
    user = cursor.fetchone()

    if user is None:
        return None

    return User(user[0], user[1], user[2])


def get_user_by_id(id):
    cursor = get_db().cursor()
    cursor.execute('SELECT * FROM users WHERE id = ?', (id,))
    user = cursor.fetchone()

    if user is None:
        return None

    return User(user[0], user[1], user[2])


def get_recipe(id):
    cursor = get_db().cursor()
    cursor.execute('SELECT * FROM recipes WHERE id = ?', (id,))
    recipe = cursor.fetchone()

    if recipe is None:
        return None

    return Recipe(*recipe)


def hash_password(password):
    return bcrypt.generate_password_hash(password).decode('utf-8')


def send_reset_password_email(user_email, reset_password_link):
    message = Mail(
        from_email='cargo2137@wp.pl',
        to_emails=user_email,
        subject='Reset Your Password',
        html_content=f'Click the link to reset your password: <a href="{reset_password_link}">{reset_password_link}</a>'
    )

    try:
        sg = SendGridAPIClient(sendgrid_api_key)
        response = sg.send(message)
        print(response.status_code)
        print(response.body)
        print(response.headers)
    except Exception as e:
        print(str(e))


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
        db.execute('INSERT INTO recipes (title, ingredients, instructions, image_address, user_id) VALUES (?, ?, ?, ?, ?)',
                   (title, ingredients, instructions, image_address, current_user.id))
        db.commit()

        return redirect('/')

    return render_template('add_recipe.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        db = get_db()
        cursor = db.cursor()
        user = get_user(email)

        if user:
            flash('Email already exists. Please choose a different email.', 'error')
            return redirect('/register')

        hashed_password = hash_password(password)
        user_id = str(uuid.uuid4())
        cursor.execute("INSERT INTO users (id, email, password) VALUES (?, ?, ?)", (user_id, email, hashed_password))
        db.commit()

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

        user = get_user(email)

        is_valid = bcrypt.check_password_hash(user.password, password)

        if user is None or not is_valid:
            flash('Invalid email or password.', 'error')
            return redirect(url_for('login'))
        
        login_user(user)

        return redirect(url_for('index'))

    return render_template('login.html')


@app.route('/recipe/edit/<int:recipe_id>', methods=['GET', 'POST'])
@login_required
def edit_recipe(recipe_id):
    db = get_db()
    recipe = get_recipe(recipe_id)

    if not recipe:
        return 'Recipe not found'

    if request.method == 'POST':
        title = request.form['title']
        ingredients = request.form['ingredients']
        instructions = request.form['instructions']

        if recipe.user_id != current_user.id:
            return render_template('forbidden.html')

        db.execute('UPDATE recipes SET title = ?, ingredients = ?, instructions = ? WHERE id = ?',
                   (title, ingredients, instructions, recipe_id))
        db.commit()

        return redirect(url_for('recipe', recipe_id=recipe_id))

    return render_template('edit_recipe.html', recipe=recipe)


@app.route('/reset_password/<user_id>', methods=['GET', 'POST'])
def reset_password(user_id):
    user = get_user_by_id(user_id)
    if not user:
        return 'Invalid reset token'
    if request.method == 'POST':
        password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        if password == confirm_password:
            hashed_password = hash_password(password)
            db = get_db()
            db.cursor().execute("UPDATE users SET password = ? WHERE id = ?", (hashed_password, user.id))
            db.commit()
            flash('Your password reset has been successful', 'info')
            return redirect(url_for('login'))
        else:
            return 'Password and confirm password do not match'
    return render_template('reset_password.html', user_id=user_id)


@app.route('/recipe/delete/<int:recipe_id>', methods=['POST'])
@login_required
def delete_recipe(recipe_id):

    recipe = get_recipe(recipe_id)

    if recipe.user_id != current_user.id:
        return render_template('forbidden.html')
    
    db = get_db()
    db.execute('DELETE FROM recipes WHERE id = ?', (recipe_id,))
    db.commit()
    flash('Recipe deleted successfully', 'success')
    return redirect(url_for('index'))


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = get_user(email)

        if user:
            send_reset_password_email(email, f'http://localhost:5000/reset_password/{user.id}')

            return render_template('reset_successful.html')
        else:
            flash('Email not found', 'info')
            render_template('forgot_password.html')
    return render_template('forgot_password.html')


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
