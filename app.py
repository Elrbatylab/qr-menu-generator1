import os
from flask import Flask, render_template, request, redirect, url_for, flash, session, g
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3
import qrcode
import requests
import base64
from io import BytesIO
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', '35efa29d044333d9eec6bc882dd8e3b8')

# Configuration
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg'}
IMGBB_API_KEY = os.environ.get('IMGBB_API_KEY', '2f4c2773691fe64571698647f8b17a44')

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Database setup
DATABASE = os.path.join(app.instance_path, 'database.db')
os.makedirs(app.instance_path, exist_ok=True)

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(error):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.executescript(f.read())
        db.commit()

# Initialize the database if it doesn't exist
if not os.path.exists(DATABASE):
    init_db()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None

        if not username:
            error = 'Username is required.'
        elif not password:
            error = 'Password is required.'
        elif db.execute('SELECT id FROM users WHERE username = ?', 
            (username,)).fetchone() is not None:
            error = f'User {username} is already registered.'

        if error is None:
            db.execute('INSERT INTO users (username, password) VALUES (?, ?)',
                      (username, generate_password_hash(password)))
            db.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))

        flash(error, 'error')

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None
        user = db.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()

        if user is None:
            error = 'Incorrect username.'
        elif not check_password_hash(user['password'], password):
            error = 'Incorrect password.'

        if error is None:
            session.clear()
            session['user_id'] = user['id']
            return redirect(url_for('dashboard'))

        flash(error, 'error')

    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Please login first', 'error')
        return redirect(url_for('login'))
    
    db = get_db()
    # Get username
    user = db.execute('SELECT username FROM users WHERE id = ?', 
                     (session['user_id'],)).fetchone()
    
    # Get menus with proper datetime formatting
    menus = db.execute('''
        SELECT id, menu_name, filename, url, qr_code_url,
               datetime(created_at) as created_at
        FROM menus 
        WHERE user_id = ? 
        ORDER BY created_at DESC
    ''', (session['user_id'],)).fetchall()
    
    return render_template('dashboard.html', 
                         menus=menus, 
                         username=user['username'])

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out successfully', 'success')
    return redirect(url_for('login'))

@app.route('/upload_menu', methods=['POST'])
def upload_menu():
    if 'user_id' not in session:
        flash('Please login first', 'error')
        return redirect(url_for('login'))

    if 'menu_file' not in request.files:
        flash('No file uploaded', 'error')
        return redirect(url_for('dashboard'))
    
    menu_name = request.form.get('menu_name', '').strip()
    if not menu_name:
        flash('Menu name is required', 'error')
        return redirect(url_for('dashboard'))
    
    file = request.files['menu_file']
    if file.filename == '':
        flash('No file selected', 'error')
        return redirect(url_for('dashboard'))

    try:
        # Read and encode file
        file_content = file.read()
        base64_image = base64.b64encode(file_content).decode('utf-8')
        
        # Upload to ImgBB
        payload = {
            'key': IMGBB_API_KEY,
            'image': base64_image,
            'name': secure_filename(file.filename)
        }
        
        response = requests.post('https://api.imgbb.com/1/upload', data=payload)
        response.raise_for_status()
        
        img_data = response.json()
        menu_url = img_data['data']['url']
        
        # Generate QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(menu_url)
        qr.make(fit=True)
        
        qr_image = qr.make_image(fill_color="black", back_color="white")
        
        # Save QR code to BytesIO
        qr_io = BytesIO()
        qr_image.save(qr_io, 'PNG')
        qr_io.seek(0)
        
        # Upload QR code to ImgBB
        qr_base64 = base64.b64encode(qr_io.getvalue()).decode('utf-8')
        qr_payload = {
            'key': IMGBB_API_KEY,
            'image': qr_base64,
            'name': f'qr_code_{secure_filename(file.filename)}'
        }
        
        qr_response = requests.post('https://api.imgbb.com/1/upload', data=qr_payload)
        qr_response.raise_for_status()
        
        qr_url = qr_response.json()['data']['url']
        
        # Save to database
        db = get_db()
        db.execute('''
            INSERT INTO menus (menu_name, filename, url, qr_code_url, user_id)
            VALUES (?, ?, ?, ?, ?)
        ''', (menu_name, file.filename, menu_url, qr_url, session['user_id']))
        db.commit()
        
        flash('Menu uploaded and QR code generated successfully!', 'success')
        
    except Exception as e:
        flash(f'An error occurred: {str(e)}', 'error')
    
    return redirect(url_for('dashboard'))

@app.route('/init-db')
def initialize_database():
    try:
        init_db()
        return 'Database initialized successfully!'
    except Exception as e:
        return f'Error initializing database: {str(e)}'

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=True)
