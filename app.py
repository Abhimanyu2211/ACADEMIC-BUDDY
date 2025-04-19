from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Change this in production!
app.config['UPLOAD_FOLDER'] = 'uploads'  # Create this folder

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Database setup (in production, use a real database)
users = {
    # This will store all users
}

tutors = {
    # This will store tutor-specific info
}

@app.route('/')
def home():
    return render_template('index.html')  # Your main page

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = users.get(username)
        
        if user and check_password_hash(user['password'], password):
            session['user'] = username
            session['user_type'] = user['type']
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'error')
    
    return render_template('login.html')

@app.route('/signup/client', methods=['POST'])
def signup_client():
    name = request.form.get('name')
    email = request.form.get('email')
    phone = request.form.get('phone')
    password = request.form.get('password')
    confirm_password = request.form.get('confirm_password')
    
    if password != confirm_password:
        flash('Passwords do not match.', 'error')
        return redirect(url_for('home'))
    
    if email in users:
        flash('Email already registered.', 'error')
        return redirect(url_for('home'))
    
    users[email] = {
        'name': name,
        'password': generate_password_hash(password),
        'phone': phone,
        'type': 'client'
    }
    
    flash('Registration successful! Please login.', 'success')
    return redirect(url_for('login'))

@app.route('/signup/provider', methods=['POST'])
def signup_provider():
    name = request.form.get('name')
    email = request.form.get('email')
    phone = request.form.get('phone')
    password = request.form.get('password')
    confirm_password = request.form.get('confirm_password')
    services = request.form.getlist('services[]')
    achievements = request.form.get('achievements')
    proof = request.files['proof']
    
    if password != confirm_password:
        flash('Passwords do not match.', 'error')
        return redirect(url_for('home'))
    
    if email in users:
        flash('Email already registered.', 'error')
        return redirect(url_for('home'))
    
    # Save the proof file
    if proof:
        filename = secure_filename(f"{email}_{proof.filename}")
        proof.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    else:
        filename = None
    
    users[email] = {
        'name': name,
        'password': generate_password_hash(password),
        'phone': phone,
        'type': 'provider'
    }
    
    tutors[email] = {
        'services': services,
        'achievements': achievements,
        'proof': filename
    }
    
    flash('Registration successful! Please login.', 'success')
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    user_type = session.get('user_type')
    username = session.get('user')
    
    if user_type == 'provider':
        tutor_info = tutors.get(username, {})
        return render_template('dashboard_provider.html', 
                             user=users[username],
                             tutor=tutor_info)
    else:
        return render_template('dashboard_client.html', 
                             user=users[username])

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)