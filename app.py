from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime
import os
import subprocess
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///scripts.db'
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
port = 5001

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('You need to be an admin to access this page.', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Script(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_run = db.Column(db.DateTime, nullable=True)
    last_output = db.Column(db.Text, nullable=True)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def has_admin():
    return User.query.filter_by(is_admin=True).first() is not None

# Create the database and tables
with app.app_context():
    #db.drop_all()
    db.create_all()

@app.route('/setup-admin', methods=['GET', 'POST'])
def setup_admin():
    if has_admin():
        flash('Admin user already exists!', 'error')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if not username or not password:
            flash('Username and password are required!', 'error')
            return redirect(url_for('setup_admin'))
        
        if password != confirm_password:
            flash('Passwords do not match!', 'error')
            return redirect(url_for('setup_admin'))
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists!', 'error')
            return redirect(url_for('setup_admin'))
        
        admin = User(username=username, is_admin=True)
        admin.set_password(password)
        db.session.add(admin)
        db.session.commit()
        
        flash('Admin user created successfully! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('setup_admin.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if not has_admin():
        return redirect(url_for('setup_admin'))
        
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password!', 'error')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('login'))

@app.route('/users')
@login_required
@admin_required
def users():
    users = User.query.all()
    return render_template('users.html', users=users)

@app.route('/users/create', methods=['GET', 'POST'])
@login_required
@admin_required
def create_user():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        is_admin = request.form.get('is_admin') == 'on'
        
        if not username or not password:
            flash('Username and password are required!', 'error')
            return redirect(url_for('create_user'))
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists!', 'error')
            return redirect(url_for('create_user'))
        
        user = User(username=username, is_admin=is_admin)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        flash('User created successfully!', 'success')
        return redirect(url_for('users'))
    
    return render_template('create_user.html')

@app.route('/users/delete/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    if user_id == current_user.id:
        flash('You cannot delete your own account!', 'error')
        return redirect(url_for('users'))
    
    user = User.query.get_or_404(user_id)
    try:
        db.session.delete(user)
        db.session.commit()
        flash('User deleted successfully!', 'success')
    except Exception as e:
        flash(f'Error deleting user: {str(e)}', 'error')
    return redirect(url_for('users'))

@app.route('/')
@login_required
def index():
    scripts = Script.query.order_by(Script.created_at.desc()).all()
    return render_template('index.html', scripts=scripts)

@app.route('/create', methods=['GET', 'POST'])
@login_required
def create_script():
    if request.method == 'POST':
        name = request.form.get('name')
        content = request.form.get('content')
        
        if not name or not content:
            flash('Name and content are required!', 'error')
            return redirect(url_for('create_script'))
        
        script = Script(name=name, content=content)
        db.session.add(script)
        db.session.commit()
        
        flash('Script created successfully!', 'success')
        return redirect(url_for('index'))
    
    return render_template('create.html')

@app.route('/edit/<int:script_id>', methods=['GET', 'POST'])
@login_required
def edit_script(script_id):
    script = Script.query.get_or_404(script_id)
    
    if request.method == 'POST':
        name = request.form.get('name')
        content = request.form.get('content')
        
        if not name or not content:
            flash('Name and content are required!', 'error')
            return redirect(url_for('edit_script', script_id=script_id))
        
        script.name = name
        script.content = content
        db.session.commit()
        
        flash('Script updated successfully!', 'success')
        return redirect(url_for('index'))
    
    return render_template('edit.html', script=script)

@app.route('/run/<int:script_id>')
@login_required
def run_script(script_id):
    script = Script.query.get_or_404(script_id)
    try:
        # Create a temporary file to run the script
        temp_file = f'temp_script_{script_id}.py'
        with open(temp_file, 'w') as f:
            f.write(script.content)
        
        # Execute the script and capture output
        result = subprocess.run(['python', temp_file], 
                              capture_output=True, 
                              text=True)
        
        # Clean up
        os.remove(temp_file)
        
        # Update last run time and output
        script.last_run = datetime.utcnow()
        script.last_output = result.stdout
        if result.stderr:
            script.last_output += f"\nErrors:\n{result.stderr}"
        db.session.commit()
        
        flash('Script executed successfully!', 'success')
    except Exception as e:
        flash(f'Error executing script: {str(e)}', 'error')
    
    return redirect(url_for('index'))

@app.route('/delete/<int:script_id>', methods=['POST'])
@login_required
def delete_script(script_id):
    script = Script.query.get_or_404(script_id)
    try:
        db.session.delete(script)
        db.session.commit()
        flash('Script deleted successfully!', 'success')
    except Exception as e:
        flash(f'Error deleting script: {str(e)}', 'error')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True, port=port) 