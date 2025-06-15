from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-this-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///secure_messages.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    encryption_key = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    sent_messages = db.relationship('Message', foreign_keys='Message.sender_id', backref='sender', lazy='dynamic')
    received_messages = db.relationship('Message', foreign_keys='Message.recipient_id', backref='recipient', lazy='dynamic')

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    encrypted_for_sender = db.Column(db.Text, nullable=False)
    encrypted_for_recipient = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Encryption utilities
class MessageEncryption:
    @staticmethod
    def generate_key_from_password(password: str, salt: bytes = None) -> bytes:
        """Generate encryption key from password using PBKDF2"""
        if salt is None:
            salt = os.urandom(16)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key, salt
    
    @staticmethod
    def encrypt_message(message: str, key: bytes) -> str:
        """Encrypt message using Fernet (AES 128)"""
        f = Fernet(key)
        encrypted_message = f.encrypt(message.encode())
        return base64.urlsafe_b64encode(encrypted_message).decode()
    
    @staticmethod
    def decrypt_message(encrypted_message: str, key: bytes) -> str:
        """Decrypt message using Fernet"""
        try:
            f = Fernet(key)
            encrypted_data = base64.urlsafe_b64decode(encrypted_message.encode())
            decrypted_message = f.decrypt(encrypted_data)
            return decrypted_message.decode()
        except Exception as e:
            return f"[Error decrypting message: {str(e)}]"

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('messages'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        # Check if user exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('register'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered')
            return redirect(url_for('register'))
        
        # Generate encryption key for user
        encryption_key, salt = MessageEncryption.generate_key_from_password(password)
        
        # Create new user
        user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
            encryption_key=base64.urlsafe_b64encode(salt).decode() + ':' + encryption_key.decode()
        )
        
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('messages'))
        else:
            flash('Invalid username or password')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/messages')
@login_required
def messages():
    users = User.query.filter(User.id != current_user.id).all()
    
    received_messages = Message.query.filter_by(recipient_id=current_user.id).all()
    sent_messages = Message.query.filter_by(sender_id=current_user.id).all()
    
    decrypted_received = []
    decrypted_sent = []

    # Ambil key current_user (baik sbg pengirim atau penerima)
    key_data = current_user.encryption_key.split(':')
    key = key_data[1].encode()

    for msg in received_messages:
        try:
            decrypted_content = MessageEncryption.decrypt_message(msg.encrypted_for_recipient, key)
        except:
            decrypted_content = '[Failed to decrypt]'
        decrypted_received.append({
            'id': msg.id,
            'sender': msg.sender.username,
            'content': decrypted_content,
            'timestamp': msg.timestamp,
            'is_read': msg.is_read
        })

    for msg in sent_messages:
        try:
            decrypted_content = MessageEncryption.decrypt_message(msg.encrypted_for_sender, key)
        except:
            decrypted_content = '[Failed to decrypt]'
        decrypted_sent.append({
            'id': msg.id,
            'recipient': msg.recipient.username,
            'content': decrypted_content,
            'timestamp': msg.timestamp
        })
    
    return render_template('messages.html', 
                           users=users, 
                           received_messages=decrypted_received,
                           sent_messages=decrypted_sent)

@app.route('/send_message', methods=['POST'])
@login_required
def send_message():
    recipient_id = request.form['recipient_id']
    message_content = request.form['message']
    
    if not message_content.strip():
        flash('Message cannot be empty')
        return redirect(url_for('messages'))
    
    recipient = User.query.get(recipient_id)

    # Ambil key penerima
    rec_key_data = recipient.encryption_key.split(':')
    rec_key = rec_key_data[1].encode()
    encrypted_for_recipient = MessageEncryption.encrypt_message(message_content, rec_key)

    # Ambil key pengirim
    sender_key_data = current_user.encryption_key.split(':')
    sender_key = sender_key_data[1].encode()
    encrypted_for_sender = MessageEncryption.encrypt_message(message_content, sender_key)

    message = Message(
        sender_id=current_user.id,
        recipient_id=recipient.id,
        encrypted_for_sender=encrypted_for_sender,
        encrypted_for_recipient=encrypted_for_recipient
    )
    
    db.session.add(message)
    db.session.commit()
    
    flash('Message sent successfully')
    return redirect(url_for('messages'))

@app.route('/mark_read/<int:message_id>')
@login_required
def mark_read(message_id):
    message = Message.query.get_or_404(message_id)
    if message.recipient_id == current_user.id:
        message.is_read = True
        db.session.commit()
    return redirect(url_for('messages'))

@app.route('/test_encryption')
def test_encryption():
    """Test endpoint untuk validasi enkripsi"""
    test_message = "Hello, this is a test message!"
    test_password = "test_password_123"
    
    # Generate key
    key, salt = MessageEncryption.generate_key_from_password(test_password)
    
    # Encrypt
    encrypted = MessageEncryption.encrypt_message(test_message, key)
    
    # Decrypt
    decrypted = MessageEncryption.decrypt_message(encrypted, key)
    
    return jsonify({
        'original': test_message,
        'encrypted': encrypted,
        'decrypted': decrypted,
        'success': test_message == decrypted
    })

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        
        # Create test users if they don't exist
        if not User.query.filter_by(username='alice').first():
            key, salt = MessageEncryption.generate_key_from_password('password123')
            alice = User(
                username='alice',
                email='alice@example.com',
                password_hash=generate_password_hash('password123'),
                encryption_key=base64.urlsafe_b64encode(salt).decode() + ':' + key.decode()
            )
            db.session.add(alice)
        
        if not User.query.filter_by(username='bob').first():
            key, salt = MessageEncryption.generate_key_from_password('password456')
            bob = User(
                username='bob',
                email='bob@example.com',
                password_hash=generate_password_hash('password456'),
                encryption_key=base64.urlsafe_b64encode(salt).decode() + ':' + key.decode()
            )
            db.session.add(bob)
        
        db.session.commit()
    
    print("🔐 Flask Secure Messaging App")
    print("📧 Test users: alice/password123, bob/password456")
    print("🌐 Visit: http://localhost:5000")
    print("🧪 Test encryption: http://localhost:5000/test_encryption")
    
    app.run(debug=True)