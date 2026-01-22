#!/usr/bin/env python3
"""
Realistic E-Commerce Application with Mixed Security (Final Version)
-------------------------------------------------------------------------
This intentionally vulnerable application demonstrates core vulnerabilities (SQL injection,
command injection, SSRF, business logic flaws) while also incorporating functional improvements:
  - Duplicate route definitions removed.
  - Input validation for file paths and cart quantities.
  - Database transactions with proper error handling and concurrency control.
  - Stock validation before checkout.
  - Improved cart session management.
  - Order amount validation and error handling.

Rate limiting is set to 20 requests per 20 seconds per IP.
10 default products with real-world names (and random stock between 30 and 100) are preloaded.

> **Warning:** This code is intentionally vulnerable (with added functional improvements for training).
Do not use it in production.
"""

import os
import random
import re
import sqlite3
import xml.etree.ElementTree as ET  # Vulnerable XML parsing
import requests
import subprocess
import threading
import time  # Add this import
from flask import Flask, request, session, redirect, url_for, flash, g, render_template, make_response
from jinja2 import DictLoader
from collections import Counter
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from functools import wraps
from flask import send_file
from datetime import datetime
import fpdf  # Add this to requirements.txt

# -----------------------
# App & Rate Limiter Setup
# -----------------------
app = Flask(__name__)
app.secret_key = "insecure_secret_key"  # Demo only; not secure
app.debug = True

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["20 per 20 seconds"]
)

# -----------------------
# Directories & Database Setup
# -----------------------
DATABASE = 'ecommerce.db'
UPLOAD_FOLDER = os.path.join(os.getcwd(), "uploads")
LOGS_FOLDER = os.path.join(os.getcwd(), "logs")
INVOICES_FOLDER = os.path.join(os.getcwd(), "invoices")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(LOGS_FOLDER, exist_ok=True)
os.makedirs(INVOICES_FOLDER, exist_ok=True)

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"

# -----------------------
# Global Lock for Critical DB Operations
# -----------------------
db_lock = threading.Lock()

# -----------------------
# Database Helpers & Initialization
# -----------------------
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
        # Enable foreign key support
        db.execute("PRAGMA foreign_keys = ON")
    return db

def init_db():
    # Create a direct database connection for initialization
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    c = db.cursor()
    
    # Drop existing tables
    c.execute("DROP TABLE IF EXISTS activity_log")
    c.execute("DROP TABLE IF EXISTS wishlist")
    c.execute("DROP TABLE IF EXISTS profiles")
    c.execute("DROP TABLE IF EXISTS subscriptions")
    c.execute("DROP TABLE IF EXISTS support_tickets")
    c.execute("DROP TABLE IF EXISTS reviews")
    c.execute("DROP TABLE IF EXISTS orders")
    c.execute("DROP TABLE IF EXISTS products")
    c.execute("DROP TABLE IF EXISTS addresses")
    c.execute("DROP TABLE IF EXISTS users")
    
    # Create tables in correct order (users first, then dependent tables)
    c.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            security_question TEXT,
            security_answer TEXT,
            qid TEXT UNIQUE,
            role TEXT DEFAULT 'user'
        )
    ''')

    # Create products table
    c.execute('''
        CREATE TABLE products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            price REAL NOT NULL,
            stock INTEGER NOT NULL DEFAULT 0
        )
    ''')
    
    c.execute('''
        CREATE TABLE addresses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            street TEXT,
            city TEXT,
            country TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')
    
    c.execute('''
        CREATE TABLE orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            address_id INTEGER,
            product_ids TEXT,
            amount REAL,
            status TEXT DEFAULT 'Processing',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY(address_id) REFERENCES addresses(id) ON DELETE RESTRICT
        )
    ''')
    
    c.execute('''
        CREATE TABLE activity_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            activity TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')
    
    c.execute('''
        CREATE TABLE reviews (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            product_id INTEGER,
            user_id INTEGER,
            review TEXT,
            rating INTEGER CHECK(rating BETWEEN 1 AND 5),
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(product_id) REFERENCES products(id) ON DELETE CASCADE,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')
    
    c.execute('''
        CREATE TABLE wishlist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            product_id INTEGER,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY(product_id) REFERENCES products(id) ON DELETE CASCADE
        )
    ''')
    
    c.execute('''
        CREATE TABLE profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER UNIQUE,
            display_name TEXT,
            email TEXT,
            bio TEXT,
            image_path TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')
    
    c.execute('''
        CREATE TABLE support_tickets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            subject TEXT,
            message TEXT,
            status TEXT DEFAULT 'open',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')
    
    c.execute('''
        CREATE TABLE subscriptions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE,
            name TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Add admin user
    c.execute('''
        INSERT OR IGNORE INTO users (username, password, role) 
        VALUES (?, ?, 'admin')
    ''', (ADMIN_USERNAME, ADMIN_PASSWORD))
    
    # Add sample products
    sample_products = [
        ('Laptop Pro X', 'High-performance laptop', 1299.99, 50),
        ('Smartphone Y', 'Latest smartphone model', 799.99, 100),
        ('Wireless Earbuds', 'Premium wireless earbuds', 199.99, 75),
        ('Smartwatch Z', 'Advanced fitness tracking', 299.99, 30),
        ('Tablet Ultra', '10-inch tablet with stylus', 599.99, 40)
    ]
    
    c.executemany('''
        INSERT INTO products (name, description, price, stock)
        VALUES (?, ?, ?, ?)
    ''', sample_products)
    
    db.commit()
    db.close()

# Initialize database on startup
if not os.path.exists(DATABASE):  # Only initialize if DB doesn't exist
    init_db()
    print("Database created and initialized.")
else:
    # Ensure foreign keys are enabled on existing database
    db = sqlite3.connect(DATABASE)
    db.execute("PRAGMA foreign_keys = ON")
    db.close()
    print("Using existing database.")

# Add thread-safe transaction decorator
def transaction(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        db = get_db()
        try:
            result = f(*args, **kwargs)
            db.commit()
            return result
        except Exception as e:
            db.rollback()
            flash(f"Transaction failed: {str(e)}")
            return redirect(url_for('cart'))
    return decorated_function

# -----------------------
# Helper Functions
# -----------------------
def sanitize_xss(text):
    return re.sub(r'(?i)<\s*script[^>]*>.*?<\s*/\s*script\s*>', '', text)

def partial_filter(input_str):
    return input_str.replace("'", "")

def advanced_filter(cmd):
    for op in [";", "&&", "||", "|"]:
        cmd = cmd.replace(op, "")
    return cmd

def log_activity(user_id, activity_type, details=None):
    db = get_db()
    try:
        if details is None:
            details = activity_type
            activity_type = "general"
            
        db.execute("""
            INSERT INTO activity_log 
            (user_id, activity, timestamp) 
            VALUES (?, ?, CURRENT_TIMESTAMP)
        """, (user_id, f"{activity_type}: {details}"))
        db.commit()
    except Exception as e:
        print(f"Logging error: {e}")
        db.rollback()

def validate_filename(filename):
    return bool(re.match(r'^[a-zA-Z0-9_.-]+$', filename))

# Add stock validation before checkout
def validate_stock(cart_items):
    db = get_db()
    for pid, qty in cart_items.items():
        product = db.execute("SELECT stock FROM products WHERE id = ?", 
                           (pid,)).fetchone()
        if not product or product['stock'] < int(qty):
            return False
    return True

def generate_invoice(order, output_path):
    """Generate PDF invoice"""
    pdf = fpdf.FPDF()
    pdf.add_page()
    pdf.set_font('Arial', 'B', 16)
    
    # Header
    pdf.cell(0, 10, 'INVOICE', 0, 1, 'C')
    pdf.line(10, 30, 200, 30)
    
    # Order details
    pdf.set_font('Arial', '', 12)
    pdf.cell(0, 10, f"Order ID: {order['id']}", 0, 1)
    pdf.cell(0, 10, f"Date: {datetime.now().strftime('%Y-%m-%d')}", 0, 1)
    pdf.cell(0, 10, f"Customer: {order['username']}", 0, 1)
    
    # Shipping address
    pdf.cell(0, 10, 'Shipping Address:', 0, 1)
    pdf.cell(0, 10, f"{order['street']}", 0, 1)
    pdf.cell(0, 10, f"{order['city']}, {order['country']}", 0, 1)
    
    # Order total
    pdf.set_font('Arial', 'B', 12)
    pdf.cell(0, 10, f"Total Amount: ${order['amount']}", 0, 1)
    
    pdf.output(output_path)

def allowed_file(filename):
    # VULNERABLE: Basic extension check that can be bypassed with double extension
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg', 'gif'}

def sanitize_sql(value):
    """Only strip semicolons to allow SQLite-specific injection"""
    svalue=value.replace("-", "");  # Escape comment for SQL
    svalue=svalue.replace("'", "") ; # Escape quotes for SQL
    svalue=svalue.replace("#", "") ; # Escape comment for SQL
    return svalue  # Allow most SQL syntax for easier SQLite injection

def better_xss_filter(text):
    """Improved but still bypasable XSS filter"""
    if not text:
        return text
        
    # Remove potentially dangerous tags
    dangerous_tags = ['<script>', 'onclick', 'onload','<svg>','onerror' ]
    text_lower = text.lower()
    
    for tag in dangerous_tags:
        # Handle both <script> and variations like < script >
        #pattern = f"<\\s*{tag}.*?>.*?<\\s*/\\s*{tag}\\s*>"
        #pattern = f"<{tag}>.*?</{tag}>"

        text = text.replace(tag,"")
        
        # Remove event handlers
        if tag.startswith('on'):
            text = re.sub(f"{tag}\\s*=", "", text, flags=re.IGNORECASE)
    print(f"Filtered text: {text}");
    return text

# -----------------------
# Templates via DictLoader
# -----------------------
templates_dict = {
    "base.html": """
<!DOCTYPE html>
<html>
  <head>
    <title>E-Shop</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.7.2/font/bootstrap-icons.css" rel="stylesheet">
  </head>
  <body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
      <div class="container">
        <a class="navbar-brand" href="{{ url_for('home') }}">E-Shop</a>
        <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
          <span class="navbar-toggler-icon"></span>
        </button>
        <div class="collapse navbar-collapse" id="navbarNav">
          <ul class="navbar-nav me-auto">
            <li class="nav-item"><a class="nav-link" href="{{ url_for('products') }}">Products</a></li>
            <li class="nav-item"><a class="nav-link" href="{{ url_for('help_page') }}">Help</a></li>
            {% if session.get('user') %}
              <li class="nav-item"><a class="nav-link" href="{{ url_for('cart') }}">Cart</a></li>
              <li class="nav-item"><a class="nav-link" href="{{ url_for('wishlist') }}">Wishlist</a></li>
              <li class="nav-item"><a class="nav-link" href="{{ url_for('orders') }}">Orders</a></li>
              <li class="nav-item"><a class="nav-link" href="{{ url_for('addresses') }}">Addresses</a></li>
              {% if session.get('user', {}).get('role') == 'admin' %}
                <li class="nav-item"><a class="nav-link" href="{{ url_for('admin_dashboard') }}">Admin Panel</a></li>
              {% endif %}
            {% endif %}
          </ul>
          <ul class="navbar-nav">
            {% if session.get('user') %}
              <li class="nav-item"><a class="nav-link" href="{{ url_for('profile') }}">Profile</a></li>
              <li class="nav-item"><a class="nav-link" href="{{ url_for('logout') }}">Logout</a></li>
            {% else %}
              <li class="nav-item"><a class="nav-link" href="{{ url_for('login_route') }}">Login</a></li>
              <li class="nav-item"><a class="nav-link" href="{{ url_for('register_route') }}">Register</a></li>
            {% endif %}
          </ul>
        </div>
      </div>
    </nav>
    <div class="container py-4">
      {% with messages = get_flashed_messages() %}
        {% if messages %}
          {% for message in messages %}
            <div class="alert alert-warning">{{ message }}</div>
          {% endfor %}
        {% endif %}
      {% endwith %}
      {% block content %}{% endblock %}
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
  </body>
</html>
"""
}
templates_dict["home.html"] = """
{% extends "base.html" %}
{% block content %}
<div class="jumbotron p-5 mb-4 bg-light rounded-3">
    <div class="container-fluid py-5">
        <h1 class="display-5 fw-bold">Welcome to E-Shop</h1>
        <p class="col-md-8 fs-4">Your one-stop destination for premium electronics and gadgets.</p>
        <a href="{{ url_for('products') }}" class="btn btn-primary btn-lg">Shop Now</a>
    </div>
</div>

<div class="row">
    <div class="col-md-4">
        <div class="card">
            <div class="card-body">
                <h5 class="card-title">New Arrivals</h5>
                <p class="card-text">Check out our latest products!</p>
                <a href="{{ url_for('products', sort='name') }}" class="btn btn-outline-primary">View New Items</a>
            </div>
        </div>
    </div>
    <div class="col-md-4">
        <div class="card">
            <div class="card-body">
                <h5 class="card-title">Special Offers</h5>
                <p class="card-text">Great deals on selected items!</p>
                <a href="{{ url_for('products', sort='price') }}" class="btn btn-outline-primary">View Deals</a>
            </div>
        </div>
    </div>
    <div class="col-md-4">
        <div class="card">
            <div class="card-body">
                <h5 class="card-title">Support</h5>
                <p class="card-text">Need help? Contact our support team.</p>
                <a href="{{ url_for('support_tickets') }}" class="btn btn-outline-primary">Get Help</a>
            </div>
        </div>
    </div>
</div>
{% endblock %}
"""
templates_dict["register.html"] = """
{% extends "base.html" %}
{% block content %}
<h2>Create an Account</h2>
<form method="POST" class="col-md-6">
  <div class="mb-3">
    <label class="form-label">Username</label>
    <input class="form-control" type="text" name="username" required>
  </div>
  <div class="mb-3">
    <label class="form-label">Password</label>
    <input class="form-control" type="password" name="password" required>
  </div>
  <div class="mb-3">
    <label class="form-label">Security Question</label>
    <select class="form-select" name="security_question" required>
      <option value="What is your favorite color?">What is your favorite color?</option>
      <option value="What is your pet's name?">What is your pet's name?</option>
      <option value="What is your mother's maiden name?">What is your mother's maiden name?</option>
    </select>
  </div>
  <div class="mb-3">
    <label class="form-label">Security Answer</label>
    <input class="form-control" type="text" name="security_answer" required>
  </div>
  <button class="btn btn-primary" type="submit">Register</button>
</form>
<p class="mt-2">Already have an account? <a href="{{ url_for('login_route') }}">Login here</a>.</p>
{% endblock %}
"""
templates_dict["login.html"] = """
{% extends "base.html" %}
{% block content %}
<h2>Login</h2>
<form method="POST" action="{{ url_for('login_route', return_url=request.args.get('return_url')) }}" class="col-md-6">
  <div class="mb-3">
    <label class="form-label">Username</label>
    <input class="form-control" type="text" name="username" required>
  </div>
  <div class="mb-3">
    <label class="form-label">Password</label>
    <input class="form-control" type="password" name="password" required>
  </div>
  <button class="btn btn-success" type="submit">Login</button>
</form>
<p class="mt-2"><a href="{{ url_for('forgot_password') }}">Forgot Password?</a></p>
{% endblock %}
"""
templates_dict["dashboard.html"] = """
{% extends "base.html" %}
{% block content %}
<div class="container py-4">
    <!-- Welcome Banner -->
    <div class="row mb-4">
        <div class="col-12">
            <div class="card bg-primary text-white shadow-sm">
                <div class="card-body">
                    <h2 class="card-title">Welcome, {{ user.username }}!</h2>
                    <p class="lead mb-0">Account Type: {{ user.role|title }}</p>
                </div>
            </div>
        </div>
    </div>

    <!-- Quick Stats -->
    <div class="row mb-4">
        <div class="col-md-3">
            <div class="card border-left-primary shadow-sm h-100">
                <div class="card-body">
                    <div class="d-flex align-items-center">
                        <div class="flex-grow-1">
                            <h6 class="text-muted mb-1">Active Cart</h6>
                            <h4 class="mb-0">{{ session.get('cart', {})|length }} Items</h4>
                        </div>
                        <div class="ms-2">
                            <i class="bi bi-cart fs-1 text-primary"></i>
                        </div>
                    </div>
                </div>
                <div class="card-footer bg-light border-0">
                    <a href="{{ url_for('cart') }}" class="text-primary text-decoration-none">View Cart <i class="bi bi-arrow-right"></i></a>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="card border-left-success shadow-sm h-100">
                <div class="card-body">
                    <div class="d-flex align-items-center">
                        <div class="flex-grow-1">
                            <h6 class="text-muted mb-1">Wishlist</h6>
                            <h4 class="mb-0">View Items</h4>
                        </div>
                        <div class="ms-2">
                            <i class="bi bi-heart fs-1 text-success"></i>
                        </div>
                    </div>
                </div>
                <div class="card-footer bg-light border-0">
                    <a href="{{ url_for('wishlist') }}" class="text-success text-decoration-none">Manage Wishlist <i class="bi bi-arrow-right"></i></a>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="card border-left-info shadow-sm h-100">
                <div class="card-body">
                    <div class="d-flex align-items-center">
                        <div class="flex-grow-1">
                            <h6 class="text-muted mb-1">Orders</h6>
                            <h4 class="mb-0">Track Orders</h4>
                        </div>
                        <div class="ms-2">
                            <i class="bi bi-box-seam fs-1 text-info"></i>
                        </div>
                    </div>
                </div>
                <div class="card-footer bg-light border-0">
                    <a href="{{ url_for('order_history') }}" class="text-info text-decoration-none">View History <i class="bi bi-arrow-right"></i></a>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="card border-left-warning shadow-sm h-100">
                <div class="card-body">
                    <div class="d-flex align-items-center">
                        <div class="flex-grow-1">
                            <h6 class="text-muted mb-1">Support</h4>
                            <h4 class="mb-0">Get Help</h4>
                        </div>
                        <div class="ms-2">
                            <i class="bi bi-headset fs-1 text-warning"></i>
                        </div>
                    </div>
                </div>
                <div class="card-footer bg-light border-0">
                    <a href="{{ url_for('support_tickets') }}" class="text-warning text-decoration-none">Contact Support <i class="bi bi-arrow-right"></i></a>
                </div>
            </div>
        </div>
    </div>

    <!-- Quick Actions -->
    <div class="row mb-4">
        <div class="col-md-6">
                </div>
                <div class="card-footer bg-light border-0">
                    <a href="{{ url_for('wishlist') }}" class="text-success text-decoration-none">Manage Wishlist <i class="bi bi-arrow-right"></i></a>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="card border-left-info shadow-sm h-100">
                <div class="card-body">
                    <div class="d-flex align-items-center">
                        <div class="flex-grow-1">
                            <h6 class="text-muted mb-1">Orders</h6>
                            <h4 class="mb-0">Track Orders</h4>
                        </div>
                        <div class="ms-2">
                            <i class="bi bi-box-seam fs-1 text-info"></i>
                        </div>
                    </div>
                </div>
                <div class="card-footer bg-light border-0">
                    <a href="{{ url_for('order_history') }}" class="text-info text-decoration-none">View History <i class="bi bi-arrow-right"></i></a>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="card border-left-warning shadow-sm h-100">
                <div class="card-body">
                    <div class="d-flex align-items-center">
                        <div class="flex-grow-1">
                            <h6 class="text-muted mb-1">Support</h4>
                            <h4 class="mb-0">Get Help</h4>
                        </div>
                        <div class="ms-2">
                            <i class="bi bi-headset fs-1 text-warning"></i>
                        </div>
                    </div>
                </div>
                <div class="card-footer bg-light border-0">
                    <a href="{{ url_for('support_tickets') }}" class="text-warning text-decoration-none">Contact Support <i class="bi bi-arrow-right"></i></a>
                </div>
            </div>
        </div>
    </div>

    <!-- Quick Actions -->
    <div class="row mb-4">
        <div class="col-md-6">
            <div class="card shadow-sm">
                <div class="card-header bg-light">
                    <h5 class="card-title mb-0">Quick Actions</h5>
                </div>
                <div class="card-body">
                    <div class="d-grid gap-2">
                        <a href="{{ url_for('products') }}" class="btn btn-outline-primary">
                            <i class="bi bi-shop"></i> Browse Products
                        </a>
                        <a href="{{ url_for('profile') }}" class="btn btn-outline-secondary">
                            <i class="bi bi-person"></i> Update Profile
                        </a>
                        <a href="{{ url_for('addresses') }}" class="btn btn-outline-info">
                            <i class="bi bi-geo-alt"></i> Manage Addresses
                        </a>
                    </div>
                </div>
            </div>
        </div>
        
        {% if user.role == 'admin' %}
        <div class="col-md-6">
            <div class="card shadow-sm border-danger">
                <div class="card-header bg-danger text-white">
                    <h5 class="card-title mb-0">Admin Controls</h5>
                </div>
                <div class="card-body">
                    <div class="d-grid gap-2">
                        <a href="{{ url_for('admin_dashboard') }}" class="btn btn-outline-danger">
                            <i class="bi bi-speedometer2"></i> Admin Dashboard
                        </a>
                        <a href="{{ url_for('admin_products') }}" class="btn btn-outline-danger">
                            <i class="bi bi-box"></i> Manage Products
                        </a>
                        <a href="{{ url_for('admin_tools') }}" class="btn btn-outline-danger">
                            <i class="bi bi-tools"></i> Admin Tools
                        </a>
                    </div>
                </div>
            </div>
        </div>
        {% endif %}
    </div>
</div>

<style>
.border-left-primary {
    border-left: 4px solid #4e73df !important;
}
.border-left-success {
    border-left: 4px solid #1cc88a !important;
}
.border-left-info {
    border-left: 4px solid #36b9cc !important;
}
.border-left-warning {
    border-left: 4px solid #f6c23e !important;
}
.card {
    transition: transform 0.2s;
}
.card:hover {
    transform: translateY(-5px);
}
</style>
{% endblock %}
"""
templates_dict["forgot1.html"] = """
{% extends "base.html" %}
{% block content %}
<h2>Forgot Password - Step 1</h2>
<form method="POST" class="col-md-6">
  <div class="mb-3">
    <label class="form-label">Enter Username</label>
    <input class="form-control" type="text" name="username" required>
  </div>
  <button class="btn btn-primary" type="submit">Next</button>
</form>
{% endblock %}
"""
templates_dict["forgot2.html"] = """
{% extends "base.html" %}
{% block content %}
<h2>Forgot Password - Step 2</h2>
<div class="col-md-6">
    <p>Security verification for user: <strong>{{ reset_username }}</strong></p>
    
    <form method="POST">
        <div class="mb-3">
            <label class="form-label">Security Question:</label>
            <p class="form-control-static">{{ security_question }}</p>
        </div>
        <input type="hidden" name="qid" value="{{ qid }}">
        <div class="mb-3">
            <label class="form-label">Security Answer</label>
            <input class="form-control" type="text" name="security_answer" required>
        </div>
        <button class="btn btn-primary" type="submit">Verify</button>
    </form>
</div>
{% endblock %}
"""
templates_dict["forgot3.html"] = """
{% extends "base.html" %}
{% block content %}
<h2>Forgot Password - Step 3</h2>
<p>Reset password for <strong>{{ session.get('reset_username', 'Unknown') }}</strong></p>
<form method="POST" class="col-md-6">
  <div class="mb-3">
    <label class="form-label">New Password</label>
    <input class="form-control" type="password" name="new_password" required>
  </div>
  <button class="btn btn-primary" type="submit">Reset Password</button>
</form>
{% endblock %}
"""
templates_dict["addresses.html"] = """
{% extends "base.html" %}
{% block content %}
<h2>My Addresses</h2>
{% if addresses %}
  <ul class="list-group mb-3">
    {% for addr in addresses %}
      <li class="list-group-item">{{ addr.street }}, {{ addr.city }}, {{ addr.country }}</li>
    {% endfor %}
  </ul>
{% else %}
  <p>No addresses saved.</p>
{% endif %}
<hr>
<h4>Add New Address</h4>
<form method="POST" class="col-md-6">
  <div class="mb-3">
    <label class="form-label">Street</label>
    <input class="form-control" type="text" name="street" required>
  </div>
  <div class="mb-3">
    <label class="form-label">City</label>
    <input class="form-control" type="text" name="city" required>
  </div>
  <div class="mb-3">
    <label class="form-label">Country</label>
    <input class="form-control" type="text" name="country" required>
  </div>
  <button class="btn btn-primary" type="submit">Save Address</button>
</form>
{% endblock %}
"""
templates_dict["products.html"] = """
{% extends "base.html" %}
{% block content %}
<h2>Products</h2>
<form method="GET" class="row g-3 mb-3">
  <div class="col-auto">
    <input class="form-control" type="text" name="search" value="{{ search|replace("'", "") }}" placeholder="Search products">
  </div>
  <div class="col-auto">
    <select class="form-select" name="sort">
      <option value="">Sort By</option>
      <option value="name" {% if sort=='name' %}selected{% endif %}>Name</option>
      <option value="price" {% if sort=='price' %}selected{% endif %}>Price</option>
    </select>
  </div>
  <div class="col-auto">
    <button class="btn btn-outline-primary" type="submit">Search</button>
  </div>
</form>
{% if search %}
<p>Showing results for "<strong>{{ search|safe }}</strong>"</p>
{% endif %}
<div class="row">
  {% for p in products %}
    <div class="col-md-4 mb-3">
      <div class="card h-100">
        <div class="card-body">
          <h5 class="card-title">{{ p.name }}</h5>
          <p class="card-text">Price: ${{ p.price }}<br>Stock: {{ p.stock }}</p>
          <a href="{{ url_for('product_detail', pid=p.id) }}" class="btn btn-primary">View Details</a>
        </div>
      </div>
    </div>
  {% endfor %}
</div>
<nav aria-label="Page navigation">
  <ul class="pagination">
    {% if page > 1 %}
      <li class="page-item"><a class="page-link" href="{{ url_for('products', search=search, sort=sort, page=page-1) }}">Previous</a></li>
    {% endif %}
    <li class="page-item active"><span class="page-link">{{ page }}</span></li>
    {% if has_more %}
      <li class="page-item"><a class="page-link" href="{{ url_for('products', search=search, sort=sort, page=page+1) }}">Next</a></li>
    {% endif %}
  </ul>
</nav>
{% endblock %}
"""
templates_dict["product_detail.html"] = """
{% extends "base.html" %}
{% block content %}
<h2>{{ product.name }}</h2>
{% if avg_rating %}
  <p>Average Rating: {{ avg_rating|round(1) }} / 5</p>
{% endif %}
<p>{{ product.description }}</p>
<p>Price: ${{ product.price }} | Stock: {{ product.stock }}</p>

<div class="row mb-4">
    <div class="col-auto">
        {% if product.stock > 0 %}
        <form method="POST" action="{{ url_for('add_to_cart') }}" class="d-inline">
            <input type="hidden" name="product_id" value="{{ product.id }}">
            <div class="input-group">
                <input class="form-control" type="number" name="quantity" value="1" min="1">
                <button class="btn btn-warning" type="submit">Add to Cart</button>
            </div>
        </form>
        {% else %}
        <p class="text-danger">Out of Stock.</p>
        {% endif %}
    </div>
    <div class="col-auto">
        <form method="POST" action="{{ url_for('add_to_wishlist') }}" class="d-inline">
            <input type="hidden" name="product_id" value="{{ product.id }}">
            <button class="btn btn-outline-primary" type="submit">Add to Wishlist</button>
        </form>
    </div>
</div>

<hr>
<h4>Customer Reviews</h4>
<ul class="list-group mb-3">
  {% for r in reviews %}
    <li class="list-group-item">
      <strong>Rating:</strong> {{ r.rating }} / 5<br>
      {{ r.review|safe }}
    </li>
  {% endfor %}
</ul>
<form method="POST">
  <div class="mb-3">
    <label class="form-label">Leave a Review</label>
    <textarea class="form-control" name="review" rows="3"></textarea>
  </div>
  <div class="mb-3">
    <label class="form-label">Rating (1-5)</label>
    <select class="form-select" name="rating" required>
      <option value="1">1</option>
      <option value="2">2</option>
      <option value="3">3</option>
      <option value="4">4</option>
      <option value="5">5</option>
    </select>
  </div>
  <button class="btn btn-success" type="submit">Submit Review</button>
</form>
<hr>
{% endblock %}
"""
templates_dict["cart.html"] = """
{% extends "base.html" %}
{% block content %}
<h2>Your Cart</h2>
{% if cart_items %}
  <ul class="list-group mb-3">
    {% for item in cart_items %}
      <li class="list-group-item d-flex justify-content-between align-items-center">
        {{ item.name }} (ID: {{ item.id }}) - ${{ item.price }} x {{ item.quantity }} = ${{ item.total }}
        <form method="POST" action="{{ url_for('remove_cart_item') }}">
          <input type="hidden" name="pid" value="{{ item.id }}">
          <button class="btn btn-danger btn-sm" onclick="return confirm('Remove this item?');" type="submit">Remove</button>
        </form>
      </li>
    {% endfor %}
  </ul>
  <h5>Calculated Total: ${{ total }}</h5>
  <a class="btn btn-success" href="{{ url_for('checkout_page') }}">Proceed to Checkout</a>
{% else %}
  <p>Your cart is empty.</p>
{% endif %}
{% endblock %}
"""
templates_dict["checkout.html"] = """
{% extends "base.html" %}
{% block content %}
<h2>Checkout</h2>
<p>Calculated Total: ${{ total }}</p>
<form method="POST" action="{{ url_for('checkout_confirm') }}" class="col-md-6">
  {% if addresses %}
    <div class="mb-3">
      <label class="form-label">Shipping Address</label>
      <select class="form-select" name="address_id" required>
        {% for address in addresses %}
          <option value="{{ address.id }}">{{ address.street }}, {{ address.city }}, {{ address.country }}</option>
        {% endfor %}
      </select>
    </div>
  {% else %}
    <div class="alert alert-warning">No addresses found. Please add an address in your dashboard.</div>
  {% endif %}
  <input type="hidden" name="computed_total" value="{{ total }}">
  <button class="btn btn-primary" type="submit">Continue to Confirm</button>
</form>
{% endblock %}
"""
templates_dict["confirm.html"] = """
{% extends "base.html" %}
{% block content %}
<h2>Confirm Your Order</h2>
<p>Shipping Address: {{ address.street }}, {{ address.city }}, {{ address.country }}</p>
<p>Calculated Total: ${{ total }}</p>
<p>Please review and confirm your order.</p>

<form method="POST" action="{{ url_for('checkout_complete') }}" id="confirmForm">
  <input type="hidden" name="address_id" value="{{ address.id }}">
  <input type="hidden" name="final_amount" value="{{ total }}">
  <button class="btn btn-success" type="submit" onclick="showLoading()">Confirm Order</button>
</form>

<div id="loadingIndicator" style="display:none;" class="text-center mt-3">
  <div class="spinner-border text-primary" role="status">
    <span class="visually-hidden">Processing...</span>
  </div>
  <p class="mt-2">Processing your order...</p>
</div>

<script>
function showLoading() {
    document.getElementById('confirmForm').style.display = 'none';
    document.getElementById('loadingIndicator').style.display = 'block';
}
</script>
{% endblock %}
"""
templates_dict["payment_success.html"] = """
{% extends "base.html" %}
{% block content %}
<div class="container py-5">
    <div class="card">
        <div class="card-body">
            <h2 class="card-title text-success">
                <i class="bi bi-check-circle"></i> Payment Successful
            </h2>
            <hr>
            <div class="row">
                <div class="col-md-6">
                    <h4>Order Details</h4>
                    <p><strong>Order ID:</strong> {{ order.id }}</p>
                    <p><strong>Status:</strong> {{ order.status }}</p>
                    <p><strong>Total Amount:</strong> ${{ order.amount }}</p>
                </div>
                <div class="col-md-6">
                    <h4>Shipping Address</h4>
                    <p>{{ order.street }}<br>
                    {{ order.city }}<br>
                    {{ order.country }}</p>
                </div>
            </div>
            <div class="text-center mt-4">
                <a href="{{ url_for('invoice_download', order_id=order_id) }}" 
                   class="btn btn-primary">
                    <i class="bi bi-download"></i> Download Invoice
                </a>
                <a href="{{ url_for('order_history') }}" 
                   class="btn btn-secondary">
                    <i class="bi bi-clock-history"></i> View Order History
                </a>
            </div>
        </div>
    </div>
</div>
{% endblock %}
"""
templates_dict["export.html"] = """
{% extends "base.html" %}
{% block content %}
<h2>Export Data</h2>
<form method="GET" class="col-md-6">
  <div class="mb-3">
    <label class="form-label">Export Type</label>
    <select class="form-select" name="type" required>
      <option value="invoice">Invoice (by Order ID)</option>
      <option value="products">Products (CSV)</option>
    </select>
  </div>
  <div class="mb-3">
    <label class="form-label">ID or Filename</label>
    <input class="form-control" type="text" name="id" placeholder="e.g., 1 for invoice">
  </div>
  <button class="btn btn-primary" type="submit">Download</button>
</form>
{% if content %}
<hr>
<h4>Downloaded Content</h4>
<pre>{{ content }}</pre>
{% endif %}
{% endblock %}
"""
templates_dict["activity.html"] = """
{% extends "base.html" %}
{% block content %}
<h2>Activity Log</h2>
<table class="table table-striped">
  <thead>
    <tr>
      <th>ID</th>
      <th>User ID</th>
      <th>Activity</th>
      <th>Timestamp</th>
    </tr>
  </thead>
  <tbody>
    {% for log in logs %}
    <tr>
      <td>{{ log.id }}</td>
      <td>{{ log.user_id }}</td>
      <td>{{ log.activity }}</td>
      <td>{{ log.timestamp }}</td>
    </tr>
    {% endfor %}
  </tbody>
</table>
{% endblock %}
"""
templates_dict["profile.html"] = """
{% extends "base.html" %}
{% block content %}
<div class="container">
  <div class="row">
    <div class="col-md-4 text-center mb-4">
      {% if profile.image_path %}
        <img src="{{ url_for('uploaded_file', filename=profile.image_path) }}" 
             alt="Profile Image" 
             class="img-thumbnail rounded-circle"
             style="max-width: 200px; height: 200px; object-fit: cover;">
      {% else %}
        <img src="https://via.placeholder.com/200" 
             alt="No Profile Image"
             class="img-thumbnail rounded-circle">
      {% endif %}
    </div>
    <div class="col-md-8">
      <h2>User Profile</h2>
      <form method="POST" enctype="multipart/form-data">
        <div class="mb-3">
          <label class="form-label">Profile Image</label>
          <input class="form-control" type="file" name="image" accept="image/*">
        </div>
        <div class="mb-3">
          <label class="form-label">Display Name</label>
          <input class="form-control" type="text" name="display_name" value="{{ profile.display_name }}">
        </div>
        <div class="mb-3">
          <label class="form-label">Email</label>
          <input class="form-control" type="email" name="email" value="{{ profile.email }}">
        </div>
        <div class="mb-3">
          <label class="form-label">Bio</label>
          <textarea class="form-control" name="bio" rows="3">{{ profile.bio }}</textarea>
        </div>
        <button class="btn btn-primary" type="submit">Update Profile</button>
      </form>
    </div>
  </div>
</div>
{% endblock %}
"""
templates_dict["wishlist.html"] = """
{% extends "base.html" %}
{% block content %}
<h2>Your Wishlist</h2>
{% if items %}
  <div class="row">
    {% for item in items %}
      <div class="col-md-4 mb-3">
        <div class="card h-100">
          <div class="card-body">
            <h5 class="card-title">{{ item.name }}</h5>
            <p class="card-text">
              Price: ${{ item.price }}<br>
              Stock: {{ item.stock }}
            </p>
            <div class="btn-group">
              <a href="{{ url_for('product_detail', pid=item.id) }}" class="btn btn-primary">View Details</a>
              <form method="POST" action="{{ url_for('wishlist_remove') }}" class="d-inline">
                <input type="hidden" name="item_id" value="{{ item.id }}">
                <button class="btn btn-danger" type="submit">Remove</button>
              </form>
            </div>
          </div>
        </div>
      </div>
    {% endfor %}
  </div>
{% else %}
  <p>Your wishlist is empty.</p>
  <a href="{{ url_for('products') }}" class="btn btn-primary">Browse Products</a>
{% endif %}
{% endblock %}
"""
templates_dict["file_viewer.html"] = """
{% extends "base.html" %}
{% block content %}
<h2>Log Viewer</h2>
{% if log_files %}
  <ul class="list-group mb-3">
    {% for file in log_files %}
      <li class="list-group-item"><a href="{{ url_for('file_view', filename=file) }}">{{ file }}</a></li>
    {% endfor %}
  </ul>
{% endif %}
<form method="GET" class="mb-3">
  <div class="mb-3">
    <label class="form-label">Log Filename</label>
    <input class="form-control" type="text" name="filename" placeholder="example.log">
  </div>
  <button class="btn btn-info" type="submit">View Log</button>
</form>
{% if file_content %}
<hr>
<h4>Log File Content</h4>
<pre>{{ file_content }}</pre>
{% endif %}
{% endblock %}
"""
templates_dict["support.html"] = """
{% extends "base.html" %}
{% block content %}
<h2>Support Tickets</h2>
<form method="POST" class="col-md-6 mb-3">
  <div class="mb-3">
    <label class="form-label">Subject</label>
    <input class="form-control" type="text" name="subject" required>
  </div>
  <div class="mb-3">
    <label class="form-label">Message</label>
    <textarea class="form-control" name="message" rows="4" required></textarea>
  </div>
  <button class="btn btn-primary" type="submit">Submit Ticket</button>
</form>
{% if tickets %}
  <ul class="list-group">
    {% for t in tickets %}
      <li class="list-group-item">
        <strong>{{ t.subject }}</strong> - Status: {{ t.status }}<br>
        {{ t.message }}
      </li>
    {% endfor %}
  </ul>
{% else %}
  <p>No support tickets found.</p>
{% endif %}
{% endblock %}
"""
templates_dict["subscribe.html"] = """
{% extends "base.html" %}
{% block content %}
<h2>Newsletter Subscription</h2>
<form method="POST" class="col-md-6">
  <div class="mb-3">
    <label class="form-label">Email Address</label>
    <input class="form-control" type="email" name="email" required>
  </div>
  <div class="mb-3">
    <label class="form-label">Name (Optional)</label>
    <input class="form-control" type="text" name="name">
  </div>
  <button class="btn btn-primary" type="submit">Subscribe</button>
</form>
{% endblock %}
"""
templates_dict["eval.html"] = """
{% extends "base.html" %}
{% block content %}
<h2>Admin Tools - System Maintenance</h2>
<div class="row">
    <div class="col-md-4">
        <h4>System Health</h4>
        <p><strong>System:</strong> {{ uptime }}</p>
        <p><strong>Disk Usage:</strong><br><pre>{{ disk_usage }}</pre></p>
    </div>
    <div class="col-md-4">
        <h4>Run Maintenance Task</h4>
        <form method="POST" action="{{ url_for('admin_tools', mode='exec') }}">
            <div class="mb-3">
                <label class="form-label">Select Task</label>
                <select class="form-control" name="task_type" required>
                    <option value="backup">Database Backup</option>
                    <option value="cleanup">Cleanup Temp Files</option>
                    <option value="optimize">Optimize Database</option>
                </select>
            </div>
            <div class="mb-3">
                <label class="form-label">Parameters (Optional)</label>
                <input class="form-control" type="text" name="params" 
                       placeholder="e.g., backup.db or temp/"
                       pattern="[A-Za-z0-9_.-/]*">
            </div>
            <input type="hidden" name="cmd_key" value="{{ cmd_key }}">
            <button class="btn btn-warning" type="submit">Execute Task</button>
        </form>
    </div>
</div>
{% if result %}
<hr>
<h4>Task Output</h4>
<pre>{{ result }}</pre>
{% endif %}
{% endblock %}
"""
templates_dict["orders.html"] = """
{% extends "base.html" %}
{% block content %}
<h2>Orders</h2>
{% if orders %}
  <table class="table">
    <thead>
      <tr>
        <th>Order ID</th>
        {% if session['user']['role'] == 'admin' %}
        <th>Customer</th>
        {% endif %}
        <th>Products</th>
        <th>Amount</th>
        <th>Status</th>
        <th>Shipping Address</th>
        <th>Actions</th>
      </tr>
    </thead>
    <tbody>
      {% for order in orders %}
      <tr>
        <td>
          <a href="{{ url_for('order_details', order_id=order.id) }}">{{ order.id }}</a>
        </td>
        {% if session['user']['role'] == 'admin' %}
        <td>{{ order.username }}</td>
        {% endif %}
        <td>{{ order.product_ids }}</td>
        <td>${{ order.amount }}</td>
        <td>{{ order.status }}</td>
        <td>{{ order.street }}, {{ order.city }}</td>
        <td>
          {% if session['user']['role'] == 'admin' %}
          <form method="POST" action="{{ url_for('admin_update_order') }}" class="d-inline">
            <input type="hidden" name="order_id" value="{{ order.id }}">
            <select name="status" class="form-select form-select-sm d-inline-block w-auto">
              <option value="Processing" {% if order.status == 'Processing' %}selected{% endif %}>Processing</option>
              <option value="Shipped" {% if order.status == 'Shipped' %}selected{% endif %}>Shipped</option>
              <option value="Delivered" {% if order.status == 'Delivered' %}selected{% endif %}>Delivered</option>
              <option value="Cancelled" {% if order.status == 'Cancelled' %}selected{% endif %}>Cancelled</option>
            </select>
            <button type="submit" class="btn btn-primary btn-sm">Update</button>
          </form>
          {% endif %}
          <a href="{{ url_for('order_details', order_id=order.id) }}" class="btn btn-info btn-sm">View Details</a>
        </td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
{% else %}
  <p>No orders found.</p>
{% endif %}
{% endblock %}
"""
templates_dict["help.html"] = """
{% extends "base.html" %}
{% block content %}
<div class="row">
    <div class="col-md-12 mb-4">
        <h2>Help & Support</h2>
        <div class="card">
            <div class="card-body">
                <div class="row">
                    <div class="col-md-12">
                        <h4>Select Help Topic</h4>
                        <form method="GET" class="mb-3">
                            <div class="mb-3">
                                <label class="form-label">Help Topic</label>
                                <select class="form-select" name="template" onchange="this.form.submit()">
                                    {% for t in templates %}
                                    <option value="{{ t }}">{{ t|title }}</option>
                                    {% endfor %}
                                </select>
                            </div>
                        </form>
                    </div>
                </div>
                <div class="help-content">
                    {{ content|safe }}
                </div>
            </div>
        </div>
    </div>
</div>
{% endblock %}
"""
templates_dict["order_history.html"] = """
{% extends "base.html" %}
{% block content %}
<h2>Order History</h2>
{% if orders %}
  <table class="table">
    <thead>
      <tr>
        <th>Order ID</th>
        <th>Products</th>
        <th>Amount</th>
        <th>Status</th>
        <th>Shipping Address</th>
      </tr>
    </thead>
    <tbody>
      {% for order in orders %}
      <tr>
        <td>{{ order.id }}</td>
        <td>{{ order.product_ids }}</td>
        <td>${{ order.amount }}</td>
        <td>{{ order.status }}</td>
        <td>{{ order.street }}, {{ order.city }}</td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
{% else %}
  <p>No order history found.</p>
{% endif %}
{% endblock %}
"""
templates_dict["admin_dashboard.html"] = """
{% extends "base.html" %}
{% block content %}
<h2>Admin Dashboard</h2>
<div class="row">
    <div class="col-md-4">
        <div class="card">
            <div class="card-body">
                <h5 class="card-title">Total Orders</h5>
                <p class="card-text display-4">{{ total_orders }}</p>
            </div>
        </div>
    </div>
    <div class="col-md-4">
        <div class="card">
            <div class="card-body">
                <h5 class="card-title">Total Users</h5>
                <p class="card-text display-4">{{ total_users }}</p>
            </div>
        </div>
    </div>
    <div class="col-md-4">
        <div class="card">
            <div class="card-body">
                <h5 class="card-title">Best Selling Product</h5>
                <p class="card-text">{{ best_selling }}</p>
            </div>
        </div>
    </div>
</div>
<div class="mt-4">
    <a href="{{ url_for('admin_products') }}" class="btn btn-primary">Manage Products</a>
    <a href="{{ url_for('import_products_route') }}" class="btn btn-success">Import Products</a>
    <a href="{{ url_for('admin_tools') }}" class="btn btn-warning">Admin Tools</a>
    <a href="{{ url_for('activity') }}" class="btn btn-info">View Activity Log</a>
</div>
{% endblock %}
"""
templates_dict["admin_products.html"] = """
{% extends "base.html" %}
{% block content %}
<h2>Product Management</h2>
<div class="row mb-4">
    <div class="col-md-6">
        <h4>Add New Product</h4>
        <form method="POST">
            <input type="hidden" name="action" value="add">
            <div class="mb-3">
                <label class="form-label">Name</label>
                <input class="form-control" type="text" name="name" required>
            </div>
            <div class="mb-3">
                <label class="form-label">Description</label>
                <textarea class="form-control" name="description" required></textarea>
            </div>
            <div class="mb-3">
                <label class="form-label">Price</label>
                <input class="form-control" type="number" step="0.01" name="price" required>
            </div>
            <div class="mb-3">
                <label class="form-label">Stock</label>
                <input class="form-control" type="number" name="stock" required>
            </div>
            <button class="btn btn-success" type="submit">Add Product</button>
        </form>
    </div>
</div>

<h4>Current Products</h4>
<table class="table">
    <thead>
        <tr>
            <th>ID</th>
            <th>Name</th>
            <th>Description</th>
            <th>Price</th>
            <th>Stock</th>
            <th>Actions</th>
        </tr>
    </thead>
    <tbody>
        {% for p in products %}
        <tr>
            <td>{{ p.id }}</td>
            <td>{{ p.name }}</td>
            <td>{{ p.description }}</td>
            <td>${{ p.price }}</td>
            <td>{{ p.stock }}</td>
            <td>
                <form method="POST" class="d-inline">
                    <input type="hidden" name="action" value="delete">
                    <input type="hidden" name="pid" value="{{ p.id }}">
                    <button class="btn btn-danger btn-sm" onclick="return confirm('Delete this product?');">Delete</button>
                </form>
            </td>
        </tr>
        {% endfor %}
    </tbody>
</table>
{% endblock %}
"""
templates_dict["import_xml.html"] = """
{% extends "base.html" %}
{% block content %}
<h2>Import Products from XML</h2>
<form method="POST" enctype="multipart/form-data" class="col-md-6">
    <div class="mb-3">
        <label class="form-label">XML File</label>
        <input class="form-control" type="file" name="xml_file" accept=".xml" required>
    </div>
    <button class="btn btn-primary" type="submit">Import Products</button>
</form>
{% endblock %}
"""
templates_dict["help_content"] = {
    "default": """
        <div class="help-section">
            <h3>Getting Started</h3>
            <ul>
                <li>Browse our products in the Products section</li>
                <li>Add items to your cart</li>
                <li>Proceed to checkout when ready</li>
            </ul>
            
            <h3>Common Questions</h3>
            <div class="accordion">
                <div class="accordion-item">
                    <h4>How do I track my order?</h4>
                    <p>You can view your orders in the Order History section of your dashboard.</p>
                </div>
                <div class="accordion-item">
                    <h4>What payment methods do you accept?</h4>
                    <p>We accept all major credit cards and PayPal.</p>
                </div>
            </div>
        </div>
    """,
    "shipping": """
        <div class="help-section">
            <h3>Shipping Information</h3>
            <ul>
                <li>Standard Shipping: 5-7 business days</li>
                <li>Express Shipping: 2-3 business days</li>
                <li>International Shipping: 7-14 business days</li>
            </ul>
        </div>
    """,
    "returns": """
        <div class="help-section">
            <h3>Returns Policy</h3>
            <p>Items can be returned within 30 days of delivery.</p>
            <ol>
                <li>Contact customer support</li>
                <li>Get a return authorization</li>
                <li>Ship the item back</li>
                <li>Receive your refund</li>
            </ol>
        </div>
    """,
    "contact": """
        <div class="help-section">
            <h3>Contact Support</h3>
            <p>Our support team is available 24/7:</p>
            <ul>
                <li>Email: support@eshop.com</li>
                <li>Phone: 1-800-123-4567</li>
                <li>Chat: Available on website</li>
            </ul>
        </div>
    """
}
templates_dict["maintenance.html"] = """
{% extends "base.html" %}
{% block content %}
<h2>System Maintenance</h2>
<div class="row mb-4">
    <div class="col-md-3">
        <div class="card">
            <div class="card-body">
                <h5 class="card-title">Disk Usage</h5>
                <p class="card-text">{{ stats.disk_usage }}</p>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card">
            <div class="card-body">
                <h5 class="card-title">Memory Usage</h5>
                <p class="card-text">{{ stats.memory_usage }}</p>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card">
            <div class="card-body">
                <h5 class="card-title">Active Sessions</h5>
                <p class="card-text">{{ stats.user_sessions }}</p>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card">
            <div class="card-body">
                <h5 class="card-title">Pending Orders</h5>
                <p class="card-text">{{ stats.pending_orders }}</p>
            </div>
        </div>
    </div>
</div>
<div class="row">
    <div class="col-md-6">
        <div class="card">
            <div class="card-header">
                <h5 class="card-title">System Cleanup</h5>
            </div>
            <div class="card-body">
                <form method="POST">
                    <input type="hidden" name="action" value="cleanup">
                    <div class="mb-3">
                        <label class="form-label">Cleanup Target</label>
                        <select class="form-select" name="target">
                            <option value="temp">Temporary Files</option>
                            <option value="logs">Old Logs</option>
                            <option value="cache">Cache Files</option>
                            <option value="sessions">Expired Sessions</option>
                        </select>
                    </div>
                    <button type="submit" class="btn btn-warning">Run Cleanup</button>
                </form>
            </div>
        </div>
    </div>
    <div class="col-md-6">
        <div class="card">
            <div class="card-header">
                <h5 class="card-title">Database Optimization</h5>
            </div>
            <div class="card-body">
                <form method="POST">
                    <input type="hidden" name="action" value="optimize">
                    <div class="mb-3">
                        <label class="form-label">Database Name</label>
                        <input type="text" class="form-control" name="db_name" value="ecommerce">
                    </div>
                    <button type="submit" class="btn btn-primary">Optimize Database</button>
                </form>
            </div>
        </div>
    </div>
</div>
{% endblock %}
"""
templates_dict["nav.html"] = """
<nav class="navbar navbar-expand-lg navbar-dark bg-primary">
    <div class="container">
        <a class="navbar-brand" href="{{ url_for('home') }}">E-Shop</a>
        <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
            <span class="navbar-toggler-icon"></span>
        </button>
        <div class="collapse navbar-collapse" id="navbarNav">
            <ul class="navbar-nav me-auto">
                <li class="nav-item"><a class="nav-link" href="{{ url_for('products') }}">Products</a></li>
                {% if session.get('user') %}
                    <li class="nav-item"><a class="nav-link" href="{{ url_for('cart') }}">Cart</a></li>
                    <li class="nav-item"><a class="nav-link" href="{{ url_for('orders') }}">Orders</a></li>
                    <li class="nav-item"><a class="nav-link" href="{{ url_for('profile') }}">Profile</a></li>
                    {% if session.get('user', {}).get('role') == 'admin' %}
                        <li class="nav-item"><a class="nav-link" href="{{ url_for('admin_dashboard') }}">Admin</a></li>
                    {% endif %}
                {% endif %}
            </ul>
            <ul class="navbar-nav">
                {% if session.get('user') %}
                    <li class="nav-item"><a class="nav-link" href="{{ url_for('logout') }}">Logout</a></li>
                {% else %}
                    <li class="nav-item"><a class="nav-link" href="{{ url_for('login_route') }}">Login</a></li>
                    <li class="nav-item"><a class="nav-link" href="{{ url_for('register_route') }}">Register</a></li>
                {% endif %}
            </ul>
        </div>
    </div>
</nav>
"""
templates_dict["import_xml.html"] = """
{% extends "base.html" %}
{% block content %}
<h2>Import Products via XML</h2>
<div class="row">
    <div class="col-md-6">
        <div class="card">
            <div class="card-header">
                <h2>Import Products via XML</h2>
            </div>
            <div class="card-body">
                <form method="POST" enctype="multipart/form-data">
                    <div class="mb-3">
                        <label class="form-label">Upload XML File</label>
                        <input class="form-control" type="file" name="xml_file" accept=".xml" required>
                    </div>
                    <button class="btn btn-primary" type="submit">Import Products</button>
                </form>
            </div>
        </div>
    </div>
    <div class="col-md-6">
        <div class="card">
            <div class="card-header">
                <h3>Sample XML Format</h3>
            </div>
            <div class="card-body">
                <pre class="bg-light p-3">
&lt;?xml version="1.0" encoding="UTF-8"?&gt;
&lt;products&gt;
    &lt;product&gt;
        &lt;name&gt;Product Name&lt;/name&gt;
        &lt;description&gt;Product Description&lt;/description&gt;
        &lt;price&gt;99.99&lt;/price&gt;
        &lt;stock&gt;100&lt;/stock&gt;
    &lt;/product&gt;
&lt;/products&gt;</pre>
            </div>
        </div>
    </div>
</div>
{% endblock %}
"""
templates_dict["order_details.html"] = """{% extends "base.html" %}
{% block content %}
<div class="container py-4">
    <h2>Order Details</h2>
    <div class="card mb-4">
        <div class="card-header">
            <h5 class="card-title mb-0">Order #{{ order.id }}</h5>
        </div>
        <div class="card-body">
            <div class="row">
                <div class="col-md-6">
                    <h6>Customer Information</h6>
                    <p>
                        <strong>Customer:</strong> {{ order.username }}<br>
                        <strong>Order Date:</strong> {{ order.created_at }}<br>
                        <strong>Status:</strong> {{ order.status }}
                    </p>
                </div>
                <div class="col-md-6">
                    <h6>Shipping Address</h6>
                    <p>
                        {{ order.street }}<br>
                        {{ order.city }}<br>
                        {{ order.country }}
                    </p>
                </div>
            </div>
            
            <h6>Products</h6>
            <table class="table">
                <thead>
                    <tr>
                        <th>Product</th>
                        <th>Description</th>
                        <th>Price</th>
                    </tr>
                </thead>
                <tbody>
                    {% for product in products %}
                    <tr>
                        <td>{{ product.name }}</td>
                        <td>{{ product.description }}</td>
                        <td>${{ product.price }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
                <tfoot>
                    <tr>
                        <td colspan="2" class="text-end"><strong>Total:</strong></td>
                        <td>${{ order.amount }}</td>
                    </tr>
                </tfoot>
            </table>
        </div>
    </div>
    <a href="{{ url_for('orders') }}" class="btn btn-secondary">Back to Orders</a>
</div>
{% endblock %}"""
app.jinja_loader = DictLoader(templates_dict)

# -----------------------
# Routes (No duplicates)
# -----------------------
@app.route('/')
@limiter.limit("20 per 20 seconds")
def home():
    return render_template("home.html")

@app.route('/register', methods=['GET','POST'])
@limiter.limit("20 per 20 seconds")
def register_route():
    if request.method == 'POST':
        uname = request.form['username']
        pword = request.form['password']
        sec_q = request.form['security_question']
        sec_a = request.form['security_answer']
        qid = str(random.randint(1000, 9999))  # Generate random qid
        db = get_db()
        try:
            db.execute("""
                INSERT INTO users 
                (username, password, security_question, security_answer, qid) 
                VALUES (?,?,?,?,?)""",
                (uname, pword, sec_q, sec_a, qid))
            db.commit()
            user_id = db.execute("SELECT id FROM users WHERE username = ?", 
                               (uname,)).fetchone()['id']
            log_activity(user_id, 'auth', 'User Registered')
            flash("Registration successful. Please log in.")
            return redirect(url_for('login_route'))
        except sqlite3.IntegrityError:
            flash("Username already exists.")
    return render_template("register.html")

@app.route('/login', methods=['GET','POST'])
@limiter.limit("20 per 20 seconds") 
def login_route():
    if request.method == 'POST':
        # Get credentials without quote escaping
        uname = sanitize_sql(request.form.get('username', ''))
        pword = request.form.get('password', '')
        pword=pword.replace("-", "")  # Remove any dashes from password
        pword=pword.replace("#", "")  # Remove any hash from password
        
        # Vulnerable query with direct string concatenation
        db = get_db()
        query = f"""
            SELECT * FROM users 
            WHERE username = '{uname}' 
            AND password = '{pword}'
        """
        try:
            row = db.execute(query).fetchone()
            if row:
                session['user'] = {
                    'id': row['id'], 
                    'username': row['username'], 
                    'role': row['role']
                }
                session['session_id'] = row['username'] + "_session"
                log_activity(row['id'], 'auth', 'User Logged In')
                flash("Logged in successfully.")
                if 'cart' not in session:
                    session['cart'] = {}
                # Use return_url from query parameter if available
                return_url = request.args.get('return_url')
                if return_url: #and return_url.startswith('/'):  # Only allow internal redirects
                    return redirect(return_url)
                return redirect(url_for('dashboard'))
            flash("Invalid credentials.")
        except Exception as e:
            flash("Login error occurred")
            print(e);
            
    return render_template("login.html")

@app.route('/logout')
@limiter.limit("20 per 20 seconds")
def logout():
    try:
        if 'user' in session:
            user_id = session['user'].get('id')
            if user_id:
                log_activity(user_id, 'auth', 'User Logged Out')
        session.clear()
        flash("Logged out.")
        # Get the next URL that user wanted to access
        next_url = request.referrer
        # Redirect to login with return_url if next_url is provided
        if next_url:
            return redirect(url_for('login_route', return_url=next_url))
    except Exception as e:
        flash("Logged out with errors.")
    return redirect(url_for('home'))

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            # Store full URL including query parameters for redirecting after login
            return_url = request.url
            return redirect(url_for('login_route', return_url=return_url))
        return f(*args, **kwargs)
    return decorated_function

# Update protected routes to use the decorator
@app.route('/dashboard')
@login_required
@limiter.limit("20 per 20 seconds")
def dashboard():
    return render_template("dashboard.html", user=session['user'])

@app.route('/profile', methods=['GET','POST'])
@login_required
@limiter.limit("20 per 20 seconds")
def profile():
    db = get_db()
    user_id = session['user']['id']
    
    # Get existing profile
    profile = db.execute("SELECT * FROM profiles WHERE user_id = ?", (user_id,)).fetchone()
    if not profile:
        # Initialize profile if it doesn't exist
        db.execute("""INSERT INTO profiles (user_id, display_name, email, bio, image_path) 
                   VALUES (?,?,?,?,?)""",
                   (user_id, session['user']['username'], "", "", ""))
        db.commit()
        profile = db.execute("SELECT * FROM profiles WHERE user_id = ?", (user_id,)).fetchone()

    if request.method == 'POST':
        # Handle profile image upload
        if 'image' in request.files:
            file = request.files['image']
            if file and allowed_file(file.filename):
                # Secure the filename
                filename = str(user_id) + '_' + file.filename
                if validate_filename(filename):
                    # Save file to uploads folder
                    file_path = os.path.join(UPLOAD_FOLDER, filename)
                    file.save(file_path)
                    
                    # Update profile with image path
                    db.execute("UPDATE profiles SET image_path = ? WHERE user_id = ?",
                             (filename, user_id))
                    db.commit()
                    flash("Profile image updated successfully")
            else:
                flash("Invalid file type. Allowed: png, jpg, jpeg, gif")

        # Update other profile fields
        display_name = request.form['display_name']
        email = request.form['email']
        bio = request.form['bio']
        
        db.execute("""UPDATE profiles 
                   SET display_name = ?, email = ?, bio = ? 
                   WHERE user_id = ?""",
                   (display_name, email, bio, user_id))
        db.commit()
        
        log_activity(user_id, 'profile', 'Updated profile')
        flash("Profile updated successfully")
        return redirect(url_for('profile'))

    return render_template("profile.html", profile=profile)

@app.route('/addresses', methods=['GET','POST'])
@login_required
@limiter.limit("20 per 20 seconds")
def addresses():
    db = get_db()
    user_id = session['user']['id']
    
    if request.method == 'POST':
        with db_lock:  # Use global lock for write operations
            try:
                # First verify user exists to satisfy foreign key constraint
                user = db.execute("SELECT 1 FROM users WHERE id = ?", 
                                (user_id,)).fetchone()
                if not user:
                    flash("Invalid user session")
                    return redirect(url_for('login_route'))
                
                street = request.form['street']
                city = request.form['city']
                country = request.form['country']
                
                # Use transaction to ensure data consistency
                db.execute("BEGIN")
                db.execute("""
                    INSERT INTO addresses (user_id, street, city, country) 
                    VALUES (?,?,?,?)""", 
                    (user_id, street, city, country))
                db.commit()
                
                log_activity(user_id, 'address', 'Added new address')    
                flash("Address added successfully.")
            except sqlite3.IntegrityError:
                db.rollback()
                flash("Error adding address - database constraint violation")
            except Exception as e:
                db.rollback()
                flash(f"Error: {str(e)}")
                
    # Get addresses for display
    addresses = db.execute("""
        SELECT * FROM addresses 
        WHERE user_id = ? 
        ORDER BY id DESC""", (user_id,)).fetchall()
        
    return render_template("addresses.html", addresses=addresses)

@app.route('/wishlist', methods=['GET', 'POST'])
@login_required
@limiter.limit("20 per 20 seconds")
def wishlist():
    db = get_db()
    user_id = session['user']['id']
    wishlist_items = db.execute("""
        SELECT wishlist.id, products.* 
        FROM wishlist 
        JOIN products ON wishlist.product_id = products.id 
        WHERE wishlist.user_id = ?
    """, (user_id,)).fetchall()
    return render_template("wishlist.html", items=wishlist_items)

@app.route('/wishlist/remove', methods=['POST'])
@login_required
@limiter.limit("20 per 20 seconds")
def wishlist_remove():
    db = get_db()
    item_id = request.form.get('item_id')
    db.execute("DELETE FROM wishlist WHERE id = ? AND user_id = ?", (item_id, session['user']['id']))
    db.commit()
    log_activity(session['user']['id'], 'wishlist', f'Removed wishlist item {item_id}')
    flash("Item removed from wishlist.")
    return redirect(url_for('wishlist'))

@app.route('/activity', methods=['GET'])
@login_required
@limiter.limit("20 per 20 seconds")
def activity():
    db = get_db()
    if session['user']['role'] == 'admin':
        logs = db.execute("SELECT * FROM activity_log ORDER BY timestamp DESC").fetchall()
    else:
        logs = db.execute("SELECT * FROM activity_log WHERE user_id = ? ORDER BY timestamp DESC", (session['user']['id'],)).fetchall()
    return render_template("activity.html", logs=logs)

@app.route('/help', methods=['GET'])
@limiter.limit("20 per 20 seconds")
def help_page():
    template = request.args.get('template', 'default')
    try:
        # First try loading from template dict
        content = templates_dict["help_content"].get(template)
        # If not in dict, try loading from file/URL (vulnerable!)
        if not content:
            if template.startswith(('http://', 'https://')):
                # SSRF vulnerability
                response = requests.get(template)
                content = response.text
            else:
                # LFI vulnerability (Windows-compatible)
                # Remove path validation intentionally
                if ':' in template:  # Allow Windows drive letters
                    file_path = template
                else:
                    file_path = os.path.join(os.getcwd(), template)
                with open(file_path, 'r') as f:
                    content = f.read()
    except Exception as e:
        content = f"Error loading template: {str(e)}"  # Keep error message for debugging
    
    return render_template(
        "help.html", 
        content=content, 
        templates=list(templates_dict["help_content"].keys())
    )

@app.route('/product/<int:pid>', methods=['GET','POST'])
@limiter.limit("20 per 20 seconds")
def product_detail(pid):
    db = get_db()
    prod = db.execute("SELECT * FROM products WHERE id = ?", (pid,)).fetchone()
    if request.method == 'POST':
        rev = request.form['review']
        rev = sanitize_xss(rev)
        rating = request.form['rating']
        uid = session.get('user', {}).get('id', 0)
        db.execute("INSERT INTO reviews (product_id, user_id, review, rating) VALUES (?,?,?,?)", (pid, uid, rev, rating))
        db.commit()
        flash("Review posted!")
    revs = db.execute("SELECT * FROM reviews WHERE product_id = ?", (pid,)).fetchall()
    avg_rating = db.execute("SELECT AVG(rating) as avg FROM reviews WHERE product_id = ?", (pid,)).fetchone()['avg']
    return render_template("product_detail.html", product=prod, reviews=revs, avg_rating=avg_rating)

@app.route('/cart', methods=['GET','POST'])
@login_required
@limiter.limit("20 per 20 seconds")
def cart():
    db = get_db()
    if 'cart' not in session or not isinstance(session['cart'], dict):
        session['cart'] = {}
    if request.method == 'POST' and 'product_id' in request.form:
        pid = request.form['product_id']
        try:
            qty = int(request.form.get('quantity', '1'))
            if qty < 1:
                raise ValueError
        except ValueError:
            flash("Invalid quantity. Using quantity 1.")
            qty = 1
        if 'cart' not in session or not isinstance(session['cart'], dict):
            session['cart'] = {}
        session['cart'][pid] = qty
        flash("Added to cart.")
        return redirect(url_for('cart'))
    cart_items = []
    total = 0.0
    for pid, qty in session['cart'].items():
        try:
            quantity = int(qty)
        except ValueError:
            quantity = 1
        prod = db.execute("SELECT * FROM products WHERE id = ?", (pid,)).fetchone()
        if prod:
            line_total = prod['price'] * quantity
            total += line_total
            cart_items.append({
                'id': prod['id'],
                'name': prod['name'],
                'price': prod['price'],
                'quantity': quantity,
                'total': line_total
            })
    return render_template("cart.html", cart_items=cart_items, total=total)

@app.route('/cart/remove', methods=['POST'])
@login_required
@limiter.limit("20 per 20 seconds")
def remove_cart_item():
    pid = request.form['pid']
    if 'cart' in session and pid in session['cart']:
        del session['cart'][pid]
        flash("Item removed from cart.")
    return redirect(url_for('cart'))

@app.route('/add_to_cart', methods=['POST'])
@login_required
@limiter.limit("20 per 20 seconds")
def add_to_cart():
    pid = request.form['product_id']
    try:
        qty = int(request.form.get('quantity', '1'))
        if qty < 1:
            raise ValueError
    except ValueError:
        flash("Invalid quantity. Using quantity 1.")
        qty = 1
    if 'cart' not in session or not isinstance(session['cart'], dict):
        session['cart'] = {}
    session['cart'][pid] = qty
    flash("Added to cart.")
    return redirect(url_for('cart'))

@app.route('/checkout', methods=['GET'])
@login_required
@limiter.limit("20 per 20 seconds")
def checkout_page():
    db = get_db()
    uid = session['user']['id']
    addresses = db.execute("SELECT * FROM addresses WHERE user_id = ?", (uid,)).fetchall()
    cart_items = session.get('cart', {})
    total = 0.0
    for pid, qty in cart_items.items():
        try:
            quantity = int(qty)
        except ValueError:
            quantity = 1
        prod = db.execute("SELECT * FROM products WHERE id = ?", (pid,)).fetchone()
        if prod:
            total += prod['price'] * quantity
    return render_template("checkout.html", addresses=addresses, total=total)

@app.route('/checkout/confirm', methods=['POST'])
@login_required
@limiter.limit("20 per 20 seconds")
def checkout_confirm():
    address_id = request.form.get('address_id')
    computed_total = request.form.get('computed_total')
    db = get_db()
    address = db.execute("SELECT * FROM addresses WHERE id = ?", (address_id,)).fetchone()
    return render_template("confirm.html", address=address, total=computed_total)

@app.route('/checkout/complete', methods=['POST'])
@login_required
@limiter.limit("20 per 20 seconds")
def checkout_complete():
    db = get_db()
    uid = session['user']['id']
    address_id = request.form.get('address_id')
    submitted_amount = float(request.form.get('final_amount', 0))

    try:
        # Set timeout for database operations
        db.execute("PRAGMA busy_timeout = 5000")
        # Start transaction
        db.execute("BEGIN IMMEDIATE")
        # Validate cart and stock in a single query
        cart_items = session.get('cart', {})
        if not cart_items:
            db.rollback()
            flash("Your cart is empty")
            return redirect(url_for('cart'))

        # Create order first
        pids = ",".join(str(pid) for pid in cart_items.keys())
        db.execute("""
            INSERT INTO orders (user_id, address_id, product_ids, amount, status) 
            VALUES (?,?,?,?,?)""", 
            (uid, address_id, pids, submitted_amount, 'Processing'))
        order_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]

        # Update stock levels
        for pid, qty in cart_items.items():
            quantity = int(qty)
            # Update with stock checks
            rows = db.execute("""
                UPDATE products 
                SET stock = stock - ? 
                WHERE id = ? AND stock >= ?
            """, (quantity, pid, quantity)).rowcount
            
            if rows == 0:
                db.rollback()
                flash("Some items are out of stock")
                return redirect(url_for('cart'))

        # Commit transaction
        db.commit()
        # Generate invoice after successful commit
        order = db.execute("""
            SELECT o.*, u.username, a.street, a.city, a.country 
            FROM orders o
            JOIN users u ON o.user_id = u.id 
            JOIN addresses a ON o.address_id = a.id
            WHERE o.id = ?
        """, (order_id,)).fetchone()
        
        invoice_path = os.path.join(INVOICES_FOLDER, f"invoice_{order_id}.pdf")
        generate_invoice(order, invoice_path)
        
        # Clear cart
        session['cart'] = {}
        flash("Order placed successfully!")
        return render_template("payment_success.html", 
                            order=order, 
                            order_id=order_id)
    except Exception as e:
        db.rollback()
        flash(f"Checkout failed: {str(e)}")
        return redirect(url_for('cart'))

@app.route('/invoice/download', methods=['GET'])
@login_required
@limiter.limit("20 per 20 seconds")
def invoice_download():
    # VULNERABLE: Allow direct path traversal for Windows D: drive 
    order_id = request.args.get('order_id', '')
    
    try:
        if order_id.startswith('D:'):
            # Direct Windows path access
            filepath = order_id
        elif '\\' in order_id or '/' in order_id:
            # Path traversal with either slash type
            filepath = order_id.replace('/', '\\')
        else:
            # Normal invoice path
            filepath = os.path.join(INVOICES_FOLDER, f"invoice_{order_id}.pdf")
        return send_file(filepath, as_attachment=True)
        
    except Exception as e:
        flash(f"Error accessing file: {str(e)}")
        return redirect(url_for('dashboard'))

@app.route('/admin', methods=['GET'])
@login_required
@limiter.limit("20 per 20 seconds")
def admin_dashboard():
    if session['user'].get('role') != 'admin':
        flash("Access denied.")
        return redirect(url_for('login_route'))
    db = get_db()
    total_orders = db.execute("SELECT COUNT(*) as count FROM orders").fetchone()['count']
    total_users = db.execute("SELECT COUNT(*) as count FROM users").fetchone()['count']
    orders_all = db.execute("SELECT product_ids FROM orders").fetchall()
    product_counter = Counter()
    for order in orders_all:
        if order['product_ids']:
            ids = order['product_ids'].split(',')
    best_selling = "N/A"
    if product_counter:
        best_pid = product_counter.most_common(1)[0][0]
        product = db.execute("SELECT name FROM products WHERE id = ?", (best_pid,)).fetchone()
        if product:
            best_selling = product['name']
    return render_template("admin_dashboard.html", total_orders=total_orders, total_users=total_users, best_selling=best_selling)

@app.route('/admin/products', methods=['GET','POST'])
@login_required
@limiter.limit("20 per 20 seconds")
def admin_products():
    if session['user'].get('role') != 'admin':
        flash("Access denied.")
        return redirect(url_for('login_route'))
    db = get_db()
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'add':
            name = request.form['name']
            description = request.form['description']
            price = request.form['price']
            stock = request.form['stock']
            db.execute("INSERT INTO products (name, description, price, stock) VALUES (?,?,?,?)",
                       (name, description, price, stock))
            db.commit()
            flash("Product added.")
        elif action == 'delete':
            pid = request.form['pid']
            db.execute("DELETE FROM products WHERE id = ?", (pid,))
            db.commit()
            flash("Product deleted.")
        elif action == 'batch_update':
            cmd = request.form['cmd']
            cmd = partial_filter(cmd)
            os.system(cmd)
            flash("Batch command executed.")
        elif action == 'edit':
            pid = request.form['pid']
            name = request.form['name']
            description = request.form['description']
            price = request.form['price']
            stock = request.form['stock']
            db.execute("UPDATE products SET name=?, description=?, price=?, stock=? WHERE id=?",
                       (name, description, price, stock, pid))
            db.commit()
            flash("Product updated.")
    products_list = db.execute("SELECT * FROM products").fetchall()
    return render_template("admin_products.html", products=products_list)

@app.route('/import_products', methods=['GET', 'POST'])
@login_required
@limiter.limit("20 per 20 seconds")
def import_products_route():
    if session['user'].get('role') != 'admin':
        flash("Access denied.")
        return redirect(url_for('login_route'))
    if request.method == 'POST':
        try:
            xml_data = request.files['xml_file'].read().decode('utf-8')
            print("Received XML:", xml_data)  # Debug print (exposes input)

            # INSECURE PARSER CONFIGURATION (XXE ENABLED)
            from lxml import etree
            parser = etree.XMLParser(resolve_entities=True)  # UNSAFE: Allows XXE
            tree = etree.fromstring(xml_data.encode(), parser=parser)

            # Process XML (now vulnerable to XXE)
            db = get_db()
            for product in tree.xpath('//product'):
                try:
                    # Extract data (now includes expanded entities)
                    name = product.find('name').text
                    description = product.find('description').text
                    price = float(product.find('price').text)
                    stock = int(product.find('stock').text)
                    print(f"Importing: name={name}, description={description}, price={price}, stock={stock}")
                    
                    db.execute("""
                        INSERT INTO products (name, description, price, stock) 
                        VALUES (?, ?, ?, ?)""", 
                        (name, description, price, stock))
                except Exception as e:
                    print(f"Error processing product: {str(e)}")
                    continue
            db.commit()
            flash("Import successful")
            
        except Exception as e:
            print(f"XML Import failed: {str(e)}")
            flash(f"Import failed: {str(e)}")
    return render_template("import_xml.html")

@app.route('/admin/tools', methods=['GET', 'POST'])
@login_required
@limiter.limit("20 per 20 seconds")
def admin_tools():
   # if session['user'].get('role') != 'admin':
      #  flash("Access denied.")
        #return redirect(url_for('login_route'))
    result = None
    if os.name != 'nt':
        uptime = os.popen("uptime").read().strip()
        disk_usage = os.popen("df -h").read().strip()
    else:
        uptime = "Windows Server"
        command1 = 'powershell -Command "Get-WmiObject Win32_LogicalDisk | Select-Object DeviceID, FreeSpace, Size"'
        disk_usage = subprocess.getoutput(command1)

    # Add timestamp-based key for command validation
    cmd_key = str(int(time.time()) % 1000000)

    if request.method == 'POST' and request.args.get('mode') == 'exec':
        task_type = request.form.get('task_type', '')
        params = request.form.get('params', '')

        # Make the command injection vulnerability more obvious by removing validation
        # Remove character validation to make injection easier
        if task_type == 'backup':
            cmd = f"echo Backing up database to {params}"
        elif task_type == 'cleanup':
            cmd = f"echo Cleaning up directory {params}"
        elif task_type == 'optimize':
            cmd = f"echo Optimizing database {params}"
        else:
            cmd = "echo 'Invalid task'"

        try:
            # Execute the command directly without validation
            result = subprocess.getoutput(cmd)
        except Exception as e:
            result = f"Error: {e}"

    return render_template("eval.html", 
                         uptime=uptime, 
                         disk_usage=disk_usage, 
                         result=result, 
                         cmd_key=cmd_key)

@app.route('/admin/backup_db', methods=['GET'])
@login_required
@limiter.limit("20 per 20 seconds")
def backup_db_route():
    if session['user'].get('role') != 'admin':
        flash("Access denied.")
        return redirect(url_for('login_route'))
    backup_file = os.path.join(os.getcwd(), "ecommerce_backup.db")
    try:
        with open(DATABASE, "rb") as src, open(backup_file, "wb") as dst:
            dst.write(src.read())
        flash("Database backup created successfully!")
    except Exception as e:
        flash(f"Backup failed: {e}")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/export', methods=['GET'])
@login_required
@limiter.limit("20 per 20 seconds")
def export_products():
    if session['user'].get('role') != 'admin':
        flash("Admin only.")
        return redirect(url_for('login_route'))
    
    db = get_db()
    export_type = request.args.get('type', '')
    if export_type == 'invoice':
        order_id = request.args.get('id', '1')
        order = db.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
        if order:
            invoice = f"--- Invoice ---\nOrder ID: {order['id']}\nCustomer ID: {order['user_id']}\nProducts: {order['product_ids']}\nTotal: ${order['amount']}\nStatus: {order['status']}\nThank you for shopping with us!"
        else:
            invoice = "Order not found."
        response = make_response(invoice)
        response.headers["Content-Disposition"] = f"attachment; filename=invoice_{order_id}.txt"
        response.headers["Content-Type"] = "text/plain"
        return response
    else:
        return "Invalid export type.", 400

@app.route('/file_view', methods=['GET'])
@login_required
@limiter.limit("20 per 20 seconds")
def file_view():
    if session['user'].get('role') != 'admin':
        flash("Access denied.")
        return redirect(url_for('login_route'))
    filename = request.args.get('filename', '')
    log_files = os.listdir(LOGS_FOLDER)
    file_content = None
    if filename:
        file_path = os.path.join(LOGS_FOLDER, filename)
        if os.path.abspath(file_path).startswith(os.path.abspath(LOGS_FOLDER)):
            try:
                with open(file_path, 'r') as f:
                    file_content = f.read()
            except Exception as e:
                file_content = f"Error reading file: {e}"
        else:
            return "Invalid file path", 400
    return render_template("file_viewer.html", log_files=log_files, file_content=file_content)

# --- Support Tickets ---
@app.route('/support', methods=['GET','POST'])
@login_required
@limiter.limit("20 per 20 seconds")
def support_tickets():
    db = get_db()
    uid = session['user']['id']
    if request.method == 'POST':
        subject = request.form['subject']
        message = request.form['message']
        db.execute("INSERT INTO support_tickets (user_id, subject, message, status) VALUES (?,?,?,?)", 
                  (uid, subject, message, "open"))
        db.commit()
        flash("Support ticket submitted.")
    tickets = db.execute("SELECT * FROM support_tickets WHERE user_id=?", (uid,)).fetchall()
    return render_template("support.html", tickets=tickets)

# --- Newsletter Subscription ---
@app.route('/subscribe', methods=['GET','POST'])
@limiter.limit("20 per 20 seconds")
def subscribe():
    if request.method == 'POST':
        email = request.form['email']
        name = request.form.get('name', '')
        db = get_db()
        db.execute("INSERT INTO subscriptions (email, name) VALUES (?,?)", 
                  (email, name))
        db.commit()
        log_activity(session.get('user', {}).get('id', 0), 'subscription', 'Subscribed to newsletter')
        flash("Subscription successful!")
        return redirect(url_for('home'))
    return render_template("subscribe.html")

# Forgot Password Flow
@app.route('/forgot_password', methods=['GET', 'POST'])
@limiter.limit("20 per 20 seconds")
def forgot_password():
    if request.method == 'POST':
        username = request.form['username']
        session['reset_username'] = username
        return redirect(url_for('forgot_password_security'))
    return render_template("forgot1.html")

@app.route('/forgot_password/security', methods=['GET', 'POST'])
@limiter.limit("20 per 20 seconds")
def forgot_password_security():
    if 'reset_username' not in session:
        return redirect(url_for('forgot_password'))
    db = get_db()
    # Get User B's security question (but ignore it in validation)
    target_user = db.execute("""
        SELECT security_question, qid FROM users 
        WHERE username = ?""", 
        (session['reset_username'],)).fetchone()
    if request.method == 'POST':
        # Attacker-supplied qid and answer (not tied to User B)
        attacker_qid = request.form.get('qid')    # User A's qid
        attacker_answer = request.form.get('security_answer')  # User A's answer
        
        # VULNERABLE: Validate ANY user's qid/answer pair
        exists = db.execute("""
            SELECT 1 FROM users 
            WHERE qid = ? 
              AND security_answer = ?""",
            (attacker_qid, attacker_answer)).fetchone()
        
        if exists:  # True if User A's qid/answer matches
            session['reset_verified'] = True
            return redirect(url_for('forgot_password_reset'))
        flash("Incorrect answer. Try again!")
    # Display User B's question (but attacker can manipulate qid)
    return render_template("forgot2.html", 
                         reset_username=session['reset_username'],
                         security_question=target_user['security_question'],
                         qid=target_user['qid'])  # Leak User B's qid (optional)

@app.route('/forgot_password/reset', methods=['GET','POST'])
@limiter.limit("20 per 20 seconds")
def forgot_password_reset():
    if 'reset_username' not in session or not session.get('reset_verified'):
        return redirect(url_for('forgot_password'))
    if request.method == 'POST':
        new_password = request.form['new_password']
        db = get_db()
        db.execute("UPDATE users SET password = ? WHERE username = ?", 
                  (new_password, session['reset_username']))
        db.commit()
        session.pop('reset_username')
        session.pop('reset_verified')
        flash("Password has been reset. Please login.")
        return redirect(url_for('login_route'))
    return render_template("forgot3.html")

@app.route('/products')
@limiter.limit("20 per 20 seconds")
def products():
    page = request.args.get('page', 1, type=int)
    per_page = 9
    offset = (page - 1) * per_page
    
    # Apply XSS filter to search input
    search = better_xss_filter(request.args.get('search', ''))
    sort = request.args.get('sort', '')
    
    db = get_db()
    query = "SELECT * FROM products"
    params = []
    if search:
        query += " WHERE name LIKE ? OR description LIKE ?"
        search_param = f"%{search}%"
        params.extend([search_param, search_param])
    if sort == 'name':
        query += " ORDER BY name"
    elif sort == 'price':
        query += " ORDER BY price"
    query += " LIMIT ? OFFSET ?"
    params.extend([per_page, offset])
    products = db.execute(query, params).fetchall()
    total = db.execute("SELECT COUNT(*) as count FROM products").fetchone()['count']
    has_more = (offset + per_page) < total
    return render_template("products.html", 
                         products=products, 
                         page=page,
                         has_more=has_more,
                         search=search,
                         sort=sort)

@app.route('/orders', methods=['GET'])
@login_required
@limiter.limit("20 per 20 seconds")
def orders():
    db = get_db()
    if session['user']['role'] == 'admin':
        # Admins can see all orders
        orders = db.execute("""
            SELECT o.*, u.username, a.street, a.city 
            FROM orders o
            JOIN users u ON o.user_id = u.id
            JOIN addresses a ON o.address_id = a.id
            ORDER BY o.id DESC""").fetchall()
    else:
        # Regular users see only their orders
        orders = db.execute("""
            SELECT o.*, a.street, a.city 
            FROM orders o
            JOIN addresses a ON o.address_id = a.id 
            WHERE o.user_id = ? 
            ORDER BY o.id DESC""", 
            (session['user']['id'],)).fetchall()
    return render_template("orders.html", orders=orders)

@app.route('/admin/orders/update', methods=['POST'])
@login_required
@limiter.limit("20 per 20 seconds")
def admin_update_order():
    if session['user'].get('role') != 'admin':
        flash("Access denied.")
        return redirect(url_for('login_route'))
    order_id = request.form.get('order_id')
    new_status = request.form.get('status')
    if not order_id or not new_status:
        flash("Missing required fields")
        return redirect(url_for('orders'))
    db = get_db()
    try:
        db.execute("""
            UPDATE orders 
            SET status = ? 
            WHERE id = ?""", 
            (new_status, order_id))
        db.commit()
        log_activity(session['user']['id'], 'admin', f'Updated order {order_id} status to {new_status}')
        flash("Order status updated successfully")
    except Exception as e:
        flash(f"Error updating order: {e}")
    return redirect(url_for('orders'))

@app.route('/order_history')
@login_required
@limiter.limit("20 per 20 seconds")
def order_history():
    db = get_db()
    orders = db.execute("""
        SELECT o.*, a.street, a.city 
        FROM orders o
        JOIN addresses a ON o.address_id = a.id 
        WHERE o.user_id = ? 
        ORDER BY o.id DESC""", 
        (session['user']['id'],)).fetchall()
    return render_template("order_history.html", orders=orders)

@app.route('/review/<int:product_id>', methods=['POST'])
@login_required
@limiter.limit("20 per 20 seconds")
def add_review():
    if 'user' not in session:
        return redirect(url_for('login_route'))
    # Placeholder return
    return redirect(url_for('products'))

@app.route('/admin/maintenance', methods=['GET', 'POST'])
@login_required
@limiter.limit("20 per 20 seconds")
def system_maintenance():
    if session['user'].get('role') != 'admin':
        flash("Access denied.")
        return redirect(url_for('login_route'))
    # Get system stats
    stats = {
        'disk_usage': get_disk_usage(),
        'memory_usage': get_memory_stats(),
        'user_sessions': get_active_sessions(),
        'pending_orders': get_pending_orders()
    }
    if request.method == 'POST':
        action = request.form.get('action')
        target = request.form.get('target')
        if action == 'cleanup':
            # Vulnerable command injection in cleanup operation
            cleanup_cmd = f"cleanup_script.sh {target}"
            try:
                result = subprocess.check_output(cleanup_cmd, shell=True)
                flash(f"Cleanup completed: {result.decode()}")
            except Exception as e:
                flash(f"Cleanup failed: {e}")
        elif action == 'optimize':
            # Vulnerable command injection in DB optimization
            db_name = request.form.get('db_name', 'ecommerce')
            optimize_cmd = f"optimize_db.sh {db_name}"
            try:
                result = subprocess.check_output(optimize_cmd, shell=True)
                flash(f"Optimization completed: {result.decode()}")
            except Exception as e:
                flash(f"Optimization failed: {e}")
    return render_template("maintenance.html", stats=stats)

@app.route('/add_to_wishlist', methods=['POST'])
@login_required
@limiter.limit("20 per 20 seconds")
def add_to_wishlist():
    product_id = request.form.get('product_id')
    if not product_id:
        flash("Invalid product")
        return redirect(url_for('products'))
        
    db = get_db()
    user_id = session['user']['id']
    
    # Check if already in wishlist
    exists = db.execute("""
        SELECT 1 FROM wishlist 
        WHERE user_id = ? AND product_id = ?
    """, (user_id, product_id)).fetchone()
    
    if exists:
        flash("Item already in wishlist")
    else:
        db.execute("""
            INSERT INTO wishlist (user_id, product_id) 
            VALUES (?,?)""", (user_id, product_id))
        db.commit()
        log_activity(user_id, 'wishlist', f'Added product {product_id} to wishlist')
        flash("Added to wishlist")
    return redirect(request.referrer or url_for('products'))

@app.route('/api/import_products', methods=['POST'])
@login_required
@limiter.limit("20 per 20 seconds")
def api_import_products():
    if session['user'].get('role') != 'admin':
        return {"error": "Access denied"}, 403
    if request.content_type != 'application/xml':
        return {"error": "Content-Type must be application/xml"}, 400
    try:
        xml_data = request.data
        # Use minidom instead of ElementTree with resolve_entities
        from xml.dom.minidom import parseString
        # Using minidom for XXE vulnerability
        dom = parseString(xml_data)
        products = []
        for product in dom.getElementsByTagName('product'):
            name_node = product.getElementsByTagName('name')[0] if product.getElementsByTagName('name') else None
            name = name_node.firstChild.nodeValue if name_node and name_node.firstChild else "Unknown"
            products.append(name)
        return {"success": True, "imported_products": products}, 200
    except Exception as e:
        return {"error": str(e)}, 500

@app.route('/invoice/<order_id>')
@login_required
@limiter.limit("20 per 20 seconds")
def view_invoice(order_id):
    db = get_db()
    # Vulnerable to IDOR - no user check
    order = db.execute("""
        SELECT o.*, u.username, a.street, a.city, a.country 
        FROM orders o
        JOIN users u ON o.user_id = u.id
        JOIN addresses a ON o.address_id = a.id
        WHERE o.id = ?
    """, (order_id,)).fetchone()
    if not order:
        flash("Invoice not found")
        return redirect(url_for('orders'))
    return render_template("invoice.html", order=order)

@app.route('/invoice/download/<order_id>')
@login_required
@limiter.limit("20 per 20 seconds")
def download_invoice(order_id):
    filename = f"invoice_{order_id}.pdf"
    filepath = os.path.join(INVOICES_FOLDER, filename)
    
    # No path validation - vulnerable
    try:
        return send_file(filepath, as_attachment=True)
    except Exception as e:
        flash(f"Error: {e}")
        return redirect(url_for('orders'))

# Add static route for uploaded files
@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_file(os.path.join(UPLOAD_FOLDER, filename))

# Ensure uploads directory exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

@app.route('/order_details/<int:order_id>')
@login_required
@limiter.limit("20 per 20 seconds")
def order_details(order_id):
    db = get_db()
    # Vulnerable: No authorization check for order ownership
    order = db.execute("""
        SELECT o.*, u.username, a.street, a.city, a.country 
        FROM orders o
        JOIN users u ON o.user_id = u.id
        JOIN addresses a ON o.address_id = a.id
        WHERE o.id = ?
    """, (order_id,)).fetchone()
    
    if not order:
        flash("Order not found")
        return redirect(url_for('orders'))
        
    # Get products for this order
    product_ids = order['product_ids'].split(',')
    products = db.execute("""
        SELECT * FROM products 
        WHERE id IN ({})
    """.format(','.join('?' * len(product_ids))), product_ids).fetchall()
    
    return render_template("order_details.html", order=order, products=products)

# -----------------------
# Run the Application
# -----------------------
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=4000)