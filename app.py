from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import sqlite3
import os
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from functools import wraps

app = Flask(__name__)
app.secret_key = 'rambati-secret-2026-xK9mP3qL'
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'rambati.db')

OWNER_ACTIVATION_KEY = 'RAMBATI_OWNER_2026'

# ── Database Setup ──
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        role TEXT NOT NULL,
        first_name TEXT NOT NULL,
        last_name TEXT NOT NULL,
        phone TEXT NOT NULL UNIQUE,
        email TEXT,
        designation TEXT,
        latitude TEXT,
        longitude TEXT,
        city TEXT,
        order_type TEXT,
        biz_name TEXT,
        biz_lat TEXT,
        biz_lng TEXT,
        reg_no TEXT,
        staff_count TEXT,
        password_hash TEXT NOT NULL,
        created_at TEXT NOT NULL
    )''')
    conn.execute('''CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        customer_id INTEGER NOT NULL,
        customer_name TEXT NOT NULL,
        phone TEXT NOT NULL,
        items TEXT NOT NULL,
        quantity TEXT NOT NULL,
        address TEXT NOT NULL,
        notes TEXT,
        status TEXT NOT NULL DEFAULT 'Pending',
        created_at TEXT NOT NULL,
        FOREIGN KEY(customer_id) REFERENCES users(id)
    )''')
    conn.execute('''CREATE TABLE IF NOT EXISTS feedbacks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER UNIQUE,
        customer_name TEXT NOT NULL,
        role_label TEXT NOT NULL,
        rating INTEGER NOT NULL,
        comment TEXT NOT NULL,
        created_at TEXT NOT NULL
    )''')
    conn.commit()
    conn.close()

init_db()

# ── Auth Decorators ──
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login', next=request.path))
        return f(*args, **kwargs)
    return decorated

def owner_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session or session.get('role') != 'owner':
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

# ── Routes ──
@app.route("/")
def index():
    delivery_location = "Inaruwa, Sunsari"
    location = "Inaruwa-3, Sunsari"
    phone = "9805357571"
    user = None
    if 'user_id' in session:
        user = {
            'id': session['user_id'],
            'name': session.get('user_name', ''),
            'role': session.get('role', 'customer')
        }
        
    conn = get_db()
    feedbacks = conn.execute("SELECT * FROM feedbacks ORDER BY created_at DESC LIMIT 6").fetchall()
    conn.close()
    
    return render_template('index.html',
                           delivery_location=delivery_location,
                           location=location,
                           phone=phone,
                           user=user,
                           feedbacks=feedbacks)

@app.route("/login")
def login():
    if 'user_id' in session:
        return redirect(url_for('index'))
    next_page = request.args.get('next', '')
    return render_template("login.html", next_page=next_page)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route("/login-user", methods=["POST"])
def login_user():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "message": "No data received."}), 400

        phone = data.get("phone", "").strip()
        password = data.get("password", "")
        next_page = data.get("next", "")

        if not phone or not password:
            return jsonify({"success": False, "message": "Phone and password are required."}), 400

        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE phone = ?", (phone,)).fetchone()
        conn.close()

        if not user or not check_password_hash(user['password_hash'], password):
            return jsonify({"success": False, "message": "Invalid phone number or password."}), 401

        session['user_id'] = user['id']
        session['user_name'] = f"{user['first_name']} {user['last_name']}"
        session['role'] = user['role']
        session.permanent = True

        redirect_to = next_page if next_page else '/'
        if user['role'] == 'owner':
            redirect_to = '/owner'

        return jsonify({
            "success": True,
            "message": "Login successful!",
            "redirect": redirect_to,
            "role": user['role'],
            "name": f"{user['first_name']} {user['last_name']}"
        })

    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route("/register", methods=["POST"])
def register():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "message": "No data received."}), 400

        role = data.get("role", "customer")
        first_name = data.get("first_name", "").strip()
        last_name = data.get("last_name", "").strip()
        phone = data.get("phone", "").strip()
        email = data.get("email", "").strip()
        password = data.get("password", "")

        if not first_name or not last_name or not phone or len(password) < 8:
            return jsonify({"success": False, "message": "Missing required fields or password too short."}), 400

        # Owner: validate activation key and check single-owner rule
        if role == "owner":
            owner_key = data.get("owner_key", "")
            if owner_key != OWNER_ACTIVATION_KEY:
                return jsonify({"success": False, "message": "Invalid owner activation key."}), 403

            conn = get_db()
            existing_owner = conn.execute("SELECT id FROM users WHERE role = 'owner'").fetchone()
            if existing_owner:
                conn.close()
                return jsonify({"success": False, "message": "An owner account already exists. Only one owner is allowed."}), 403
            conn.close()

        conn = get_db()
        existing = conn.execute("SELECT id FROM users WHERE phone = ?", (phone,)).fetchone()
        if existing:
            conn.close()
            return jsonify({"success": False, "message": "Phone number already registered."}), 409

        password_hash = generate_password_hash(password)
        created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if role == "customer":
            conn.execute('''INSERT INTO users
                (role, first_name, last_name, phone, email, latitude, longitude, city, order_type, password_hash, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                (role, first_name, last_name, phone, email,
                 data.get("latitude", ""), data.get("longitude", ""),
                 data.get("city", ""), data.get("order_type", ""),
                 password_hash, created_at))
        else:
            conn.execute('''INSERT INTO users
                (role, first_name, last_name, phone, email, designation, biz_name, biz_lat, biz_lng, reg_no, staff_count, password_hash, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                (role, first_name, last_name, phone, email,
                 data.get("designation", ""), data.get("biz_name", ""),
                 data.get("biz_lat", ""), data.get("biz_lng", ""),
                 data.get("reg_no", ""), data.get("staff_count", ""),
                 password_hash, created_at))

        conn.commit()
        conn.close()
        return jsonify({"success": True, "message": "Registration successful!"})

    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route("/place-order", methods=["POST"])
@login_required
def place_order():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "message": "No data received."}), 400

        items = data.get("items", "").strip()
        quantity = data.get("quantity", "").strip()
        address = data.get("address", "").strip()
        notes = data.get("notes", "").strip()

        if not items or not quantity or not address:
            return jsonify({"success": False, "message": "Items, quantity, and address are required."}), 400

        customer_id = session['user_id']
        customer_name = session['user_name']

        conn = get_db()
        user = conn.execute("SELECT phone FROM users WHERE id = ?", (customer_id,)).fetchone()
        phone = user['phone'] if user else ''

        cursor = conn.execute('''INSERT INTO orders
            (customer_id, customer_name, phone, items, quantity, address, notes, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'Pending', ?)''',
            (customer_id, customer_name, phone, items, quantity, address, notes,
             datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        order_id = cursor.lastrowid
        conn.commit()
        conn.close()

        return jsonify({
            "success": True,
            "message": "Order placed successfully!",
            "order_id": order_id
        })

    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route("/my-feedback")
@login_required
def my_feedback():
    conn = get_db()
    fb = conn.execute("SELECT * FROM feedbacks WHERE user_id = ?", (session['user_id'],)).fetchone()
    conn.close()
    if fb:
        return jsonify({"has_feedback": True, "rating": fb['rating'], "comment": fb['comment']})
    return jsonify({"has_feedback": False})

@app.route("/submit-feedback", methods=["POST"])
@login_required
def submit_feedback():
    try:
        data = request.get_json()
        rating = int(data.get("rating", 5))
        comment = data.get("comment", "").strip()
        if not comment:
            return jsonify({"success": False, "message": "Comment is required."}), 400
            
        user_id = session['user_id']
        customer_name = session.get("user_name", "Customer")
        role_label = "Verified Customer"
        created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        conn = get_db()
        conn.execute("INSERT OR REPLACE INTO feedbacks (id, user_id, customer_name, role_label, rating, comment, created_at) VALUES ((SELECT id FROM feedbacks WHERE user_id = ?), ?, ?, ?, ?, ?, ?)",
                     (user_id, user_id, customer_name, role_label, rating, comment, created_at))
        conn.commit()
        conn.close()
        
        return jsonify({"success": True, "message": "Feedback saved successfully!"})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route("/update-order-status", methods=["POST"])
@owner_required
def update_order_status():
    try:
        data = request.get_json()
        order_id = data.get("order_id")
        status = data.get("status")
        allowed = ['Pending', 'Confirmed', 'Out for Delivery', 'Delivered', 'Cancelled', 'Out of Stock']
        if status not in allowed:
            return jsonify({"success": False, "message": "Invalid status."}), 400

        conn = get_db()
        conn.execute("UPDATE orders SET status = ? WHERE id = ?", (status, order_id))
        conn.commit()
        conn.close()
        return jsonify({"success": True})

    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route("/api/orders")
@owner_required
def api_orders():
    conn = get_db()
    orders = conn.execute("SELECT * FROM orders ORDER BY created_at DESC").fetchall()
    conn.close()
    return jsonify([dict(o) for o in orders])

@app.route("/api/me")
def api_me():
    if 'user_id' not in session:
        return jsonify({"logged_in": False})
    return jsonify({
        "logged_in": True,
        "id": session['user_id'],
        "name": session['user_name'],
        "role": session['role']
    })

@app.route("/dashboard")
@login_required
def dashboard():
    if session.get('role') == 'owner':
        return redirect(url_for('owner_dashboard'))
    
    conn = get_db()
    customer_id = session['user_id']
    orders = conn.execute("SELECT * FROM orders WHERE customer_id = ? ORDER BY created_at DESC", (customer_id,)).fetchall()
    user_name = session.get('user_name', 'Customer')
    conn.close()
    return render_template("customer_dashboard.html", orders=orders, user_name=user_name)

@app.route("/owner")
@owner_required
def owner_dashboard():
    conn = get_db()
    orders = conn.execute("SELECT * FROM orders ORDER BY created_at DESC").fetchall()
    total = len(orders)
    pending = sum(1 for o in orders if o['status'] == 'Pending')
    delivered = sum(1 for o in orders if o['status'] == 'Delivered')
    confirmed = sum(1 for o in orders if o['status'] == 'Confirmed')
    owner_name = session.get('user_name', 'Owner')
    conn.close()
    return render_template("owner_dashboard.html",
                           orders=orders,
                           total=total,
                           pending=pending,
                           delivered=delivered,
                           confirmed=confirmed,
                           owner_name=owner_name)

if __name__ == "__main__":
    app.run(debug=True)