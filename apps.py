import streamlit as st

st.set_page_config(
    page_title="Farm2Market",
    page_icon="🌾",
    layout="wide",
    initial_sidebar_state="expanded"
)

import sqlite3
import hashlib
import io
import re
import logging
import time
import qrcode
import cv2
import numpy as np
from PIL import Image
from datetime import datetime
from io import BytesIO
from typing import Optional

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s", filename="farm2market.log")

# ─────────────────────────────────────────────
# CSS THEME
# ─────────────────────────────────────────────
def inject_css():
    st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
    html, body, [class*="css"] { font-family: 'Inter', sans-serif; }

    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, #1B5E20 0%, #2E7D32 60%, #388E3C 100%);
    }
    [data-testid="stSidebar"] * { color: #E8F5E9 !important; }
    [data-testid="stSidebar"] .stButton > button {
        background: rgba(255,255,255,0.12); border: 1px solid rgba(255,255,255,0.25);
        color: #fff !important; border-radius: 8px; width: 100%;
        margin-bottom: 4px; font-weight: 500; transition: background 0.2s;
    }
    [data-testid="stSidebar"] .stButton > button:hover { background: rgba(255,255,255,0.22); }

    .f2m-card {
        background: #fff; border: 1px solid #E8F5E9; border-radius: 14px;
        padding: 18px; margin-bottom: 14px;
        box-shadow: 0 2px 8px rgba(46,125,50,0.07); transition: box-shadow 0.2s;
    }
    .f2m-card:hover { box-shadow: 0 4px 18px rgba(46,125,50,0.13); }

    .metric-card {
        background: linear-gradient(135deg, #E8F5E9, #C8E6C9);
        border-radius: 12px; padding: 18px; text-align: center;
        border-left: 4px solid #2E7D32; margin-bottom: 10px;
    }
    .metric-value { font-size: 1.8rem; font-weight: 700; color: #1B5E20; }
    .metric-label { font-size: .85rem; color: #4CAF50; margin-top: 4px; }

    .seller-row {
        background: #fff; border-radius: 10px; padding: 14px;
        border-left: 4px solid #4CAF50; margin-bottom: 8px;
        box-shadow: 0 1px 4px rgba(0,0,0,0.06);
    }

    .badge-pending   { background:#FFF3E0; color:#E65100; padding:3px 10px; border-radius:20px; font-size:.8rem; font-weight:600; }
    .badge-processing{ background:#E3F2FD; color:#1565C0; padding:3px 10px; border-radius:20px; font-size:.8rem; font-weight:600; }
    .badge-shipped   { background:#EDE7F6; color:#4527A0; padding:3px 10px; border-radius:20px; font-size:.8rem; font-weight:600; }
    .badge-delivered { background:#E8F5E9; color:#1B5E20; padding:3px 10px; border-radius:20px; font-size:.8rem; font-weight:600; }
    .badge-cancelled { background:#FFEBEE; color:#B71C1C; padding:3px 10px; border-radius:20px; font-size:.8rem; font-weight:600; }
    .badge-accepted  { background:#E8F5E9; color:#1B5E20; padding:3px 10px; border-radius:20px; font-size:.8rem; font-weight:600; }
    .badge-rejected  { background:#FFEBEE; color:#B71C1C; padding:3px 10px; border-radius:20px; font-size:.8rem; font-weight:600; }
    .badge-open      { background:#E3F2FD; color:#1565C0; padding:3px 10px; border-radius:20px; font-size:.8rem; font-weight:600; }
    .badge-verified  { background:#E8F5E9; color:#1B5E20; padding:3px 10px; border-radius:20px; font-size:.8rem; font-weight:600; }
    .badge-unverified{ background:#FFF3E0; color:#E65100; padding:3px 10px; border-radius:20px; font-size:.8rem; font-weight:600; }

    .progress-bar-container { display:flex; justify-content:space-between; margin:10px 0; position:relative; }
    .progress-bar-container::before { content:''; position:absolute; top:15px; left:10%; right:10%; height:3px; background:#E8F5E9; z-index:0; }
    .progress-step { text-align:center; position:relative; z-index:1; flex:1; }
    .step-circle { width:32px; height:32px; border-radius:50%; background:#E8F5E9; border:2px solid #A5D6A7; display:inline-flex; align-items:center; justify-content:center; font-size:.85rem; font-weight:700; color:#4CAF50; }
    .step-circle.active { background:#2E7D32; border-color:#2E7D32; color:#fff; }
    .step-label { font-size:.75rem; color:#666; margin-top:6px; }
    .step-label.active { color:#2E7D32; font-weight:600; }

    .msg-sent { background:#DCF8C6; border-radius:12px 12px 2px 12px; padding:10px 14px; margin:4px 0; text-align:right; }
    .msg-recv { background:#fff; border:1px solid #E0E0E0; border-radius:12px 12px 12px 2px; padding:10px 14px; margin:4px 0; }
    .msg-time { font-size:.7rem; color:#999; margin-top:4px; }

    .page-title { font-size:1.8rem; font-weight:700; color:#1B5E20; margin-bottom:2px; }
    .page-subtitle { font-size:.95rem; color:#558B2F; margin-bottom:18px; }
    </style>
    """, unsafe_allow_html=True)


# ─────────────────────────────────────────────
# DATABASE
# ─────────────────────────────────────────────
DB_PATH = "farm2market.db"

def get_conn():
    return sqlite3.connect(DB_PATH)

def init_db():
    with get_conn() as conn:
        conn.cursor().executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            user_type TEXT NOT NULL,
            license_file BLOB,
            license_verified BOOLEAN DEFAULT FALSE
        );
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            seller_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            description TEXT,
            price REAL NOT NULL,
            quantity INTEGER NOT NULL,
            category TEXT DEFAULT 'Other',
            image BLOB,
            date_added DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (seller_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            product_id INTEGER,
            name TEXT, description TEXT, quantity INTEGER, price REAL,
            status TEXT DEFAULT 'pending',
            order_date DATETIME DEFAULT CURRENT_TIMESTAMP,
            image BLOB,
            shipping_name TEXT, shipping_email TEXT, shipping_phone TEXT,
            shipping_address TEXT, shipping_city TEXT, shipping_state TEXT,
            shipping_pincode TEXT, shipping_country TEXT DEFAULT 'India',
            payment_method TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (product_id) REFERENCES products(id)
        );
        CREATE TABLE IF NOT EXISTS cart (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL, product_id INTEGER NOT NULL, quantity INTEGER NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (product_id) REFERENCES products(id)
        );
        CREATE TABLE IF NOT EXISTS reviews (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            product_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
            rating INTEGER NOT NULL CHECK(rating BETWEEN 1 AND 5),
            comment TEXT, review_date DATETIME DEFAULT CURRENT_TIMESTAMP,
            seller_reply TEXT, reply_date DATETIME,
            FOREIGN KEY (product_id) REFERENCES products(id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS user_qr_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER UNIQUE NOT NULL, qr_code BLOB NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS wishlist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL, product_id INTEGER NOT NULL,
            added_date DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_id, product_id),
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (product_id) REFERENCES products(id)
        );
        CREATE TABLE IF NOT EXISTS offers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            product_id INTEGER NOT NULL, buyer_id INTEGER NOT NULL, seller_id INTEGER NOT NULL,
            offer_price REAL NOT NULL, quantity INTEGER NOT NULL DEFAULT 1,
            status TEXT DEFAULT 'pending', message TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (product_id) REFERENCES products(id),
            FOREIGN KEY (buyer_id) REFERENCES users(id),
            FOREIGN KEY (seller_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER NOT NULL, receiver_id INTEGER NOT NULL,
            product_id INTEGER, content TEXT NOT NULL,
            sent_at DATETIME DEFAULT CURRENT_TIMESTAMP, read_at DATETIME,
            FOREIGN KEY (sender_id) REFERENCES users(id),
            FOREIGN KEY (receiver_id) REFERENCES users(id)
        );
        """)
        conn.commit()


# ─────────────────────────────────────────────
# AUTH
# ─────────────────────────────────────────────
def hash_password(p: str) -> str:
    return hashlib.sha256(p.encode()).hexdigest()

def login_user(username, password):
    with get_conn() as conn:
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=? AND password=?", (username, hash_password(password)))
        return c.fetchone()

def register_user(username, password, user_type, license_file=None):
    if user_type == "seller" and not license_file:
        return False, "Seller registration requires a license document."
    with get_conn() as conn:
        c = conn.cursor()
        if user_type == "admin":
            c.execute("SELECT id FROM users WHERE user_type='admin'")
            if c.fetchone():
                return False, "An admin account already exists. Only one admin is allowed."
        c.execute("SELECT id FROM users WHERE username=?", (username,))
        if c.fetchone():
            return False, "Username already exists."
        lic = None
        if license_file:
            ext = license_file.name.split(".")[-1].lower()
            if ext not in ("pdf", "png", "jpg", "jpeg"):
                return False, "Invalid file type."
            if license_file.size > 5 * 1024 * 1024:
                return False, "File too large (max 5 MB)."
            lic = license_file.read()
        c.execute(
            "INSERT INTO users(username,password,user_type,license_file,license_verified) VALUES(?,?,?,?,?)",
            (username, hash_password(password), user_type, lic, user_type == "admin"),
        )
        conn.commit()
        return True, "Registration successful!"


# ─────────────────────────────────────────────
# PRODUCTS
# ─────────────────────────────────────────────
CATEGORIES = ["Crops", "Dairy", "Fruits", "Vegetables", "Spices", "Other"]

def get_products(seller_id=None, category=None, search=None, in_stock=True):
    with get_conn() as conn:
        c = conn.cursor()
        q = "SELECT * FROM products WHERE 1=1"
        params = []
        if in_stock:
            q += " AND quantity > 0"
        if seller_id:
            q += " AND seller_id=?"; params.append(seller_id)
        if category and category != "All":
            q += " AND category=?"; params.append(category)
        if search:
            q += " AND (name LIKE ? OR description LIKE ?)"; params += [f"%{search}%", f"%{search}%"]
        c.execute(q + " ORDER BY date_added DESC", params)
        return c.fetchall()

def add_product(seller_id, name, description, price, quantity, category, image=None):
    img = image.read() if image else None
    with get_conn() as conn:
        c = conn.cursor()
        c.execute("INSERT INTO products(seller_id,name,description,price,quantity,category,image,date_added) VALUES(?,?,?,?,?,?,?,?)",
                  (seller_id, name, description, price, quantity, category, img, datetime.now()))
        conn.commit()

def update_product(pid, name, description, price, quantity, category, image=None):
    with get_conn() as conn:
        c = conn.cursor()
        if image:
            c.execute("UPDATE products SET name=?,description=?,price=?,quantity=?,category=?,image=? WHERE id=?",
                      (name, description, price, quantity, category, image.read(), pid))
        else:
            c.execute("UPDATE products SET name=?,description=?,price=?,quantity=?,category=? WHERE id=?",
                      (name, description, price, quantity, category, pid))
        conn.commit()

def delete_product(pid):
    with get_conn() as conn:
        c = conn.cursor()
        c.execute("DELETE FROM reviews WHERE product_id=?", (pid,))
        c.execute("DELETE FROM cart WHERE product_id=?", (pid,))
        c.execute("DELETE FROM wishlist WHERE product_id=?", (pid,))
        c.execute("UPDATE orders SET description=description||' (Deleted)' WHERE product_id=?", (pid,))
        c.execute("DELETE FROM products WHERE id=?", (pid,))
        conn.commit()


# ─────────────────────────────────────────────
# CART
# ─────────────────────────────────────────────
def add_to_cart(user_id, product_id, quantity):
    with get_conn() as conn:
        c = conn.cursor()
        c.execute("SELECT quantity FROM products WHERE id=?", (product_id,))
        row = c.fetchone()
        if not row or row[0] < quantity:
            return False, "Not enough stock."
        c.execute("SELECT id,quantity FROM cart WHERE user_id=? AND product_id=?", (user_id, product_id))
        ex = c.fetchone()
        if ex:
            c.execute("UPDATE cart SET quantity=? WHERE id=?", (ex[1] + quantity, ex[0]))
        else:
            c.execute("INSERT INTO cart(user_id,product_id,quantity) VALUES(?,?,?)", (user_id, product_id, quantity))
        conn.commit()
        return True, "Added!"

def get_cart_items(user_id):
    with get_conn() as conn:
        c = conn.cursor()
        c.execute("""SELECT c.id,p.id,p.name,p.description,p.price,c.quantity,p.image,p.quantity
                     FROM cart c JOIN products p ON c.product_id=p.id WHERE c.user_id=?""", (user_id,))
        return c.fetchall()

def update_cart_qty(cart_id, qty):
    with get_conn() as conn:
        c = conn.cursor(); c.execute("UPDATE cart SET quantity=? WHERE id=?", (qty, cart_id)); conn.commit()

def remove_from_cart(cart_id):
    with get_conn() as conn:
        c = conn.cursor(); c.execute("DELETE FROM cart WHERE id=?", (cart_id,)); conn.commit()


# ─────────────────────────────────────────────
# ORDERS
# ─────────────────────────────────────────────
def place_order(user_id, cart_items, shipping, payment):
    with get_conn() as conn:
        c = conn.cursor()
        try:
            for item in cart_items:
                c_id, p_id, name, desc, price, qty, img, avail = item
                c.execute("""INSERT INTO orders
                    (user_id,product_id,name,description,quantity,price,status,image,
                     shipping_name,shipping_email,shipping_phone,shipping_address,
                     shipping_city,shipping_state,shipping_pincode,payment_method)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (user_id, p_id, name, desc, qty, float(price)*qty, "pending", img,
                     shipping["name"], shipping["email"], shipping["phone"], shipping["address"],
                     shipping["city"], shipping["state"], shipping["pincode"], payment))
                c.execute("UPDATE products SET quantity=quantity-? WHERE id=?", (qty, p_id))
            c.execute("DELETE FROM cart WHERE user_id=?", (user_id,))
            conn.commit()
            return True
        except Exception as e:
            conn.rollback(); logging.error(e); return False

def get_orders(user_id):
    with get_conn() as conn:
        c = conn.cursor()
        c.execute("""SELECT o.*,p.name FROM orders o LEFT JOIN products p ON o.product_id=p.id
                     WHERE o.user_id=? ORDER BY o.order_date DESC""", (user_id,))
        return c.fetchall()

def get_seller_orders(seller_id):
    with get_conn() as conn:
        c = conn.cursor()
        c.execute("""SELECT o.*,p.name FROM orders o JOIN products p ON o.product_id=p.id
                     WHERE p.seller_id=? ORDER BY o.order_date DESC""", (seller_id,))
        return c.fetchall()

def get_all_orders():
    with get_conn() as conn:
        c = conn.cursor()
        c.execute("""SELECT o.*,p.name,u.username,s.username FROM orders o
                     JOIN products p ON o.product_id=p.id
                     JOIN users u ON o.user_id=u.id
                     JOIN users s ON p.seller_id=s.id
                     ORDER BY o.order_date DESC""")
        return c.fetchall()

def update_order_status(order_id, status):
    with get_conn() as conn:
        c = conn.cursor(); c.execute("UPDATE orders SET status=? WHERE id=?", (status, order_id)); conn.commit()

def cancel_order(order_id, user_id):
    with get_conn() as conn:
        c = conn.cursor()
        c.execute("SELECT quantity,product_id,status FROM orders WHERE id=? AND user_id=?", (order_id, user_id))
        row = c.fetchone()
        if not row or row[2] not in ("pending", "processing"):
            return False
        c.execute("UPDATE orders SET status='cancelled' WHERE id=?", (order_id,))
        if row[1]:
            c.execute("UPDATE products SET quantity=quantity+? WHERE id=?", (row[0], row[1]))
        conn.commit()
        return True


# ─────────────────────────────────────────────
# REVIEWS
# ─────────────────────────────────────────────
def get_product_reviews(product_id):
    with get_conn() as conn:
        c = conn.cursor()
        c.execute("""SELECT r.*,u.username FROM reviews r JOIN users u ON r.user_id=u.id
                     WHERE r.product_id=? ORDER BY r.review_date DESC""", (product_id,))
        return c.fetchall()

def upsert_review(product_id, user_id, rating, comment):
    with get_conn() as conn:
        c = conn.cursor()
        c.execute("SELECT id FROM reviews WHERE product_id=? AND user_id=?", (product_id, user_id))
        ex = c.fetchone()
        if ex:
            c.execute("UPDATE reviews SET rating=?,comment=?,review_date=CURRENT_TIMESTAMP WHERE id=?", (rating, comment, ex[0]))
        else:
            c.execute("INSERT INTO reviews(product_id,user_id,rating,comment) VALUES(?,?,?,?)", (product_id, user_id, rating, comment))
        conn.commit()

def add_seller_reply(review_id, reply):
    with get_conn() as conn:
        c = conn.cursor()
        c.execute("UPDATE reviews SET seller_reply=?,reply_date=CURRENT_TIMESTAMP WHERE id=?", (reply, review_id))
        conn.commit()


# ─────────────────────────────────────────────
# WISHLIST
# ─────────────────────────────────────────────
def toggle_wishlist(user_id, product_id):
    with get_conn() as conn:
        c = conn.cursor()
        c.execute("SELECT id FROM wishlist WHERE user_id=? AND product_id=?", (user_id, product_id))
        if c.fetchone():
            c.execute("DELETE FROM wishlist WHERE user_id=? AND product_id=?", (user_id, product_id))
            conn.commit(); return False
        c.execute("INSERT INTO wishlist(user_id,product_id) VALUES(?,?)", (user_id, product_id))
        conn.commit(); return True

def in_wishlist(user_id, product_id):
    with get_conn() as conn:
        c = conn.cursor()
        c.execute("SELECT id FROM wishlist WHERE user_id=? AND product_id=?", (user_id, product_id))
        return c.fetchone() is not None

def get_wishlist(user_id):
    with get_conn() as conn:
        c = conn.cursor()
        c.execute("""SELECT p.* FROM wishlist w JOIN products p ON w.product_id=p.id
                     WHERE w.user_id=? ORDER BY w.added_date DESC""", (user_id,))
        return c.fetchall()


# ─────────────────────────────────────────────
# OFFERS
# ─────────────────────────────────────────────
def make_offer(product_id, buyer_id, seller_id, offer_price, quantity, message):
    with get_conn() as conn:
        c = conn.cursor()
        c.execute("INSERT INTO offers(product_id,buyer_id,seller_id,offer_price,quantity,message) VALUES(?,?,?,?,?,?)",
                  (product_id, buyer_id, seller_id, offer_price, quantity, message))
        conn.commit()

def get_offers_for_buyer(buyer_id):
    with get_conn() as conn:
        c = conn.cursor()
        c.execute("""SELECT o.*,p.name,u.username FROM offers o
                     JOIN products p ON o.product_id=p.id JOIN users u ON o.seller_id=u.id
                     WHERE o.buyer_id=? ORDER BY o.created_at DESC""", (buyer_id,))
        return c.fetchall()

def get_offers_for_seller(seller_id):
    with get_conn() as conn:
        c = conn.cursor()
        c.execute("""SELECT o.*,p.name,u.username FROM offers o
                     JOIN products p ON o.product_id=p.id JOIN users u ON o.buyer_id=u.id
                     WHERE o.seller_id=? ORDER BY o.created_at DESC""", (seller_id,))
        return c.fetchall()

def respond_offer(offer_id, status):
    with get_conn() as conn:
        c = conn.cursor()
        c.execute("UPDATE offers SET status=?,updated_at=CURRENT_TIMESTAMP WHERE id=?", (status, offer_id))
        conn.commit()


# ─────────────────────────────────────────────
# MESSAGES
# ─────────────────────────────────────────────
def send_message(sender_id, receiver_id, content, product_id=None):
    with get_conn() as conn:
        c = conn.cursor()
        c.execute("INSERT INTO messages(sender_id,receiver_id,product_id,content) VALUES(?,?,?,?)",
                  (sender_id, receiver_id, product_id, content))
        conn.commit()

def get_conversation(user_a, user_b):
    with get_conn() as conn:
        c = conn.cursor()
        c.execute("""SELECT * FROM messages
                     WHERE (sender_id=? AND receiver_id=?) OR (sender_id=? AND receiver_id=?)
                     ORDER BY sent_at ASC""", (user_a, user_b, user_b, user_a))
        msgs = c.fetchall()
        c.execute("UPDATE messages SET read_at=CURRENT_TIMESTAMP WHERE receiver_id=? AND sender_id=? AND read_at IS NULL",
                  (user_a, user_b))
        conn.commit()
        return msgs

def get_contacts(user_id):
    with get_conn() as conn:
        c = conn.cursor()
        c.execute("""SELECT DISTINCT u.id, u.username, u.user_type,
                     (SELECT COUNT(*) FROM messages m2 WHERE m2.sender_id=u.id AND m2.receiver_id=? AND m2.read_at IS NULL) as unread
                     FROM messages m
                     JOIN users u ON (CASE WHEN m.sender_id=? THEN m.receiver_id=u.id ELSE m.sender_id=u.id END)
                     WHERE m.sender_id=? OR m.receiver_id=?
                     ORDER BY unread DESC, u.username""", (user_id, user_id, user_id, user_id))
        return c.fetchall()

def get_unread_count(user_id):
    with get_conn() as conn:
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM messages WHERE receiver_id=? AND read_at IS NULL", (user_id,))
        return c.fetchone()[0]


# ─────────────────────────────────────────────
# QR CODES
# ─────────────────────────────────────────────
def generate_user_qr(user_id, username, user_type) -> bytes:
    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(f"farm2market://{user_id}:{username}:{user_type}")
    qr.make(fit=True)
    img = qr.make_image(fill_color="#1B5E20", back_color="white")
    buf = BytesIO(); img.save(buf, format="PNG"); return buf.getvalue()

def generate_product_qr(product_id, product_name, price) -> bytes:
    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(f"farm2market://product/{product_id}:{product_name}:{price}")
    qr.make(fit=True)
    img = qr.make_image(fill_color="#1B5E20", back_color="white")
    buf = BytesIO(); img.save(buf, format="PNG"); return buf.getvalue()

def save_user_qr(user_id):
    with get_conn() as conn:
        c = conn.cursor()
        c.execute("SELECT username,user_type FROM users WHERE id=?", (user_id,))
        row = c.fetchone()
        if not row: return False
        qr = generate_user_qr(user_id, row[0], row[1])
        c.execute("INSERT OR REPLACE INTO user_qr_codes(user_id,qr_code) VALUES(?,?)", (user_id, qr))
        conn.commit(); return True

def get_user_qr(user_id) -> Optional[bytes]:
    with get_conn() as conn:
        c = conn.cursor()
        c.execute("SELECT qr_code FROM user_qr_codes WHERE user_id=?", (user_id,))
        row = c.fetchone(); return row[0] if row else None


# ─────────────────────────────────────────────
# UTILITIES
# ─────────────────────────────────────────────
def render_image(image_bytes, width=None, use_container_width=False, caption=None):
    if not image_bytes: return
    try:
        st.image(Image.open(io.BytesIO(image_bytes)), width=width,
                 use_container_width=use_container_width, caption=caption)
    except Exception:
        pass

def status_badge(status: str) -> str:
    return f'<span class="badge-{status.lower()}">{status.upper()}</span>'

def _render_progress(status):
    steps = ["pending", "processing", "shipped", "delivered"]
    idx = steps.index(status) if status in steps else -1
    html = '<div class="progress-bar-container">'
    for i, s in enumerate(steps):
        active = "active" if i <= idx and idx >= 0 else ""
        html += (f'<div class="progress-step">'
                 f'<div class="step-circle {active}">{"✓" if i <= idx and idx >= 0 else i+1}</div>'
                 f'<div class="step-label {active}">{s.title()}</div></div>')
    st.markdown(html + "</div>", unsafe_allow_html=True)


# ─────────────────────────────────────────────
# SESSION
# ─────────────────────────────────────────────
def init_session():
    for k, v in {
        "user": None, "current_page": "Login",
        "checkout_cart_items": None, "editing_product_id": None,
        "msg_contact_id": None,
    }.items():
        if k not in st.session_state:
            st.session_state[k] = v

def _nav_btn(label, page, **kwargs):
    if st.button(label, **kwargs):
        st.session_state.current_page = page

def nav_to(page):
    st.session_state.current_page = page
    st.rerun()


# ═══════════════════════════════════════════════
# PAGES
# ═══════════════════════════════════════════════

# ─────────────────────────────────────────────
# LOGIN / REGISTER
# ─────────────────────────────────────────────
def show_login():
    col1, col2, col3 = st.columns([1, 1.4, 1])
    with col2:
        st.markdown('<div style="text-align:center;margin-bottom:24px;">'
                    '<div style="font-size:3rem;">🌾</div>'
                    '<h1 style="color:#1B5E20;margin:0;">Farm2Market</h1>'
                    '<p style="color:#558B2F;">Fresh from farm to your table</p></div>',
                    unsafe_allow_html=True)
        with st.form("login_form"):
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            ca, cb = st.columns(2)
            with ca: submit = st.form_submit_button("🔐 Login", use_container_width=True, type="primary")
            with cb: go_reg = st.form_submit_button("📝 Register", use_container_width=True)
        if submit:
            if not username or not password:
                st.error("Please enter username and password.")
            else:
                user = login_user(username, password)
                if user:
                    st.session_state.user = user
                    st.success(f"Welcome back, {user[1]}! 👋")
                    time.sleep(0.8); st.rerun()
                else:
                    st.error("Invalid username or password.")
        if go_reg:
            nav_to("Register")

def show_register():
    col1, col2, col3 = st.columns([1, 1.4, 1])
    with col2:
        st.markdown('<h2 style="color:#1B5E20;">Create Account</h2>', unsafe_allow_html=True)
        with st.form("register_form"):
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            confirm  = st.text_input("Confirm Password", type="password")
            user_type = st.selectbox("Account Type", ["buyer", "seller", "admin"])
            lic = None
            if user_type == "seller":
                st.info("📄 Sellers must upload a license (PDF/image, max 5 MB).")
                lic = st.file_uploader("License Document", type=["pdf","png","jpg","jpeg"])
            submitted = st.form_submit_button("Create Account", use_container_width=True, type="primary")
        if submitted:
            if not all([username, password, confirm]):
                st.error("All fields required.")
            elif password != confirm:
                st.error("Passwords don't match.")
            elif user_type == "seller" and not lic:
                st.error("Please upload license.")
            else:
                ok, msg = register_user(username, password, user_type, lic)
                if ok:
                    st.success(msg + " Please log in."); time.sleep(1); nav_to("Login")
                else:
                    st.error(msg)
        if st.button("← Back to Login"):
            nav_to("Login")


# ─────────────────────────────────────────────
# MARKETPLACE
# ─────────────────────────────────────────────
def show_marketplace():
    st.markdown('<p class="page-title">🛒 Marketplace</p>', unsafe_allow_html=True)
    st.markdown('<p class="page-subtitle">Fresh produce directly from local farmers</p>', unsafe_allow_html=True)

    col1, col2, col3 = st.columns([3, 1.5, 1.5])
    with col1: search = st.text_input("🔍 Search", placeholder="tomatoes, rice…", label_visibility="collapsed")
    with col2: cat = st.selectbox("Category", ["All"] + CATEGORIES, label_visibility="collapsed")
    with col3: sort = st.selectbox("Sort", ["Newest", "Price ↑", "Price ↓"], label_visibility="collapsed")

    products = get_products(category=cat, search=search)
    if sort == "Price ↑": products = sorted(products, key=lambda p: p[4])
    elif sort == "Price ↓": products = sorted(products, key=lambda p: p[4], reverse=True)

    if not products:
        st.info("No products found."); return

    user = st.session_state.user
    is_buyer = user and user[3] == "buyer"
    cols = st.columns(3, gap="medium")

    for idx, p in enumerate(products):
        pid, seller_id, name, desc, price, qty, category, img, _ = p[:9]
        with cols[idx % 3]:
            if img:
                render_image(img, use_container_width=True)
            else:
                st.markdown('<div style="background:#E8F5E9;height:130px;border-radius:8px;'
                            'display:flex;align-items:center;justify-content:center;font-size:2.5rem;">🌿</div>',
                            unsafe_allow_html=True)
            reviews = get_product_reviews(pid)
            avg_str = f"⭐ {sum(r[3] for r in reviews)/len(reviews):.1f} ({len(reviews)})" if reviews else "No reviews"
            st.markdown(f"**{name}**  `{category}`")
            st.caption(avg_str)
            st.markdown(f"**₹{price:.2f}**  —  {qty} in stock")

            if is_buyer:
                a1, a2, a3 = st.columns(3)
                with a1:
                    q_val = st.number_input("", 1, qty, 1, key=f"q_{pid}", label_visibility="collapsed")
                with a2:
                    if st.button("🛒", key=f"c_{pid}", help="Add to cart"):
                        ok, msg = add_to_cart(user[0], pid, q_val)
                        st.toast("✅ Added to cart!" if ok else msg)
                with a3:
                    icon = "❤️" if in_wishlist(user[0], pid) else "🤍"
                    if st.button(icon, key=f"w_{pid}", help="Wishlist"):
                        added = toggle_wishlist(user[0], pid)
                        st.toast("❤️ Saved!" if added else "💔 Removed.")
                        st.rerun()

            with st.expander("💬 Reviews & Offers"):
                _reviews_inline(pid, seller_id)
                if is_buyer:
                    _offer_inline(pid, seller_id)
            st.divider()


def _reviews_inline(product_id, seller_id):
    reviews = get_product_reviews(product_id)
    user = st.session_state.user
    is_owner = user and user[3] == "seller" and user[0] == seller_id
    is_buyer = user and user[3] == "buyer"
    if reviews:
        avg = sum(r[3] for r in reviews) / len(reviews)
        st.caption(f"⭐ {avg:.1f}/5 — {len(reviews)} review(s)")
        for r in reviews[:3]:
            st.markdown(f"{'⭐'*r[3]} **{r[-1]}** — {r[4] or ''}")
            if r[6]: st.caption(f"↳ Seller: {r[6]}")
            elif is_owner:
                with st.form(f"rp_{r[0]}"):
                    rep = st.text_input("Reply", key=f"rpt_{r[0]}")
                    if st.form_submit_button("Reply"):
                        add_seller_reply(r[0], rep); st.rerun()
    else:
        st.caption("No reviews yet.")
    if is_buyer:
        with st.form(f"rv_{product_id}"):
            rating = st.slider("Rating", 1, 5, 5, key=f"rat_{product_id}")
            comment = st.text_area("Comment", key=f"cmt_{product_id}")
            if st.form_submit_button("Submit Review"):
                upsert_review(product_id, user[0], rating, comment)
                st.success("Review submitted!"); st.rerun()


def _offer_inline(product_id, seller_id):
    with get_conn() as conn:
        c = conn.cursor(); c.execute("SELECT price FROM products WHERE id=?", (product_id,))
        row = c.fetchone()
    if not row: return
    user = st.session_state.user
    st.markdown("**💰 Make an Offer**")
    with st.form(f"of_{product_id}"):
        op = st.number_input("Your price (₹)", min_value=0.01, value=round(row[0]*0.9, 2), step=1.0, key=f"ofp_{product_id}")
        oq = st.number_input("Quantity", min_value=1, value=1, key=f"ofq_{product_id}")
        om = st.text_input("Note to seller", key=f"ofm_{product_id}")
        if st.form_submit_button("Send Offer"):
            if op >= row[0]:
                st.info("Offer is at listed price — just add to cart!")
            else:
                make_offer(product_id, user[0], seller_id, op, oq, om)
                st.success("Offer sent!")


# ─────────────────────────────────────────────
# CART
# ─────────────────────────────────────────────
def show_cart():
    st.markdown('<p class="page-title">🛒 My Cart</p>', unsafe_allow_html=True)
    user = st.session_state.user
    if not user: st.error("Please log in."); return
    items = get_cart_items(user[0])
    if not items:
        st.info("Your cart is empty.")
        if st.button("🛍️ Browse Marketplace", type="primary"): nav_to("Marketplace")
        return
    total = 0.0
    for item in items:
        c_id, p_id, name, desc, price, qty, img, avail = item
        st.markdown('<div class="f2m-card">', unsafe_allow_html=True)
        col1, col2, col3 = st.columns([1, 3, 1.5])
        with col1: render_image(img, width=90)
        with col2:
            st.markdown(f"**{name}**")
            st.caption(desc[:80] + "…" if desc and len(desc) > 80 else (desc or ""))
            st.markdown(f"₹{float(price):.2f} each")
            nq = st.number_input("Qty", 1, avail, qty, key=f"cq_{c_id}", label_visibility="collapsed")
            if nq != qty: update_cart_qty(c_id, nq); st.rerun()
        with col3:
            sub = float(price) * qty; total += sub
            st.markdown(f"**₹{sub:.2f}**")
            if st.button("🗑️", key=f"rm_{c_id}"): remove_from_cart(c_id); st.rerun()
        st.markdown('</div>', unsafe_allow_html=True)
    st.markdown("---")
    ca, cb, cc = st.columns([2, 1, 1])
    with ca: st.markdown(f"### Total: ₹{total:.2f}")
    with cb:
        if st.button("Continue Shopping", use_container_width=True): nav_to("Marketplace")
    with cc:
        if st.button("✅ Checkout", type="primary", use_container_width=True):
            st.session_state.checkout_cart_items = get_cart_items(user[0])
            nav_to("Checkout")


# ─────────────────────────────────────────────
# CHECKOUT
# ─────────────────────────────────────────────
def show_checkout():
    cart_items = st.session_state.get("checkout_cart_items")
    if not cart_items: nav_to("My Cart"); return
    st.markdown('<p class="page-title">✅ Checkout</p>', unsafe_allow_html=True)
    total = sum(float(i[4]) * i[5] for i in cart_items)
    col1, col2 = st.columns([1.4, 1])
    with col1:
        st.subheader("Shipping Information")
        with st.form("chk_form"):
            name  = st.text_input("Full Name *")
            email = st.text_input("Email *")
            phone = st.text_input("Phone *")
            addr  = st.text_area("Delivery Address *")
            c1, c2, c3 = st.columns(3)
            with c1: city    = st.text_input("City *")
            with c2: state   = st.text_input("State *")
            with c3: pincode = st.text_input("PIN Code *")
            payment = st.selectbox("Payment", ["Cash on Delivery", "UPI", "Net Banking", "Card Payment"])
            terms   = st.checkbox("I agree to terms and conditions *")
            submit  = st.form_submit_button("🛒 Place Order", use_container_width=True, type="primary")
    with col2:
        st.subheader("Order Summary")
        for item in cart_items:
            st.markdown(f"**{item[2]}** × {item[5]} = ₹{float(item[4])*item[5]:.2f}")
        st.markdown("---"); st.markdown(f"### Total: ₹{total:.2f}")
    if submit:
        errs = []
        if not all([name, email, phone, addr, city, state, pincode]): errs.append("Fill all required fields.")
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email): errs.append("Invalid email.")
        if not re.match(r"^\d{6}$", pincode): errs.append("PIN code must be 6 digits.")
        if not terms: errs.append("Accept the terms.")
        for e in errs: st.error(e)
        if not errs:
            shipping = {"name": name, "email": email, "phone": phone,
                        "address": addr, "city": city, "state": state, "pincode": pincode}
            if place_order(st.session_state.user[0], cart_items, shipping, payment):
                st.success("🎉 Order placed!"); st.balloons()
                st.session_state.checkout_cart_items = None
                time.sleep(2); nav_to("My Orders")
            else:
                st.error("Error placing order.")


# ─────────────────────────────────────────────
# BUYER ORDERS
# ─────────────────────────────────────────────
def show_orders():
    st.markdown('<p class="page-title">📦 My Orders</p>', unsafe_allow_html=True)
    user = st.session_state.user
    if not user: st.error("Please log in."); return
    orders = get_orders(user[0])
    if not orders: st.info("No orders yet."); return
    sf = st.selectbox("Filter", ["All", "pending", "processing", "shipped", "delivered", "cancelled"])
    for order in orders:
        oid, uid, pid, name, desc, qty, price, status = order[:8]
        pname = order[-1] or name
        if sf != "All" and status != sf: continue
        st.markdown('<div class="f2m-card">', unsafe_allow_html=True)
        c1, c2, c3 = st.columns([2, 2, 1])
        with c1:
            st.markdown(f"**Order #{oid}** — {pname}")
            st.caption(f"Placed: {order[8]}")
            st.markdown(f"Qty: {qty}  |  Total: ₹{float(price):.2f}")
        with c2: _render_progress(status)
        with c3:
            st.markdown(status_badge(status), unsafe_allow_html=True)
            if status in ("pending", "processing"):
                if st.button("Cancel", key=f"can_{oid}"):
                    if cancel_order(oid, user[0]): st.success("Cancelled."); st.rerun()
        st.markdown('</div>', unsafe_allow_html=True)


# ─────────────────────────────────────────────
# WISHLIST
# ─────────────────────────────────────────────
def show_wishlist():
    st.markdown('<p class="page-title">❤️ My Wishlist</p>', unsafe_allow_html=True)
    user = st.session_state.user
    if not user: st.error("Please log in."); return
    items = get_wishlist(user[0])
    if not items:
        st.info("Wishlist is empty. Click 🤍 on any product to save it."); return
    cols = st.columns(3, gap="medium")
    for idx, p in enumerate(items):
        pid, _, name, desc, price, qty, cat, img, _ = p[:9]
        with cols[idx % 3]:
            render_image(img, use_container_width=True)
            st.markdown(f"**{name}**  |  ₹{price:.2f}")
            ca, cb = st.columns(2)
            with ca:
                if st.button("🛒 Cart", key=f"wc_{pid}", use_container_width=True):
                    ok, msg = add_to_cart(user[0], pid, 1)
                    st.toast("✅ Added!" if ok else msg)
            with cb:
                if st.button("💔 Remove", key=f"wr_{pid}", use_container_width=True):
                    toggle_wishlist(user[0], pid); st.rerun()


# ─────────────────────────────────────────────
# BUYER OFFERS
# ─────────────────────────────────────────────
def show_my_offers():
    st.markdown('<p class="page-title">💰 My Offers</p>', unsafe_allow_html=True)
    user = st.session_state.user
    if not user: return
    offers = get_offers_for_buyer(user[0])
    if not offers:
        st.info("No offers made yet. Browse the marketplace and make an offer."); return
    for o in offers:
        oid, pid, bid, sid, op, oq, status, msg, created, updated, pname, sname = o
        st.markdown('<div class="f2m-card">', unsafe_allow_html=True)
        c1, c2 = st.columns([3, 1])
        with c1:
            st.markdown(f"**{pname}** — ₹{op:.2f} × {oq}")
            st.caption(f"Seller: {sname}  |  Sent: {created}")
            if msg: st.caption(f"Your note: {msg}")
        with c2:
            st.markdown(status_badge(status), unsafe_allow_html=True)
            if status == "accepted": st.success("Accepted! Add to cart to buy.")
        st.markdown('</div>', unsafe_allow_html=True)


# ─────────────────────────────────────────────
# MESSAGES
# ─────────────────────────────────────────────
def show_messages():
    st.markdown('<p class="page-title">💬 Messages</p>', unsafe_allow_html=True)
    user = st.session_state.user
    if not user: st.error("Please log in."); return
    contacts = get_contacts(user[0])
    col1, col2 = st.columns([1, 2.5])
    with col1:
        st.markdown("**Conversations**")
        if not contacts:
            st.caption("No conversations yet.")
        for contact in contacts:
            cid, cname, ctype, unread = contact
            lbl = f"{'🔴 ' if unread else ''}{cname}"
            if st.button(lbl, key=f"ct_{cid}", use_container_width=True):
                st.session_state.msg_contact_id = cid
                st.rerun()
    with col2:
        cid = st.session_state.msg_contact_id
        if not cid:
            st.info("Select a conversation."); return
        with get_conn() as conn:
            cur = conn.cursor(); cur.execute("SELECT username FROM users WHERE id=?", (cid,))
            row = cur.fetchone()
        cname = row[0] if row else "Unknown"
        st.markdown(f"**Chat with {cname}**")
        for m in get_conversation(user[0], cid):
            mid, sid, rid, _, content, sent_at, _ = m[:7]
            if sid == user[0]:
                st.markdown(f'<div class="msg-sent">{content}<div class="msg-time">{sent_at}</div></div>', unsafe_allow_html=True)
            else:
                st.markdown(f'<div class="msg-recv">{content}<div class="msg-time">{sent_at}</div></div>', unsafe_allow_html=True)
        with st.form("mf", clear_on_submit=True):
            txt = st.text_input("Type…", label_visibility="collapsed")
            if st.form_submit_button("Send ➤", use_container_width=True):
                if txt.strip(): send_message(user[0], cid, txt.strip()); st.rerun()


# ─────────────────────────────────────────────
# SELLER DASHBOARD
# ─────────────────────────────────────────────
def show_seller_dashboard():
    st.markdown('<p class="page-title">📊 Seller Dashboard</p>', unsafe_allow_html=True)
    user = st.session_state.user
    if not user or user[3] != "seller": st.error("Access denied."); return
    if not _seller_is_verified(user[0]): return

    with get_conn() as conn:
        c = conn.cursor()
        c.execute("SELECT COUNT(*), COALESCE(SUM(quantity),0) FROM products WHERE seller_id=?", (user[0],))
        prod_count, total_stock = c.fetchone()
        c.execute("""SELECT COUNT(*), COALESCE(SUM(price),0) FROM orders o
                     JOIN products p ON o.product_id=p.id
                     WHERE p.seller_id=? AND o.status!='cancelled'""", (user[0],))
        order_count, revenue = c.fetchone()
        c.execute("""SELECT COUNT(*) FROM orders o JOIN products p ON o.product_id=p.id
                     WHERE p.seller_id=? AND o.status='pending'""", (user[0],))
        pending = c.fetchone()[0]

    c1, c2, c3, c4 = st.columns(4)
    for col, val, label in [
        (c1, prod_count or 0, "Products Listed"),
        (c2, order_count or 0, "Total Orders"),
        (c3, f"₹{float(revenue or 0):,.0f}", "Revenue"),
        (c4, pending or 0, "Pending Orders"),
    ]:
        col.markdown(f'<div class="metric-card"><div class="metric-value">{val}</div>'
                     f'<div class="metric-label">{label}</div></div>', unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)
    col1, col2 = st.columns(2)
    with col1:
        st.subheader("Revenue by Product")
        with get_conn() as conn:
            c = conn.cursor()
            c.execute("""SELECT p.name, COALESCE(SUM(o.price),0) FROM products p
                         LEFT JOIN orders o ON o.product_id=p.id AND o.status!='cancelled'
                         WHERE p.seller_id=? GROUP BY p.id ORDER BY 2 DESC LIMIT 10""", (user[0],))
            rows = c.fetchall()
        if rows:
            import pandas as pd
            st.bar_chart(pd.DataFrame(rows, columns=["Product","Revenue (₹)"]).set_index("Product"))
        else:
            st.info("No sales data yet.")
    with col2:
        st.subheader("Orders by Status")
        with get_conn() as conn:
            c = conn.cursor()
            c.execute("""SELECT o.status, COUNT(*) FROM orders o JOIN products p ON o.product_id=p.id
                         WHERE p.seller_id=? GROUP BY o.status""", (user[0],))
            rows = c.fetchall()
        if rows:
            import pandas as pd
            st.bar_chart(pd.DataFrame(rows, columns=["Status","Count"]).set_index("Status"))
        else:
            st.info("No orders yet.")

    st.subheader("Recent Orders")
    for o in get_seller_orders(user[0])[:5]:
        st.markdown(f'<div class="f2m-card"><b>Order #{o[0]}</b> — {o[-1] or o[3]} &nbsp;'
                    + status_badge(o[7]) +
                    f'<br><small>Qty: {o[5]} | ₹{float(o[6]):.2f}</small></div>', unsafe_allow_html=True)


def _seller_is_verified(user_id) -> bool:
    with get_conn() as conn:
        c = conn.cursor()
        c.execute("SELECT license_verified FROM users WHERE id=?", (user_id,))
        row = c.fetchone()
    if row and not row[0]:
        st.warning("⏳ Your seller account is pending admin verification.")
        return False
    return True


# ─────────────────────────────────────────────
# SELLER PRODUCTS
# ─────────────────────────────────────────────
def show_seller_products():
    st.markdown('<p class="page-title">📦 My Products</p>', unsafe_allow_html=True)
    user = st.session_state.user
    if not user or user[3] != "seller": st.error("Access denied."); return
    if not _seller_is_verified(user[0]): return
    if st.button("➕ Add New Product", type="primary"): nav_to("Add Product")
    products = get_products(seller_id=user[0], in_stock=False)
    if not products: st.info("No products yet."); return
    for p in products:
        pid, sid, name, desc, price, qty, cat, img, _ = p[:9]
        st.markdown('<div class="f2m-card">', unsafe_allow_html=True)
        c1, c2, c3, c4 = st.columns([1, 2.5, 1.5, 1])
        with c1: render_image(img, width=80)
        with c2:
            st.markdown(f"**{name}** — {cat}")
            st.caption((desc or "")[:100])
        with c3:
            st.markdown(f"₹{price:.2f}  |  Stock: {qty}")
            if st.button("📲 QR", key=f"pqr_{pid}"):
                qb = generate_product_qr(pid, name, price)
                st.image(Image.open(BytesIO(qb)), width=120)
        with c4:
            if st.button("✏️ Edit", key=f"ed_{pid}"):
                st.session_state.editing_product_id = pid; nav_to("Edit Product")
            if st.button("🗑️ Del", key=f"dl_{pid}"):
                delete_product(pid); st.success("Deleted."); st.rerun()
        st.markdown('</div>', unsafe_allow_html=True)


# ─────────────────────────────────────────────
# ADD / EDIT PRODUCT
# ─────────────────────────────────────────────
def show_add_product():
    st.markdown('<p class="page-title">➕ Add Product</p>', unsafe_allow_html=True)
    user = st.session_state.user
    if not user or user[3] != "seller": st.error("Access denied."); return
    if st.button("← Back"): nav_to("My Products")
    with st.form("add_p", clear_on_submit=True):
        name = st.text_input("Product Name *")
        desc = st.text_area("Description *")
        c1, c2, c3 = st.columns(3)
        with c1: price = st.number_input("Price (₹)*", min_value=0.01, value=10.0, step=1.0)
        with c2: qty   = st.number_input("Quantity *", min_value=1, value=10)
        with c3: cat   = st.selectbox("Category *", CATEGORIES)
        img  = st.file_uploader("Image", type=["png","jpg","jpeg"])
        sub  = st.form_submit_button("Add Product", type="primary", use_container_width=True)
    if sub:
        if not name or not desc: st.error("Name and description required.")
        else:
            add_product(user[0], name, desc, price, qty, cat, img)
            st.success(f"✅ '{name}' added!"); time.sleep(1); nav_to("My Products")

def show_edit_product():
    st.markdown('<p class="page-title">✏️ Edit Product</p>', unsafe_allow_html=True)
    user = st.session_state.user
    pid  = st.session_state.get("editing_product_id")
    if not pid or not user or user[3] != "seller":
        st.error("No product selected."); nav_to("My Products"); return
    if st.button("← Back"): nav_to("My Products")
    with get_conn() as conn:
        c = conn.cursor(); c.execute("SELECT * FROM products WHERE id=? AND seller_id=?", (pid, user[0]))
        p = c.fetchone()
    if not p: st.error("Product not found."); return
    _, _, cn, cd, cp, cq, cc, ci, _ = p[:9]
    with st.form("edit_p"):
        name = st.text_input("Product Name *", value=cn)
        desc = st.text_area("Description *", value=cd or "")
        c1, c2, c3 = st.columns(3)
        with c1: price = st.number_input("Price (₹)*", min_value=0.01, value=float(cp), step=1.0)
        with c2: qty   = st.number_input("Quantity *", min_value=0, value=int(cq))
        with c3:
            cat_idx = CATEGORIES.index(cc) if cc in CATEGORIES else 0
            cat = st.selectbox("Category *", CATEGORIES, index=cat_idx)
        if ci: st.caption("Current image:"); render_image(ci, width=120)
        img = st.file_uploader("Replace image (optional)", type=["png","jpg","jpeg"])
        sub = st.form_submit_button("Save Changes", type="primary", use_container_width=True)
    if sub:
        if not name or not desc: st.error("Required fields missing.")
        else:
            update_product(pid, name, desc, price, qty, cat, img)
            st.success("Updated!"); time.sleep(1); nav_to("My Products")


# ─────────────────────────────────────────────
# SELLER ORDERS
# ─────────────────────────────────────────────
def show_seller_orders():
    st.markdown('<p class="page-title">📋 My Orders</p>', unsafe_allow_html=True)
    user = st.session_state.user
    if not user or user[3] != "seller": st.error("Access denied."); return
    orders = get_seller_orders(user[0])
    if not orders: st.info("No orders yet."); return
    rev = sum(float(o[6]) for o in orders if o[7] != "cancelled")
    c1, c2, c3 = st.columns(3)
    c1.metric("Total Orders", len(orders))
    c2.metric("Active", sum(1 for o in orders if o[7] not in ("cancelled","delivered")))
    c3.metric("Revenue", f"₹{rev:,.2f}")
    sf = st.selectbox("Filter", ["All","pending","processing","shipped","delivered","cancelled"])
    for o in orders:
        oid, uid, pid, name, desc, qty, price, status = o[:8]
        pname = o[-1] or name
        if sf != "All" and status != sf: continue
        st.markdown('<div class="f2m-card">', unsafe_allow_html=True)
        c1, c2, c3 = st.columns([2, 2, 1.5])
        with c1:
            st.markdown(f"**Order #{oid}** — {pname}")
            st.caption(f"Qty: {qty}  |  ₹{float(price):.2f}")
            if len(o) > 10 and o[10]: st.caption(f"Ship to: {o[10]}, {o[14] if len(o)>14 else ''}")
        with c2:
            if status not in ("cancelled","delivered"):
                ns = st.selectbox("Update", ["processing","shipped","delivered"], key=f"ns_{oid}")
                if st.button("Update", key=f"upd_{oid}"):
                    update_order_status(oid, ns); st.success(f"→ {ns}"); st.rerun()
        with c3:
            st.markdown(status_badge(status), unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)


# ─────────────────────────────────────────────
# SELLER OFFERS
# ─────────────────────────────────────────────
def show_seller_offers():
    st.markdown('<p class="page-title">💰 Incoming Offers</p>', unsafe_allow_html=True)
    user = st.session_state.user
    if not user or user[3] != "seller": st.error("Access denied."); return
    offers = get_offers_for_seller(user[0])
    if not offers: st.info("No offers yet."); return
    for o in offers:
        oid, pid, bid, sid, op, oq, status, msg, created, updated, pname, bname = o
        st.markdown('<div class="f2m-card">', unsafe_allow_html=True)
        c1, c2 = st.columns([3, 1])
        with c1:
            st.markdown(f"**{pname}** — ₹{op:.2f} × {oq}")
            st.caption(f"From: {bname}  |  {created}")
            if msg: st.caption(f"Note: {msg}")
            with get_conn() as conn:
                cur = conn.cursor(); cur.execute("SELECT price FROM products WHERE id=?", (pid,))
                row = cur.fetchone()
            if row:
                st.caption(f"Listed: ₹{row[0]:.2f}  →  Offer is {(op/row[0])*100:.0f}% of listed")
        with c2:
            if status == "pending":
                if st.button("✅ Accept", key=f"acc_{oid}", type="primary"):
                    respond_offer(oid, "accepted"); st.rerun()
                if st.button("❌ Reject", key=f"rej_{oid}"):
                    respond_offer(oid, "rejected"); st.rerun()
            else:
                st.markdown(status_badge(status), unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)


# ─────────────────────────────────────────────
# QR PAGES
# ─────────────────────────────────────────────
def show_my_qr():
    st.markdown('<p class="page-title">📱 My QR Code</p>', unsafe_allow_html=True)
    user = st.session_state.user
    if not user: st.error("Please log in."); return
    qr = get_user_qr(user[0])
    if not qr: save_user_qr(user[0]); qr = get_user_qr(user[0])
    col1, col2 = st.columns([1, 2])
    with col1:
        if qr:
            st.image(Image.open(BytesIO(qr)), width=200)
            buf = BytesIO(); Image.open(BytesIO(qr)).save(buf, format="PNG")
            st.download_button("⬇️ Download", buf.getvalue(), "my_qr.png", "image/png")
    with col2:
        st.markdown("### How to use\n- Share to let others find your profile\n- Sellers: put it on your stall or packaging\n- Buyers: share with sellers to connect quickly")

def show_qr_scanner():
    st.markdown('<p class="page-title">📷 QR Scanner</p>', unsafe_allow_html=True)
    up = st.file_uploader("Upload QR image", type=["png","jpg","jpeg"])
    if not up: return
    st.image(Image.open(up), width=280)
    up.seek(0)
    fb = np.frombuffer(up.read(), np.uint8)
    img_cv = cv2.imdecode(fb, cv2.IMREAD_COLOR)
    ret, info, _, _ = cv2.QRCodeDetector().detectAndDecodeMulti(img_cv)
    if ret and info and info[0]:
        text = info[0]
        st.success(f"Decoded: `{text}`")
        if "product/" in text:
            parts = text.split("product/")[1].split(":")
            if len(parts) >= 2:
                st.markdown(f"**Product:** {parts[1]}  |  **Price:** ₹{parts[2] if len(parts)>2 else '?'}")
        elif text.startswith("farm2market://"):
            parts = text.split("://")[1].split(":")
            if len(parts) >= 3:
                st.markdown(f"**User:** {parts[1]} ({parts[2]})")
    else:
        st.error("No QR code detected. Ensure the image is clear and fully visible.")


# ─────────────────────────────────────────────
# ADMIN PANEL  ★ comprehensive
# ─────────────────────────────────────────────
def show_admin_panel():
    st.markdown('<p class="page-title">⚙️ Admin Panel</p>', unsafe_allow_html=True)
    user = st.session_state.user
    if not user or user[3] != "admin":
        st.error("Access denied."); return

    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "📊 Overview",
        "🏪 Seller Performance",
        "✅ Seller Verification",
        "👥 User Management",
        "📦 All Orders",
    ])

    with tab1: _admin_overview()
    with tab2: _admin_seller_performance()
    with tab3: _admin_verification()
    with tab4: _admin_users()
    with tab5: _admin_orders()


# ── Tab 1: Overview ──────────────────────────
def _admin_overview():
    with get_conn() as conn:
        c = conn.cursor()

        c.execute("SELECT COUNT(*) FROM users WHERE user_type='buyer'")
        buyers = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM users WHERE user_type='seller'")
        sellers = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM products WHERE quantity > 0")
        active_products = c.fetchone()[0]
        c.execute("SELECT COUNT(*), COALESCE(SUM(price),0) FROM orders WHERE status != 'cancelled'")
        total_orders, total_revenue = c.fetchone()
        c.execute("SELECT COUNT(*) FROM orders WHERE status='pending'")
        pending_orders = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM users WHERE user_type='seller' AND license_verified=0")
        pending_sellers = c.fetchone()[0]

    # Top-level metrics
    st.subheader("Marketplace Overview")
    cols = st.columns(6)
    for col, val, label in [
        (cols[0], buyers, "Buyers"),
        (cols[1], sellers, "Sellers"),
        (cols[2], active_products, "Active Products"),
        (cols[3], total_orders, "Total Orders"),
        (cols[4], f"₹{float(total_revenue):,.0f}", "Total Revenue"),
        (cols[5], pending_sellers, "Pending Verifications"),
    ]:
        col.markdown(f'<div class="metric-card"><div class="metric-value">{val}</div>'
                     f'<div class="metric-label">{label}</div></div>', unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    import pandas as pd
    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Revenue by Category")
        with get_conn() as conn:
            c = conn.cursor()
            c.execute("""SELECT p.category, COALESCE(SUM(o.price),0) as rev
                         FROM products p LEFT JOIN orders o ON o.product_id=p.id AND o.status!='cancelled'
                         GROUP BY p.category ORDER BY rev DESC""")
            rows = c.fetchall()
        if rows:
            df = pd.DataFrame(rows, columns=["Category","Revenue (₹)"]).set_index("Category")
            st.bar_chart(df)
        else:
            st.info("No data yet.")

    with col2:
        st.subheader("Orders by Status")
        with get_conn() as conn:
            c = conn.cursor()
            c.execute("SELECT status, COUNT(*) FROM orders GROUP BY status")
            rows = c.fetchall()
        if rows:
            df = pd.DataFrame(rows, columns=["Status","Count"]).set_index("Status")
            st.bar_chart(df)
        else:
            st.info("No orders yet.")

    st.subheader("Top 10 Best-Selling Products")
    with get_conn() as conn:
        c = conn.cursor()
        c.execute("""SELECT p.name, p.category,
                     COUNT(o.id) as order_count,
                     COALESCE(SUM(o.quantity),0) as units_sold,
                     COALESCE(SUM(o.price),0) as revenue,
                     s.username as seller
                     FROM products p
                     LEFT JOIN orders o ON o.product_id=p.id AND o.status!='cancelled'
                     JOIN users s ON p.seller_id=s.id
                     GROUP BY p.id ORDER BY revenue DESC LIMIT 10""")
        rows = c.fetchall()
    if rows:
        df = pd.DataFrame(rows, columns=["Product","Category","Orders","Units Sold","Revenue (₹)","Seller"])
        df["Revenue (₹)"] = df["Revenue (₹)"].apply(lambda x: f"₹{float(x):,.2f}")
        st.dataframe(df, use_container_width=True, hide_index=True)
    else:
        st.info("No sales data yet.")


# ── Tab 2: Seller Performance ────────────────
def _admin_seller_performance():
    st.subheader("Per-Seller Analytics")

    with get_conn() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT
                u.id,
                u.username,
                u.license_verified,
                COUNT(DISTINCT p.id)                                        AS products_listed,
                COALESCE(SUM(CASE WHEN p.quantity >= 0 THEN 1 ELSE 0 END),0) AS active_listings,
                COALESCE(SUM(p.quantity),0)                                 AS stock_remaining,
                COUNT(DISTINCT o.id)                                        AS total_orders,
                COALESCE(SUM(CASE WHEN o.status='delivered' THEN 1 ELSE 0 END),0) AS delivered,
                COALESCE(SUM(CASE WHEN o.status='cancelled' THEN 1 ELSE 0 END),0) AS cancelled,
                COALESCE(SUM(CASE WHEN o.status!='cancelled' THEN o.price ELSE 0 END),0) AS revenue,
                COALESCE(AVG(r.rating),0)                                   AS avg_rating
            FROM users u
            LEFT JOIN products p ON p.seller_id = u.id
            LEFT JOIN orders o   ON o.product_id = p.id
            LEFT JOIN reviews r  ON r.product_id = p.id
            WHERE u.user_type = 'seller'
            GROUP BY u.id
            ORDER BY revenue DESC
        """)
        rows = c.fetchall()

    if not rows:
        st.info("No sellers registered yet."); return

    # Summary bar
    total_rev = sum(float(r[9]) for r in rows)
    top_seller = max(rows, key=lambda r: float(r[9]))
    ca, cb, cc = st.columns(3)
    ca.metric("Total Seller Revenue", f"₹{total_rev:,.2f}")
    cb.metric("Top Seller", top_seller[1])
    cc.metric("Top Seller Revenue", f"₹{float(top_seller[9]):,.2f}")

    st.markdown("---")

    for r in rows:
        sid, sname, verified, listed, active, stock, orders, delivered, cancelled, revenue, avg_rat = r
        rev_f = float(revenue)
        rat_f = float(avg_rat)
        v_badge = '<span class="badge-verified">✅ Verified</span>' if verified else '<span class="badge-unverified">⏳ Pending</span>'

        with st.expander(f"🏪 {sname}  —  ₹{rev_f:,.2f} revenue  {('⭐ '+str(round(rat_f,1))) if rat_f else ''}"):
            st.markdown(f"**Status:** {v_badge}", unsafe_allow_html=True)

            mc1, mc2, mc3, mc4 = st.columns(4)
            mc1.metric("Products Listed", listed)
            mc2.metric("Stock Remaining", stock)
            mc3.metric("Orders Received", orders)
            mc4.metric("Revenue", f"₹{rev_f:,.2f}")

            mc5, mc6, mc7 = st.columns(3)
            mc5.metric("Delivered", delivered)
            mc6.metric("Cancelled", cancelled)
            mc7.metric("Avg Rating", f"{rat_f:.1f} ⭐" if rat_f else "—")

            # Per-seller product breakdown
            with get_conn() as conn:
                cur = conn.cursor()
                cur.execute("""
                    SELECT p.name, p.category, p.price, p.quantity,
                           COUNT(o.id), COALESCE(SUM(CASE WHEN o.status!='cancelled' THEN o.price ELSE 0 END),0)
                    FROM products p
                    LEFT JOIN orders o ON o.product_id=p.id
                    WHERE p.seller_id=?
                    GROUP BY p.id ORDER BY 6 DESC
                """, (sid,))
                prows = cur.fetchall()

            if prows:
                import pandas as pd
                df = pd.DataFrame(prows, columns=["Product","Category","Price (₹)","Stock","Orders","Revenue (₹)"])
                df["Price (₹)"]   = df["Price (₹)"].apply(lambda x: f"₹{float(x):.2f}")
                df["Revenue (₹)"] = df["Revenue (₹)"].apply(lambda x: f"₹{float(x):.2f}")
                st.dataframe(df, use_container_width=True, hide_index=True)

            # Message seller button
            if st.button(f"💬 Message {sname}", key=f"msg_s_{sid}"):
                st.session_state.msg_contact_id = sid
                nav_to("Messages")


# ── Tab 3: Seller Verification ───────────────
def _admin_verification():
    st.subheader("Seller Verification")
    with get_conn() as conn:
        c = conn.cursor()
        c.execute("SELECT id,username,license_file,license_verified FROM users WHERE user_type='seller' ORDER BY license_verified ASC, username ASC")
        sellers = c.fetchall()
    if not sellers:
        st.info("No sellers registered."); return
    for sid, sname, lic, verified in sellers:
        st.markdown('<div class="f2m-card">', unsafe_allow_html=True)
        c1, c2, c3 = st.columns([2, 1.5, 1])
        with c1:
            v = "✅ Verified" if verified else "⏳ Pending"
            st.markdown(f"**{sname}** — {v}")
        with c2:
            if lic:
                try: st.image(Image.open(io.BytesIO(lic)), width=120, caption="License")
                except Exception: st.caption("License (non-image format)")
            else:
                st.caption("No license uploaded")
        with c3:
            if not verified:
                if st.button("✅ Verify", key=f"v_{sid}", type="primary"):
                    with get_conn() as conn:
                        conn.cursor().execute("UPDATE users SET license_verified=1 WHERE id=?", (sid,))
                        conn.commit()
                    st.success("Verified!"); st.rerun()
                if st.button("❌ Reject", key=f"rj_{sid}"):
                    with get_conn() as conn:
                        conn.cursor().execute("DELETE FROM users WHERE id=?", (sid,))
                        conn.commit()
                    st.warning("Seller removed."); st.rerun()
            else:
                if st.button("Revoke", key=f"rv_{sid}"):
                    with get_conn() as conn:
                        conn.cursor().execute("UPDATE users SET license_verified=0 WHERE id=?", (sid,))
                        conn.commit()
                    st.rerun()
        st.markdown('</div>', unsafe_allow_html=True)


# ── Tab 4: User Management ───────────────────
def _admin_users():
    st.subheader("User Management")
    search = st.text_input("🔍 Search username")
    uf = st.selectbox("Filter type", ["All", "buyer", "seller"])
    with get_conn() as conn:
        c = conn.cursor()
        q = "SELECT u.id, u.username, u.user_type, u.license_verified, COUNT(DISTINCT p.id), COUNT(DISTINCT o.id) FROM users u LEFT JOIN products p ON p.seller_id=u.id LEFT JOIN orders o ON o.user_id=u.id WHERE u.user_type != 'admin'"
        params = []
        if uf != "All": q += " AND u.user_type=?"; params.append(uf)
        if search: q += " AND u.username LIKE ?"; params.append(f"%{search}%")
        c.execute(q + " GROUP BY u.id ORDER BY u.user_type, u.username", params)
        users = c.fetchall()
    if not users: st.info("No users found."); return
    st.caption(f"{len(users)} user(s) found")
    for uid, uname, utype, verified, prods, ords in users:
        st.markdown('<div class="f2m-card">', unsafe_allow_html=True)
        c1, c2 = st.columns([3, 1])
        with c1:
            v = " ✅" if (utype == "seller" and verified) else (" ⏳" if utype == "seller" else "")
            st.markdown(f"**{uname}**{v} — {utype.capitalize()}")
            if utype == "seller": st.caption(f"Products: {prods}  |  Orders received: {ords}")
            else: st.caption(f"Orders placed: {ords}")
        with c2:
            if st.button("🗑️ Delete", key=f"du_{uid}"):
                with get_conn() as conn:
                    cur = conn.cursor()
                    cur.execute("DELETE FROM orders WHERE user_id=?", (uid,))
                    cur.execute("DELETE FROM cart WHERE user_id=?", (uid,))
                    if utype == "seller": cur.execute("DELETE FROM products WHERE seller_id=?", (uid,))
                    cur.execute("DELETE FROM users WHERE id=?", (uid,))
                    conn.commit()
                st.success("User deleted."); st.rerun()
        st.markdown('</div>', unsafe_allow_html=True)


# ── Tab 5: All Orders ────────────────────────
def _admin_orders():
    st.subheader("All Orders")
    orders = get_all_orders()
    if not orders: st.info("No orders yet."); return

    rev   = sum(float(o[6]) for o in orders if o[7] != "cancelled")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Orders", len(orders))
    c2.metric("Revenue", f"₹{rev:,.2f}")
    c3.metric("Delivered", sum(1 for o in orders if o[7] == "delivered"))
    c4.metric("Cancelled", sum(1 for o in orders if o[7] == "cancelled"))

    sf = st.selectbox("Filter status", ["All","pending","processing","shipped","delivered","cancelled"], key="aosf")
    search = st.text_input("Search buyer / seller / product", key="aos")

    for o in orders:
        oid, uid, pid, name, desc, qty, price, status = o[:8]
        pname  = o[-3] if len(o) >= 22 else (o[-1] or name)
        buyer  = o[-2] if len(o) >= 22 else ""
        seller = o[-1] if len(o) >= 22 else ""
        if sf != "All" and status != sf: continue
        if search and search.lower() not in f"{pname}{buyer}{seller}".lower(): continue
        st.markdown('<div class="f2m-card">', unsafe_allow_html=True)
        c1, c2, c3 = st.columns(3)
        with c1:
            st.markdown(f"**Order #{oid}** — {pname}")
            st.caption(f"Qty: {qty}  |  ₹{float(price):.2f}")
        with c2:
            st.caption(f"Buyer: {buyer}  |  Seller: {seller}")
            st.caption(f"Date: {o[8]}")
            if len(o) > 14 and o[14]: st.caption(f"Ship to: {o[10]}, {o[14]}")
        with c3:
            st.markdown(status_badge(status), unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)


# ─────────────────────────────────────────────
# SIDEBAR
# ─────────────────────────────────────────────
def build_sidebar():
    user = st.session_state.user
    with st.sidebar:
        st.markdown('<div style="text-align:center;padding:10px 0 20px;">'
                    '<div style="font-size:2.5rem;">🌾</div>'
                    '<div style="font-size:1.3rem;font-weight:700;">Farm2Market</div>'
                    '</div>', unsafe_allow_html=True)

        if not user:
            _nav_btn("🔐 Login", "Login", use_container_width=True)
            _nav_btn("📝 Register", "Register", use_container_width=True)
            return

        utype = user[3]
        st.markdown(f"**👤 {user[1]}**")
        st.caption(utype.capitalize())
        st.markdown("---")

        if utype == "buyer":
            _nav_btn("🏪 Marketplace",  "Marketplace",  use_container_width=True)
            _nav_btn("🛒 My Cart",      "My Cart",      use_container_width=True)
            _nav_btn("📦 My Orders",    "My Orders",    use_container_width=True)
            _nav_btn("❤️ Wishlist",     "Wishlist",     use_container_width=True)
            _nav_btn("💰 My Offers",    "My Offers",    use_container_width=True)
            unread = get_unread_count(user[0])
            _nav_btn(f"💬 Messages{f' ({unread})' if unread else ''}", "Messages", use_container_width=True)

        elif utype == "seller":
            _nav_btn("📊 Dashboard",    "Seller Dashboard", use_container_width=True)
            _nav_btn("📦 My Products",  "My Products",      use_container_width=True)
            _nav_btn("➕ Add Product",  "Add Product",      use_container_width=True)
            _nav_btn("📋 Orders",       "Seller Orders",    use_container_width=True)
            _nav_btn("💰 Offers",       "Seller Offers",    use_container_width=True)
            unread = get_unread_count(user[0])
            _nav_btn(f"💬 Messages{f' ({unread})' if unread else ''}", "Messages", use_container_width=True)

        elif utype == "admin":
            _nav_btn("⚙️ Admin Panel",  "Admin Panel",  use_container_width=True)

        st.markdown("---")
        _nav_btn("📱 My QR Code",   "My QR Code",   use_container_width=True)
        _nav_btn("📷 QR Scanner",   "QR Scanner",   use_container_width=True)
        st.markdown("---")
        if st.button("🚪 Logout", use_container_width=True):
            st.session_state.user = None
            st.session_state.current_page = "Login"


# ─────────────────────────────────────────────
# ROUTER & MAIN
# ─────────────────────────────────────────────
PAGE_MAP = {
    "Login":            show_login,
    "Register":         show_register,
    "Marketplace":      show_marketplace,
    "My Cart":          show_cart,
    "Checkout":         show_checkout,
    "My Orders":        show_orders,
    "Wishlist":         show_wishlist,
    "My Offers":        show_my_offers,
    "Messages":         show_messages,
    "Seller Dashboard": show_seller_dashboard,
    "My Products":      show_seller_products,
    "Add Product":      show_add_product,
    "Edit Product":     show_edit_product,
    "Seller Orders":    show_seller_orders,
    "Seller Offers":    show_seller_offers,
    "Admin Panel":      show_admin_panel,
    "My QR Code":       show_my_qr,
    "QR Scanner":       show_qr_scanner,
}

def main():
    inject_css()
    init_db()
    init_session()
    build_sidebar()

    page = st.session_state.current_page
    user = st.session_state.user
    public = {"Login", "Register"}

    if not user and page not in public:
        st.session_state.current_page = "Login"; page = "Login"

    if user and page in public:
        page = ("Marketplace" if user[3] == "buyer"
                else "Seller Dashboard" if user[3] == "seller"
                else "Admin Panel")
        st.session_state.current_page = page

    fn = PAGE_MAP.get(page)
    if fn:
        fn()
    else:
        st.error(f"Page '{page}' not found.")

if __name__ == "__main__":
    main()