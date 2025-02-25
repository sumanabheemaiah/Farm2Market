import streamlit as st
st.set_page_config(
    page_title="Farm2Market",
    page_icon="🌾",
    layout="wide",
    initial_sidebar_state="expanded"
)
import sqlite3
from PIL import Image
import hashlib
import io
from datetime import datetime
import re
import logging
from functools import lru_cache
import time
from typing import Optional, List, Dict, Any, Tuple
import qrcode
import cv2
import numpy as np
from io import BytesIO



def adapt_datetime(dt):
    return dt.isoformat()

def convert_datetime(text):
    return datetime.fromisoformat(text)
# Register the adapter
sqlite3.register_adapter(datetime, adapt_datetime)
sqlite3.register_converter('datetime', convert_datetime)

# Update database connection to use datetime converter
def get_db_connection():
    return sqlite3.connect('farm2market.db')

# Configure caching for database connection
@st.cache_resource
def get_database_connection():
    return sqlite3.connect('farm2market.db', check_same_thread=False)

# Cache frequently used queries
@st.cache_data(ttl=300)  # Cache for 5 minutes
def get_product_categories():
    return ["All", "Vegetables", "Fruits", "Dairy", "Meat", "Other"]

@st.cache_data
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

# Optimize image handling
@st.cache_data
def process_image(image_bytes: bytes, max_size: tuple = (800, 800)) -> bytes:
    if not image_bytes:
        return None
    try:
        img = Image.open(io.BytesIO(image_bytes))
        img.thumbnail(max_size, Image.Resampling.LANCZOS)
        buffer = io.BytesIO()
        img.save(buffer, format="JPEG", quality=85, optimize=True)
        return buffer.getvalue()
    except Exception as e:
        logging.error(f"Image processing error: {e}")
        return None


class QRCodeDetector:
    def __init__(self):
        self.qreader = QReader()

    def detect_and_decode(self, image_array):
        try:
            # Detect and decode QR code
            decoded_text = self.qreader.detect_and_decode(image=image_array)
            if decoded_text:
                return decoded_text[0]  # Return first detected QR code
            return None
        except Exception as e:
            print(f"Error detecting QR code: {e}")
            return None


class DatabaseManager:
    def __init__(self):
        self.conn = get_database_connection()
        self.cursor = self.conn.cursor()

    def execute_query(self, query: str, params: tuple = None) -> List:
        try:
            if params:
                self.cursor.execute(query, params)
            else:
                self.cursor.execute(query)
            return self.cursor.fetchall()
        except Exception as e:
            logging.error(f"Database error: {e}")
            return []

    def commit(self):
        self.conn.commit()
# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename='farm2market.log'
)


def cleanup_categories():
    """Clean up any invalid categories in the database"""
    conn = sqlite3.connect('farm2market.db')
    c = conn.cursor()

    try:
        c.execute('''UPDATE products 
                    SET category = 'Other' 
                    WHERE category IS NULL 
                    OR category = '' 
                    OR category LIKE '%x89PNG%' 
                    OR category NOT IN ('Crops', 'Dairy', 'Fruits', 'Vegetables', 'Spices', 'Other')
                ''')
        conn.commit()
        print("Categories cleaned up successfully")

    except Exception as e:
        print(f"Error cleaning categories: {str(e)}")
        conn.rollback()
    finally:
        conn.close()


def migrate_database():
    conn = sqlite3.connect('farm2market.db')
    c = conn.cursor()

    try:
        # Begin transaction
        c.execute('BEGIN TRANSACTION')

        # Backup existing orders if any
        c.execute('CREATE TABLE IF NOT EXISTS orders_backup AS SELECT * FROM orders')

        # Drop existing orders table
        c.execute('DROP TABLE IF EXISTS orders')

        # Create new orders table
        c.execute('''CREATE TABLE orders (
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL,
            product_id INTEGER,
            name TEXT,
            description TEXT,
            quantity INTEGER,
            price REAL,
            status TEXT DEFAULT 'pending',
            order_date DATETIME DEFAULT CURRENT_TIMESTAMP,
            image BLOB,
            shipping_name TEXT,
            shipping_email TEXT,
            shipping_phone TEXT,
            shipping_address TEXT,
            shipping_city TEXT,
            shipping_state TEXT,
            shipping_pincode TEXT,
            shipping_country TEXT,
            payment_method TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (product_id) REFERENCES products (id)
        )''')

        # Restore data from backup if exists
        c.execute('''INSERT INTO orders 
                    SELECT * FROM orders_backup 
                    WHERE EXISTS 
                    (SELECT name FROM sqlite_master WHERE type='table' AND name='orders_backup')
                ''')

        # Drop backup table
        c.execute('DROP TABLE IF EXISTS orders_backup')

        # Set default status
        c.execute('''UPDATE orders 
                    SET status = 'pending' 
                    WHERE status IS NULL OR status = ''
                ''')

        # Commit transaction
        c.execute('COMMIT')
        print("Database migration successful")

    except Exception as e:
        print(f"Migration error: {str(e)}")
        c.execute('ROLLBACK')
    finally:
        conn.close()
# Database functions
# First, let's modify the orders table structure
def init_db():
    conn = sqlite3.connect('farm2market.db')
    c = conn.cursor()

    try:
        # Create users table
        c.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            user_type TEXT NOT NULL,
            license_file BLOB,
            license_verified BOOLEAN DEFAULT FALSE
        )''')

        # Create products table
        c.execute('''CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY,
            seller_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            description TEXT,
            price REAL NOT NULL,
            quantity INTEGER NOT NULL,
            category TEXT,
            image BLOB,
            date_added DATETIME,
            FOREIGN KEY (seller_id) REFERENCES users (id)
        )''')

        # Create orders table with default status
        c.execute('''CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL,
            product_id INTEGER,
            name TEXT,
            description TEXT,
            quantity INTEGER,
            price REAL,
            status TEXT DEFAULT 'pending',
            order_date DATETIME DEFAULT CURRENT_TIMESTAMP,
            image BLOB,
            shipping_name TEXT,
            shipping_email TEXT,
            shipping_phone TEXT,
            shipping_address TEXT,
            shipping_city TEXT,
            shipping_state TEXT,
            shipping_pincode TEXT,
            shipping_country TEXT,
            payment_method TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (product_id) REFERENCES products (id)
        )''')

        # Create cart table
        c.execute('''CREATE TABLE IF NOT EXISTS cart (
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            quantity INTEGER NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (product_id) REFERENCES products (id)
        )''')

        # Set default status for any NULL status orders
        c.execute('''UPDATE orders 
                    SET status = 'pending' 
                    WHERE status IS NULL OR status = ''
                ''')

        c.execute('''CREATE TABLE IF NOT EXISTS user_qr_codes (
                    id INTEGER PRIMARY KEY,
                    user_id INTEGER UNIQUE NOT NULL,
                    qr_code BLOB NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )''')
        # Inside init_db()
        c.execute('''CREATE TABLE IF NOT EXISTS reviews (
            id INTEGER PRIMARY KEY,
            product_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            rating INTEGER NOT NULL,
            comment TEXT,
            review_date DATETIME DEFAULT CURRENT_TIMESTAMP,
            seller_reply TEXT,
            reply_date DATETIME,
            FOREIGN KEY (product_id) REFERENCES products (id),
            FOREIGN KEY (user_id) REFERENCES users (id),
            CHECK (rating >= 1 AND rating <= 5)
        )''')

        conn.commit()
        print("Database initialized successfully")

    except Exception as e:
        print(f"Database initialization error: {str(e)}")
        conn.rollback()
    finally:
        conn.close()

def init_session_state():
    """Initialize all session state variables"""
    if "user" not in st.session_state:
        st.session_state["user"] = None
    if "current_page" not in st.session_state:
        st.session_state["current_page"] = "Login"
    if "pages" not in st.session_state:
        st.session_state["pages"] = []
    if "editing_product" not in st.session_state:
        st.session_state["editing_product"] = None
    if "checkout_cart_items" not in st.session_state:
        st.session_state["checkout_cart_items"] = None
    if "checkout_product" not in st.session_state:
        st.session_state["checkout_product"] = None
    if "checkout_quantity" not in st.session_state:
        st.session_state["checkout_quantity"] = None

def migrate_database():
    conn = sqlite3.connect('farm2market.db')
    c = conn.cursor()

    try:
        # Begin transaction
        c.execute('BEGIN TRANSACTION')

        # Backup existing orders if any
        c.execute('CREATE TABLE IF NOT EXISTS orders_backup AS SELECT * FROM orders')

        # Drop existing orders table
        c.execute('DROP TABLE IF EXISTS orders')

        # Create new orders table
        c.execute('''CREATE TABLE orders (
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL,
            product_id INTEGER,
            name TEXT,
            description TEXT,
            quantity INTEGER,
            price REAL,
            status TEXT DEFAULT 'pending',
            order_date DATETIME DEFAULT CURRENT_TIMESTAMP,
            image BLOB,
            shipping_name TEXT,
            shipping_email TEXT,
            shipping_phone TEXT,
            shipping_address TEXT,
            shipping_city TEXT,
            shipping_state TEXT,
            shipping_pincode TEXT,
            shipping_country TEXT,
            payment_method TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (product_id) REFERENCES products (id)
        )''')

        # Restore data from backup if exists
        c.execute('''INSERT INTO orders 
                    SELECT * FROM orders_backup 
                    WHERE EXISTS 
                    (SELECT name FROM sqlite_master WHERE type='table' AND name='orders_backup')
                ''')

        # Drop backup table
        c.execute('DROP TABLE IF EXISTS orders_backup')

        # Set default status
        c.execute('''UPDATE orders 
                    SET status = 'pending' 
                    WHERE status IS NULL OR status = ''
                ''')

        # Commit transaction
        c.execute('COMMIT')
        print("Database migration successful")

    except Exception as e:
        print(f"Migration error: {str(e)}")
        c.execute('ROLLBACK')
    finally:
        conn.close()

def show_orders():
    st.title("My Orders")

    if not st.session_state.user:
        st.error("Please login to view orders")
        return

    conn = sqlite3.connect('farm2market.db')
    c = conn.cursor()

    try:
        # Modified query to work with existing table structure
        c.execute('''SELECT o.* 
                    FROM orders o
                    WHERE o.user_id = ?
                    ORDER BY o.order_date DESC''', (st.session_state.user[0],))

        orders = c.fetchall()

        if not orders:
            st.info("No orders found")
            return

        # Add filter for order status
        status_filter = st.selectbox(
            "Filter by Status",
            ["All Orders", "Pending", "Processing", "Shipped", "Delivered", "Cancelled"]
        )

        # Display orders in a modern card layout
        for order in orders:
            try:
                # Apply status filter
                order_status = order[7] if len(order) > 7 and order[7] else 'pending'
                if status_filter != "All Orders" and order_status != status_filter.lower():
                    continue

                with st.container():
                    # Card styling
                    st.markdown("""
                        <style>
                        .order-card {
                            border: 1px solid #ddd;
                            border-radius: 5px;
                            padding: 15px;
                            margin: 10px 0;
                        }
                        </style>
                    """, unsafe_allow_html=True)

                    st.markdown('<div class="order-card">', unsafe_allow_html=True)

                    # Order header with ID and status
                    col1, col2 = st.columns([3, 1])
                    with col1:
                        st.subheader(f"Order #{order[0]}")
                    with col2:
                        status_colors = {
                            'pending': 'orange',
                            'processing': 'blue',
                            'shipped': 'purple',
                            'delivered': 'green',
                            'cancelled': 'red'
                        }
                        status_color = status_colors.get(order_status, 'grey')
                        st.markdown(f'<p style="color: {status_color}; font-weight: bold;">{order_status.upper()}</p>',
                                    unsafe_allow_html=True)

                    # Order details
                    col1, col2 = st.columns(2)
                    with col1:
                        st.write("**Order Details:**")
                        st.write(f"Product: {order[3]}")  # name
                        st.write(f"Quantity: {order[5]}")
                        st.write(f"Total Price: ${float(order[6]):.2f}")

                    with col2:
                        st.write("**Order Information:**")
                        st.write(f"Order Date: {order[8]}")

                        # Allow cancellation only for pending or processing orders
                        if order_status in ['pending', 'processing']:
                            cancel_col1, cancel_col2 = st.columns([2, 1])
                            with cancel_col1:
                                confirm = st.checkbox('Confirm cancellation',
                                                      key=f"confirm_{order[0]}")
                            with cancel_col2:
                                if st.button('Cancel Order', key=f"cancel_{order[0]}"):
                                    if confirm:
                                        try:
                                            # Update order status to cancelled
                                            c.execute('''UPDATE orders 
                                                       SET status = 'cancelled' 
                                                       WHERE id = ? AND user_id = ?''',
                                                      (order[0], st.session_state.user[0]))

                                            # Restore product quantity
                                            if order[2]:  # if product_id exists
                                                c.execute('''UPDATE products 
                                                           SET quantity = quantity + ?
                                                           WHERE id = ?''',
                                                          (order[5], order[2]))

                                            conn.commit()
                                            st.success("Order cancelled successfully!")
                                            time.sleep(1)
                                            st.rerun()
                                        except Exception as e:
                                            st.error(f"Error cancelling order: {str(e)}")
                                            conn.rollback()
                                    else:
                                        st.warning("Please confirm cancellation first")

                    # Show order image if available
                    if len(order) > 9 and order[9]:
                        try:
                            image = Image.open(io.BytesIO(order[9]))
                            st.image(image, width=200)
                        except Exception as e:
                            st.warning("Product image not available")

                    st.markdown('</div>', unsafe_allow_html=True)

            except Exception as e:
                st.error(f"Error displaying order: {str(e)}")
                continue

    except Exception as e:
        st.error(f"Error fetching orders: {str(e)}")
    finally:
        conn.close()


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def login_user(username, password):
    conn = sqlite3.connect('farm2market.db')
    c = conn.cursor()

    try:
        # Hash the provided password
        hashed_password = hash_password(password)

        # Debug print
        print(f"Attempting login for username: {username}")
        print(f"Hashed password: {hashed_password}")

        # Query user
        c.execute('SELECT * FROM users WHERE username = ? AND password = ?',
                  (username, hashed_password))
        user = c.fetchone()

        if user:
            print(f"Login successful for user: {username}")
            return user
        else:
            print(f"Login failed for user: {username}")
            # Debug query to check stored password
            c.execute('SELECT password FROM users WHERE username = ?', (username,))
            stored = c.fetchone()
            if stored:
                print(f"Stored hashed password: {stored[0]}")
            return None

    except Exception as e:
        print(f"Login error: {e}")
        return None
    finally:
        conn.close()


def register_user(username, password, user_type, license_file=None):
    # Validate seller registration requirements
    if user_type == "seller" and not license_file:
        return False, "Seller registration requires a valid license document"

    conn = sqlite3.connect('farm2market.db')
    c = conn.cursor()

    try:
        # Check if username exists
        c.execute('SELECT * FROM users WHERE username = ?', (username,))
        if c.fetchone() is not None:
            return False, "Username already exists"

        # Hash the password
        hashed_password = hash_password(password)

        # Process license file if provided
        license_data = None
        if license_file:
            try:
                # Validate file type
                allowed_types = ['pdf', 'png', 'jpg', 'jpeg']
                file_type = license_file.name.split('.')[-1].lower()
                if file_type not in allowed_types:
                    return False, "Invalid file type. Please upload PDF or image files only"

                # Validate file size (max 5MB)
                if license_file.size > 5 * 1024 * 1024:  # 5MB in bytes
                    return False, "File size too large. Maximum size is 5MB"

                license_data = license_file.read()
            except Exception as e:
                return False, f"Error processing license file: {str(e)}"

        # Set license verification (auto-verify for admin)
        license_verified = True if user_type == 'admin' else False

        # Insert new user
        c.execute('''INSERT INTO users 
                    (username, password, user_type, license_file, license_verified)
                    VALUES (?, ?, ?, ?, ?)''',
                  (username, hashed_password, user_type, license_data, license_verified))

        conn.commit()
        return True, "Registration successful"

    except Exception as e:
        print(f"Registration error: {e}")
        return False, f"Registration failed: {str(e)}"
    finally:
        conn.close()

def add_product(seller_id, name, description, price, quantity, category, image=None):
    valid_categories = ["Crops", "Dairy", "Fruits", "Vegetables", "Spices", "Other"]

    # Validate category
    if category not in valid_categories:
        category = "Other"

    conn = sqlite3.connect('farm2market.db')
    c = conn.cursor()
    try:
        image_data = image.read() if image else None
        c.execute('''INSERT INTO products 
                    (seller_id, name, description, price, quantity, category, image, date_added)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                  (seller_id, name, description, price, quantity, category,
                   image_data, datetime.now()))
        conn.commit()
        return True
    except Exception as e:
        print(f"Error adding product: {e}")
        return False
    finally:
        conn.close()

def delete_product(product_id):
    conn = get_db_connection()
    c = conn.cursor()
    try:
        c.execute('DELETE FROM products WHERE id = ?', (product_id,))
        conn.commit()
        return True
    except Exception as e:
        logging.error(f"Error deleting product: {e}")
        return False
    finally:
        conn.close()

def edit_product(product_id, name, description, price, quantity, category):
    conn = get_db_connection()
    c = conn.cursor()
    try:
        c.execute('''UPDATE products 
                     SET name=?, description=?, price=?, quantity=?, category=?
                     WHERE id=?''',
                  (name, description, price, quantity, category, product_id))
        conn.commit()
        return True
    except Exception as e:
        logging.error(f"Error editing product: {e}")
        return False
    finally:
        conn.close()

def get_products(seller_id=None):
    conn = sqlite3.connect('farm2market.db')
    c = conn.cursor()

    try:
        if seller_id:
            c.execute('SELECT * FROM products WHERE seller_id=?', (seller_id,))
        else:
            c.execute('SELECT * FROM products WHERE quantity > 0')
        products = c.fetchall()
        return products
    finally:
        conn.close()


def add_to_cart(user_id, product_id, quantity):
    conn = get_db_connection()
    c = conn.cursor()
    try:
        c.execute('INSERT INTO cart (user_id, product_id, quantity) VALUES (?, ?, ?)',
                  (user_id, product_id, quantity))
        conn.commit()
        return True
    except Exception as e:
        logging.error(f"Error adding to cart: {e}")
        return False
    finally:
        conn.close()

def get_cart_items(user_id):
    conn = get_db_connection()
    c = conn.cursor()
    try:
        c.execute('''SELECT c.id, p.name, p.price, c.quantity, p.image, p.id 
                     FROM cart c
                     JOIN products p ON c.product_id = p.id
                     WHERE c.user_id = ?''', (user_id,))
        return c.fetchall()
    finally:
        conn.close()

def remove_from_cart(cart_item_id):
    conn = get_db_connection()
    c = conn.cursor()
    try:
        c.execute('DELETE FROM cart WHERE id = ?', (cart_item_id,))
        conn.commit()
        return True
    except Exception as e:
        logging.error(f"Error removing from cart: {e}")
        return False
    finally:
        conn.close()

# Page functions
def show_login():
    st.title("Login to Farm2Market")

    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Login")

        if submitted:
            if not username or not password:
                st.error("Please enter both username and password")
                return

            user = login_user(username, password)
            if user:
                st.session_state.user = user
                st.success("Login successful!")
                time.sleep(1)
                st.rerun()
            else:
                st.error("Invalid username or password")


def show_register():
    st.title("Register for Farm2Market")

    with st.form("register_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        confirm_password = st.text_input("Confirm Password", type="password")
        user_type = st.selectbox("Account Type", ["buyer", "seller", "admin"])

        license_file = None
        if user_type == "seller":
            st.write("Please upload your seller's license (Required)")
            st.write("Accepted formats: PDF, PNG, JPG, JPEG (Max size: 5MB)")
            license_file = st.file_uploader("License", type=["pdf", "png", "jpg", "jpeg"])
            if not license_file:
                st.warning("⚠️ A valid license document is required for seller registration")

        submitted = st.form_submit_button("Register")

        if submitted:
            if not username or not password or not confirm_password:
                st.error("Please fill in all fields")
                return

            if password != confirm_password:
                st.error("Passwords do not match")
                return

            if user_type == "seller" and not license_file:
                st.error("Please upload a valid license document to register as a seller")
                return

            success, message = register_user(username, password, user_type, license_file)
            if success:
                st.success(message + " Please login.")
            else:
                st.error(message)


def show_add_product():
    if not st.session_state.user or st.session_state.user[3] != 'seller':
        st.error("Access denied")
        return

    st.title("➕ Add New Product")

    # Initialize database connection
    conn = sqlite3.connect('farm2market.db')
    c = conn.cursor()

    try:
        # Check seller verification first
        c.execute('SELECT license_verified FROM users WHERE id = ?', (st.session_state.user[0],))
        is_verified = c.fetchone()[0]

        if not is_verified:
            st.warning("Your seller account is pending verification.")
            return

        # Create form
        with st.form("add_product_form", clear_on_submit=True):
            name = st.text_input("Product Name*")
            description = st.text_area("Description*")
            col1, col2, col3 = st.columns(3)

            with col1:
                price = st.number_input("Price (₹)*", min_value=0.01, step=0.01)
            with col2:
                quantity = st.number_input("Quantity*", min_value=1, step=1)
            with col3:
                category = st.selectbox("Category*", ["Crops", "Dairy", "Fruits", "Vegetables", "Spices", "Other"])

            image = st.file_uploader("Product Image", type=["png", "jpg", "jpeg"])
            submitted = st.form_submit_button("Add Product")

            if submitted:
                if not all([name, description, price > 0, quantity > 0]):
                    st.error("Please fill all required fields")
                    return

                try:
                    # Process image if provided
                    image_data = None
                    if image:
                        image_data = image.read()

                    # Insert new product
                    c.execute('''INSERT INTO products 
                                (seller_id, name, description, price, quantity, 
                                 category, image, date_added)
                                VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                              (st.session_state.user[0], name, description,
                               price, quantity, category, image_data, datetime.now()))

                    # Commit the transaction
                    conn.commit()
                    st.success("✅ Product added successfully!")

                    # Optional: Clear form (will happen naturally with clear_on_submit=True)
                    time.sleep(1)  # Give user time to see success message

                    # Return to product list
                    st.session_state["current_page"] = "My Products"
                    st.rerun()

                except Exception as e:
                    st.error(f"Error adding product: {str(e)}")
                    conn.rollback()

    except Exception as e:
        st.error(f"An error occurred: {str(e)}")
    finally:
        conn.close()

def show_admin_panel():
    st.title("Admin Panel")

    if not st.session_state.user or st.session_state.user[3] != 'admin':
        st.error("Access denied. Admin only.")
        return

    # Tabs for different admin functions
    tab1, tab2 = st.tabs(["Seller Verification", "User Management"])

    with tab1:
        st.subheader("Pending Seller Verifications")

        conn = sqlite3.connect('farm2market.db')
        c = conn.cursor()

        try:
            c.execute('''SELECT id, username, license_file, license_verified 
                        FROM users 
                        WHERE user_type='seller'
                        ORDER BY license_verified ASC, username ASC''')
            sellers = c.fetchall()

            if not sellers:
                st.info("No sellers found")
                return

            for seller in sellers:
                with st.container():
                    st.markdown("""
                        <style>
                        .seller-card {
                            border: 1px solid #ddd;
                            border-radius: 10px;
                            padding: 15px;
                            margin: 10px 0;
                            background-color: white;
                            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                        }
                        </style>
                    """, unsafe_allow_html=True)

                    st.markdown('<div class="seller-card">', unsafe_allow_html=True)

                    col1, col2, col3 = st.columns([2, 1, 1])

                    with col1:
                        st.write(f"**Seller:** {seller[1]}")
                        status = "✅ Verified" if seller[3] else "⏳ Pending Verification"
                        st.write(f"**Status:** {status}")

                    with col2:
                        if seller[2]:  # license file
                            try:
                                license_image = Image.open(io.BytesIO(seller[2]))
                                st.image(license_image, caption="License Document", width=150)
                            except:
                                st.warning("License file not viewable")
                        else:
                            st.warning("No license uploaded")

                    with col3:
                        if not seller[3]:  # if not verified
                            col_a, col_b = st.columns(2)
                            with col_a:
                                if st.button("✅ Verify", key=f"verify_{seller[0]}",
                                             use_container_width=True):
                                    c.execute('''UPDATE users 
                                               SET license_verified = TRUE 
                                               WHERE id = ?''', (seller[0],))
                                    conn.commit()
                                    st.success("Seller verified!")
                                    time.sleep(1)
                                    st.rerun()
                            with col_b:
                                if st.button("❌ Reject", key=f"reject_{seller[0]}",
                                             use_container_width=True):
                                    if st.checkbox("Confirm rejection",
                                                   key=f"confirm_{seller[0]}"):
                                        c.execute('DELETE FROM users WHERE id = ?',
                                                  (seller[0],))
                                        conn.commit()
                                        st.success("Seller rejected!")
                                        time.sleep(1)
                                        st.rerun()
                        else:
                            if st.button("Revoke Verification",
                                         key=f"revoke_{seller[0]}",
                                         use_container_width=True):
                                if st.checkbox("Confirm revocation",
                                               key=f"confirm_revoke_{seller[0]}"):
                                    c.execute('''UPDATE users 
                                               SET license_verified = FALSE 
                                               WHERE id = ?''', (seller[0],))
                                    conn.commit()
                                    st.success("Verification revoked!")
                                    time.sleep(1)
                                    st.rerun()

                    st.markdown('</div>', unsafe_allow_html=True)

        except Exception as e:
            st.error(f"Error: {str(e)}")
        finally:
            conn.close()

    with tab2:
        st.subheader("User Management")

        conn = sqlite3.connect('farm2market.db')
        c = conn.cursor()

        try:
            c.execute('''SELECT id, username, user_type, 
                        CASE 
                            WHEN user_type = 'seller' THEN license_verified 
                            ELSE NULL 
                        END as verified
                        FROM users 
                        ORDER BY user_type, username''')
            users = c.fetchall()

            if users:
                for user in users:
                    with st.container():
                        st.markdown('<div class="seller-card">', unsafe_allow_html=True)

                        col1, col2 = st.columns([3, 1])

                        with col1:
                            st.write(f"**Username:** {user[1]}")
                            st.write(f"**Type:** {user[2].capitalize()}")
                            if user[2] == 'seller':
                                st.write(f"**Verified:** {'Yes' if user[3] else 'No'}")

                        with col2:
                            if user[2] != 'admin':
                                if st.button("🗑️ Delete User",
                                             key=f"delete_{user[0]}",
                                             use_container_width=True):
                                    if st.checkbox("Confirm deletion",
                                                   key=f"confirm_delete_{user[0]}"):
                                        c.execute('DELETE FROM users WHERE id = ?',
                                                  (user[0],))
                                        conn.commit()
                                        st.success("User deleted!")
                                        time.sleep(1)
                                        st.rerun()

                        st.markdown('</div>', unsafe_allow_html=True)
            else:
                st.info("No users found")

        except Exception as e:
            st.error(f"Error: {str(e)}")
        finally:
            conn.close()


def show_seller_verification():
    conn = sqlite3.connect('farm2market.db')
    c = conn.cursor()

    try:
        c.execute('''SELECT id, username, license_file, license_verified 
                    FROM users WHERE user_type='seller' ORDER BY license_verified ASC''')
        sellers = c.fetchall()

        for seller in sellers:
            with st.container():
                col1, col2 = st.columns([3, 1])

                with col1:
                    st.write(f"**Seller:** {seller[1]}")
                    status = "✅ Verified" if seller[3] else "⏳ Pending"
                    st.write(f"**Status:** {status}")

                    if seller[2]:
                        st.write("**License Document:**")
                        try:
                            image = Image.open(io.BytesIO(seller[2]))
                            st.image(image, width=300)
                        except Exception as e:
                            st.error("Unable to display license document")
                    else:
                        st.warning("No license document found")

                with col2:
                    if not seller[3]:  # If not verified
                        st.write("**Actions:**")
                        if st.button("✅ Approve", key=f"verify_{seller[0]}"):
                            c.execute('UPDATE users SET license_verified = TRUE WHERE id = ?', (seller[0],))
                            conn.commit()
                            st.success("Seller verified successfully!")
                            time.sleep(1)
                            st.rerun()
    except Exception as e:
        st.error(f"Error processing seller verification: {str(e)}")
    finally:
        conn.close()


def show_user_management():
    st.title("👥 User Management")

    if not st.session_state.user or st.session_state.user[3] != 'admin':
        st.error("Access denied. Admin only.")
        return

    conn = sqlite3.connect('farm2market.db')
    c = conn.cursor()

    try:
        # User Statistics - Update to exclude admin from count
        c.execute('''SELECT 
                        COUNT(*) - (SELECT COUNT(*) FROM users WHERE user_type = 'admin') as total,
                        SUM(CASE WHEN user_type = 'buyer' THEN 1 ELSE 0 END) as buyers,
                        SUM(CASE WHEN user_type = 'seller' THEN 1 ELSE 0 END) as sellers
                    FROM users''')
        stats = c.fetchone()

        # Statistics Cards
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Users", stats[0])
        with col2:
            st.metric("Buyers", stats[1] or 0)
        with col3:
            st.metric("Sellers", stats[2] or 0)

        # Filters
        col1, col2 = st.columns(2)
        with col1:
            user_type_filter = st.selectbox(
                "👤 Filter by User Type",
                ["All Users", "Buyers", "Sellers"],
                key="user_type_filter"
            )
        with col2:
            search_query = st.text_input("🔍 Search users", key="user_search")

        # Query Construction
        query = '''SELECT u.id, u.username, u.user_type, u.license_verified,
                    COUNT(DISTINCT p.id) as product_count,
                    SUM(p.quantity) as total_stock,
                    COUNT(DISTINCT o.id) as order_count
                  FROM users u
                  LEFT JOIN products p ON u.id = p.seller_id
                  LEFT JOIN orders o ON u.id = o.user_id
                  WHERE u.user_type != 'admin' '''

        params = []
        if user_type_filter == "Buyers":
            query += "AND u.user_type = 'buyer' "
        elif user_type_filter == "Sellers":
            query += "AND u.user_type = 'seller' "

        if search_query:
            query += "AND u.username LIKE ? "
            params.append(f"%{search_query}%")

        query += "GROUP BY u.id ORDER BY u.user_type, u.username"

        c.execute(query, params)
        users = c.fetchall()

        if not users:
            st.info("No users found matching your criteria")
            return

        # Display Users
        for user in users:
            user_id, username, user_type, verified, product_count, total_stock, order_count = user

            with st.container():
                st.markdown("""
                    <div style="border: 1px solid #ddd; padding: 15px; 
                    border-radius: 10px; margin: 10px 0; background-color: rgba(17, 17, 17, 0.3);">
                """, unsafe_allow_html=True)

                col1, col2 = st.columns([3, 1])

                with col1:
                    st.write(f"**Username:** {username}")
                    st.write(f"**Type:** {user_type.capitalize()}")

                    # Only show verification status for sellers
                    if user_type == 'seller':
                        status = "✅ Verified" if verified else "⏳ Pending Verification"
                        st.write(f"**Status:** {status}")

                    if user_type == 'seller':
                        st.write(f"📦 Products Listed: {product_count or 0}")
                        st.write(f"📊 Total Stock: {total_stock or 0}")
                    else:  # buyer
                        st.write(f"🛍️ Orders Placed: {order_count or 0}")

                with col2:
                    # Delete functionality
                    delete_key = f'delete_{user_id}'
                    if delete_key not in st.session_state:
                        st.session_state[delete_key] = False

                    if st.button("🗑️ Delete User", key=f"del_btn_{user_id}"):
                        st.session_state[delete_key] = True

                    if st.session_state[delete_key]:
                        st.warning("⚠️ This action cannot be undone!")
                        col1, col2 = st.columns(2)

                        with col1:
                            if st.button("✔️ Confirm", key=f"confirm_{user_id}"):
                                try:
                                    c.execute('BEGIN TRANSACTION')
                                    # Delete related records first
                                    c.execute('DELETE FROM orders WHERE user_id = ?', (user_id,))
                                    c.execute('DELETE FROM cart WHERE user_id = ?', (user_id,))
                                    if user_type == 'seller':
                                        c.execute('DELETE FROM products WHERE seller_id = ?', (user_id,))
                                    c.execute('DELETE FROM users WHERE id = ?', (user_id,))
                                    conn.commit()
                                    st.success(f"User {username} has been deleted successfully!")
                                    time.sleep(1)
                                    st.rerun()
                                except Exception as e:
                                    conn.rollback()
                                    st.error(f"Error deleting user: {str(e)}")

                        with col2:
                            if st.button("❌ Cancel", key=f"cancel_{user_id}"):
                                st.session_state[delete_key] = False
                                st.rerun()

                st.markdown("</div>", unsafe_allow_html=True)

    except Exception as e:
        st.error(f"Error in user management: {str(e)}")
    finally:
        conn.close()

def show_marketplace():
    st.title("Farm2Market Marketplace")

    # Add search and filter options
    col1, col2 = st.columns([2, 1])
    with col1:
        search = st.text_input("🔍 Search products")
    with col2:
        category = st.selectbox(
            "Category",
            ["All", "Crops", "Dairy", "Fruits", "Vegetables", "Spices", "Other"]
        )

    conn = sqlite3.connect('farm2market.db')
    c = conn.cursor()

    try:
        # Clean up categories first
        cleanup_categories()

        # Build query
        query = "SELECT * FROM products WHERE quantity > 0"
        params = []

        if search:
            query += " AND (name LIKE ? OR description LIKE ?)"
            params.extend([f"%{search}%", f"%{search}%"])

        if category != "All":
            query += " AND category = ?"
            params.append(category)

        c.execute(query, tuple(params))
        products = c.fetchall()

        if not products:
            st.info("No products found")
            return

        # Display products in grid
        cols = st.columns(3)
        for idx, product in enumerate(products):
            with cols[idx % 3]:
                if product[7]:  # image
                    try:
                        image = Image.open(io.BytesIO(product[7]))
                        st.image(image, use_column_width=True)
                    except Exception as e:
                        st.warning("Image not available")

                st.subheader(product[2])  # name
                st.write(product[3])  # description
                st.write(f"Price: ${float(product[4]):.2f}")
                st.write(f"Available: {product[5]}")
                st.write(f"Category: {product[6]}")

                if st.session_state.user and st.session_state.user[3] == 'buyer':
                    quantity = st.number_input(
                        "Quantity",
                        min_value=1,
                        max_value=product[5],
                        value=1,
                        key=f"qty_{product[0]}"
                    )
                    if st.button("Add to Cart", key=f"add_{product[0]}"):
                        if add_to_cart(st.session_state.user[0], product[0], quantity):
                            st.success("Added to cart!")
                            time.sleep(0.5)
                            st.rerun()
    finally:
        conn.close()

def display_product_card(product):
    with st.container():
        card_style = """
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 10px;
            margin: 5px;
        """
        st.markdown(f'<div style="{card_style}">', unsafe_allow_html=True)

        # Display product image
        if product[7]:  # image blob
            try:
                image = Image.open(io.BytesIO(product[7]))
                st.image(image, use_column_width=True)
            except Exception as e:
                st.warning("Image not available")

        # Product details
        st.subheader(product[2])  # name
        st.write(product[3])  # description
        st.write(f"Price: ${float(product[4]):.2f}")
        st.write(f"Available: {product[5]}")
        st.write(f"Category: {product[6]}")

        # Format and display date
        if product[8]:  # date_added
            date_str = product[8].strftime("%Y-%m-%d %H:%M")
            st.write(f"Listed on: {date_str}")

        # Add to cart button for buyers
        if st.session_state.user and st.session_state.user[3] == 'buyer':
            add_to_cart_section(product)

        st.markdown('</div>', unsafe_allow_html=True)

def add_to_cart_section(product):
    col1, col2 = st.columns([2, 1])
    with col1:
        quantity = st.number_input(
            "Quantity",
            min_value=1,
            max_value=product[5],
            value=1,
            key=f"qty_{product[0]}"
        )
    with col2:
        if st.button("🛒 Add", key=f"add_{product[0]}"):
            add_to_cart(st.session_state.user[0], product[0], quantity)
            st.success(f"Added to cart!")
            time.sleep(0.5)
            st.rerun()

@st.cache_data(ttl=60)
def add_to_cart(user_id, product_id, quantity):
    conn = sqlite3.connect('farm2market.db')
    c = conn.cursor()
    try:
        # Check stock availability
        c.execute('SELECT quantity FROM products WHERE id = ?', (product_id,))
        available = c.fetchone()[0]

        if available < quantity:
            st.error(f"Not enough stock available")
            return False

        # Check cart
        c.execute('SELECT id, quantity FROM cart WHERE user_id = ? AND product_id = ?',
                 (user_id, product_id))
        existing = c.fetchone()

        if existing:
            # Update quantity if product already in cart
            new_qty = existing[1] + quantity
            c.execute('UPDATE cart SET quantity = ? WHERE id = ?',
                     (new_qty, existing[0]))
        else:
            # Insert new cart item (id is autoincremented)
            c.execute('INSERT INTO cart (user_id, product_id, quantity) VALUES (?, ?, ?)',
                     (user_id, product_id, quantity))

        conn.commit()
        return True

    except Exception as e:
        st.error(f"Error: {e}")
        return False
    finally:
        conn.close()


def show_cart():
    st.markdown("""
        <style>
        .cart-title {
            color: white;
            font-size: 2.5em;
            margin-bottom: 1em;
        }
        .cart-item {
            background-color: #262730;
            padding: 20px;
            border-radius: 10px;
            margin: 10px 0;
            border: 1px solid #464855;
        }
        .total-section {
            background-color: #262730;
            padding: 20px;
            border-radius: 10px;
            margin-top: 20px;
            border: 1px solid #464855;
        }
        </style>
    """, unsafe_allow_html=True)

    st.markdown('<h1 class="cart-title">My Shopping Cart 🛒</h1>', unsafe_allow_html=True)

    if not st.session_state.user:
        st.error("Please login to view cart")
        return

    conn = sqlite3.connect('farm2market.db')
    c = conn.cursor()

    try:
        c.execute('''
            SELECT 
                c.id, 
                p.id as product_id, 
                p.name, 
                p.description, 
                p.price, 
                c.quantity, 
                p.image, 
                p.quantity as available
            FROM cart c
            JOIN products p ON c.product_id = p.id
            WHERE c.user_id = ?
        ''', (st.session_state.user[0],))

        cart_items = c.fetchall()

        if not cart_items:
            col1, col2, col3 = st.columns([1, 2, 1])
            with col2:
                st.info("Your cart is empty")
                if st.button("🛍️ Start Shopping", type="primary", use_container_width=True):
                    st.session_state.current_page = "Marketplace"
                    st.rerun()
            return

        # Initialize cart total before loop
        cart_total = 0.0

        # Display cart items
        for item in cart_items:
            cart_id, product_id, name, description, price, quantity, image_data, available = item

            with st.container():
                st.markdown('<div class="cart-item">', unsafe_allow_html=True)
                cols = st.columns([1, 2, 1])

                with cols[0]:
                    if image_data:
                        try:
                            image = Image.open(io.BytesIO(image_data))
                            st.image(image, width=150)
                        except:
                            st.write("No image available")

                with cols[1]:
                    st.subheader(name)
                    st.write(description)
                    st.write(f"Price: ₹{float(price):.2f}")

                    # Quantity selector
                    new_quantity = st.number_input(
                        "Quantity",
                        min_value=1,
                        max_value=available,
                        value=quantity,
                        key=f"qty_{cart_id}"
                    )

                    if new_quantity != quantity:
                        c.execute('UPDATE cart SET quantity = ? WHERE id = ?', (new_quantity, cart_id))
                        conn.commit()
                        st.rerun()

                with cols[2]:
                    subtotal = float(price) * quantity
                    cart_total += subtotal
                    st.write(f"Subtotal: ₹{subtotal:.2f}")

                    if st.button("🗑️ Remove", key=f"remove_{cart_id}"):
                        c.execute('DELETE FROM cart WHERE id = ?', (cart_id,))
                        conn.commit()
                        st.rerun()

                st.markdown('</div>', unsafe_allow_html=True)

        # Display total and checkout buttons
        st.markdown('<div class="total-section">', unsafe_allow_html=True)
        cols = st.columns([2, 1, 1])

        with cols[0]:
            st.subheader(f"Total: ₹{cart_total:.2f}")

        with cols[1]:
            if st.button("Continue Shopping", key="continue_shopping", use_container_width=True):
                st.session_state.current_page = "Marketplace"
                st.rerun()

        with cols[2]:
            if st.button("Proceed to Checkout", type="primary", key="checkout_button", use_container_width=True):
                proceed_to_checkout(cart_items=cart_items)

        st.markdown('</div>', unsafe_allow_html=True)

    except Exception as e:
        st.error(f"Error loading cart: {str(e)}")
    finally:
        conn.close()


def display_cart_item(item):
    col1, col2, col3 = st.columns([1, 2, 1])

    with col1:
        if item[6]:
            try:
                image = Image.open(io.BytesIO(item[6]))
                st.image(image, width=150)
            except:
                st.write("No image available")

    with col2:
        st.subheader(item[2])
        st.write(item[3])
        st.write(f"Price: ₹{float(item[4]):.2f}")
        quantity = st.number_input("Quantity", 1, item[7], item[5], key=f"qty_{item[0]}")
        if quantity != item[5]:
            conn = sqlite3.connect('farm2market.db')
            c = conn.cursor()
            try:
                c.execute('UPDATE cart SET quantity = ? WHERE id = ?', (quantity, item[0]))
                conn.commit()
                st.rerun()
            except Exception as e:
                st.error(f"Error updating cart: {str(e)}")
            finally:
                conn.close()

    with col3:
        subtotal = float(item[4]) * item[5]
        st.write(f"Subtotal: ₹{subtotal:.2f}")
        if st.button("Remove", key=f"remove_{item[0]}"):
            conn = sqlite3.connect('farm2market.db')
            c = conn.cursor()
            try:
                c.execute('DELETE FROM cart WHERE id = ?', (item[0],))
                conn.commit()
                st.rerun()
            except Exception as e:
                st.error(f"Error removing from cart: {str(e)}")
            finally:
                conn.close()

def process_all_orders(cart_items):
    conn = sqlite3.connect('farm2market.db')
    c = conn.cursor()
    try:
        for item in cart_items:
            # Check stock availability
            if item[5] > item[7]:
                st.error(f"Not enough stock for {item[2]}")
                return False

            # Create order
            c.execute('''INSERT INTO orders 
                       (user_id, product_id, name, description, 
                        quantity, price, status, image)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                      (st.session_state.user[0], item[1],
                       item[2], item[3], item[5],
                       item[5] * float(item[4]), 'pending', item[6]))

            # Update product quantity
            c.execute('''UPDATE products 
                       SET quantity = quantity - ? 
                       WHERE id = ?''',
                      (item[5], item[1]))

        # Clear cart
        c.execute('DELETE FROM cart WHERE user_id = ?', (st.session_state.user[0],))

        conn.commit()
        return True

    except Exception as e:
        conn.rollback()
        st.error(f"Error processing orders: {str(e)}")
        return False
    finally:
        conn.close()

def safe_float(value, default=0.0):
    if value is None:
        return default
    try:
        return float(value)
    except (ValueError, TypeError):
        return default

def safe_int(value, default=0):
    if value is None:
        return default
    try:
        return int(value)
    except (ValueError, TypeError):
        return default


def display_order_progress(current_status):
    st.markdown("""
        <style>
        .progress-section {
            margin: 30px 0;
            padding: 40px 20px 20px;
            background: rgba(0, 0, 0, 0.2);
            border-radius: 12px;
            position: relative;
        }

        .steps-container {
            display: flex;
            justify-content: space-between;
            margin: 0 5%;
            position: relative;
        }

        .step-dot {
            width: 30px;
            height: 30px;
            background: #1E1E1E;
            border: 2px solid #333;
            border-radius: 50%;
            margin: 0 auto 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 14px;
            color: #94A3B8;
            position: relative;
            z-index: 2;
        }

        .step {
            flex: 1;
            text-align: center;
            position: relative;
        }

        .step.active .step-dot {
            background: #2ECC71;
            border-color: #27AE60;
            color: white;
        }

        .step-label {
            font-size: 0.9rem;
            color: #94A3B8;
            margin-top: 8px;
        }

        .step.active .step-label {
            color: #2ECC71;
            font-weight: 500;
        }

        .progress-line {
            position: absolute;
            top: 55px;
            left: 10%;
            right: 10%;
            height: 3px;
            background: #333;
            z-index: 1;
        }

        .progress-fill {
            position: absolute;
            left: 0;
            top: 0;
            height: 100%;
            background: #2ECC71;
            transition: width 0.3s ease;
        }
        </style>
    """, unsafe_allow_html=True)

    steps = [
        {'number': '1', 'label': 'Pending'},
        {'number': '2', 'label': 'Processing'},
        {'number': '3', 'label': 'Shipped'},
        {'number': '4', 'label': 'Delivered'}
    ]

    # Calculate active step
    status_map = {
        'pending': 0,
        'processing': 1,
        'shipped': 2,
        'delivered': 3,
        'cancelled': -1
    }
    active_step = status_map.get(current_status.lower(), 0)
    progress_width = 0 if active_step < 0 else (active_step / (len(steps) - 1)) * 100

    # Generate HTML
    html = f"""
        <div class="progress-section">
            <div class="steps-container">
                <div class="progress-line">
                    <div class="progress-fill" style="width: {progress_width}%;"></div>
                </div>
    """

    for i, step in enumerate(steps):
        is_active = 'active' if i <= active_step and active_step >= 0 else ''
        html += f"""
            <div class="step {is_active}">
                <div class="step-dot">{step['number']}</div>
                <div class="step-label">{step['label']}</div>
            </div>
        """

    html += """
            </div>
        </div>
    """

    return html


def display_order_details(order, conn, c):
    # Display order basic details
    st.markdown(f"""
        <div style="background: #1E1E1E; padding: 20px; border-radius: 12px; margin-bottom: 20px;">
            <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 16px;">
                <div style="background: rgba(0,0,0,0.2); padding: 15px; border-radius: 8px;">
                    <div style="color: #94A3B8; font-size: 0.9rem;">Product</div>
                    <div style="color: #E2E8F0; font-size: 1.1rem; font-weight: 500;">{order[-1]}</div>
                </div>
                <div style="background: rgba(0,0,0,0.2); padding: 15px; border-radius: 8px;">
                    <div style="color: #94A3B8; font-size: 0.9rem;">Quantity</div>
                    <div style="color: #E2E8F0; font-size: 1.1rem; font-weight: 500;">{order[5]}</div>
                </div>
                <div style="background: rgba(0,0,0,0.2); padding: 15px; border-radius: 8px;">
                    <div style="color: #94A3B8; font-size: 0.9rem;">Price per item</div>
                    <div style="color: #E2E8F0; font-size: 1.1rem; font-weight: 500;">₹{float(order[6]) / float(order[5]):.2f}</div>
                </div>
                <div style="background: rgba(0,0,0,0.2); padding: 15px; border-radius: 8px;">
                    <div style="color: #94A3B8; font-size: 0.9rem;">Total Amount</div>
                    <div style="color: #E2E8F0; font-size: 1.1rem; font-weight: 500;">₹{float(order[6]):.2f}</div>
                </div>
            </div>
        </div>
    """, unsafe_allow_html=True)

    # Display progress tracker
    progress_html = display_order_progress(order[7])
    st.markdown(progress_html, unsafe_allow_html=True)

    # Cancel order functionality
    if order[7].lower() in ['pending', 'processing']:
        col1, col2 = st.columns([1, 3])
        with col1:
            if st.button("Cancel Order", key=f"cancel_{order[0]}", type="primary"):
                st.warning("⚠️ Are you sure you want to cancel this order?")
                if st.button("✅ Yes, Cancel", key=f"confirm_{order[0]}"):
                    try:
                        c.execute("""
                            UPDATE orders SET status = 'cancelled' 
                            WHERE id = ? AND user_id = ?
                        """, (order[0], st.session_state.user[0]))

                        # Restore product quantity
                        c.execute("""
                            UPDATE products SET quantity = quantity + ? 
                            WHERE id = ?
                        """, (order[5], order[2]))

                        conn.commit()
                        st.success("Order cancelled successfully!")
                        time.sleep(1)
                        st.rerun()
                    except Exception as e:
                        conn.rollback()
                        st.error(f"Error cancelling order: {str(e)}")


def get_progress_width(status):
    progress_map = {
        'pending': 0,
        'processing': 33,
        'shipped': 66,
        'delivered': 100,
        'cancelled': 0
    }
    return progress_map.get(status.lower(), 0)


def generate_step_html(current_status):
    steps = ['Pending', 'Processing', 'Shipped', 'Delivered']
    current_idx = steps.index(current_status.capitalize()) if current_status.capitalize() in steps else -1

    steps_html = []
    for i, step in enumerate(steps):
        is_active = i <= current_idx
        step_html = f"""
            <div class="step {'active' if is_active else ''}">
                <div class="step-dot">
                    {'✓' if is_active else ''}
                </div>
                <div class="step-label">{step}</div>
            </div>
        """
        steps_html.append(step_html)

    return '\n'.join(steps_html)


# Update the show_orders function to use this new display
def show_orders():
    if not st.session_state.user:
        st.error("Please login to view orders")
        return

    conn = sqlite3.connect('farm2market.db')
    c = conn.cursor()

    try:
        # Initialize session state for cancel confirmation
        for key in st.session_state:
            if key.startswith('show_cancel_') and st.session_state[key]:
                order_id = key.split('_')[-1]
                if f'cancelled_{order_id}' not in st.session_state:
                    st.session_state[f'cancelled_{order_id}'] = False

        # Get orders
        c.execute('''SELECT o.*, p.name as product_name 
                    FROM orders o
                    LEFT JOIN products p ON o.product_id = p.id
                    WHERE o.user_id = ?
                    ORDER BY o.order_date DESC''', (st.session_state.user[0],))
        orders = c.fetchall()

        if not orders:
            st.info("No orders found")
            return

        # Display each order
        for order in orders:
            with st.container():
                col1, col2 = st.columns([3, 1])
                with col1:
                    st.subheader(f"Order #{order[0]}")
                    st.text(f"Order Date: {order[8]}")
                with col2:
                    status_color = {
                        'pending': 'orange',
                        'processing': 'blue',
                        'shipped': 'purple',
                        'delivered': 'green',
                        'cancelled': 'red'
                    }
                    st.markdown(f"""
                        <div style="
                            background-color: {status_color.get(order[7].lower(), 'grey')};
                            color: white;
                            padding: 5px 10px;
                            border-radius: 15px;
                            text-align: center;
                            font-weight: bold;
                        ">
                            {order[7].upper()}
                        </div>
                    """, unsafe_allow_html=True)

                # Order details
                st.markdown("---")
                details_col1, details_col2 = st.columns(2)
                with details_col1:
                    st.markdown("**Order Details**")
                    st.write(f"Product: {order[-1]}")
                    st.write(f"Quantity: {order[5]}")
                    st.write(f"Price per item: ₹{float(order[6]) / float(order[5]):.2f}")
                    st.write(f"Total Amount: ₹{float(order[6]):.2f}")

                # Cancel order button and confirmation
                if order[7].lower() in ['pending', 'processing']:
                    cancel_key = f'show_cancel_{order[0]}'
                    if cancel_key not in st.session_state:
                        st.session_state[cancel_key] = False

                    if not st.session_state[cancel_key]:
                        if st.button("Cancel Order", key=f"cancel_btn_{order[0]}"):
                            st.session_state[cancel_key] = True
                            st.rerun()

                    if st.session_state[cancel_key]:
                        st.warning("⚠️ Are you sure you want to cancel this order?")
                        col1, col2 = st.columns(2)

                        with col1:
                            if st.button("Yes, Cancel", key=f"confirm_cancel_{order[0]}"):
                                try:
                                    # Start transaction
                                    c.execute('BEGIN TRANSACTION')

                                    # Update order status
                                    c.execute("""
                                        UPDATE orders SET status = 'cancelled' 
                                        WHERE id = ? AND user_id = ?
                                    """, (order[0], st.session_state.user[0]))

                                    # Restore product quantity
                                    c.execute("""
                                        UPDATE products SET quantity = quantity + ? 
                                        WHERE id = ?
                                    """, (order[5], order[2]))

                                    # Commit transaction
                                    conn.commit()

                                    st.session_state[cancel_key] = False
                                    st.success("Order cancelled successfully!")
                                    time.sleep(1)
                                    st.rerun()

                                except Exception as e:
                                    conn.rollback()
                                    st.error(f"Error cancelling order: {str(e)}")

                        with col2:
                            if st.button("No, Keep Order", key=f"keep_{order[0]}"):
                                st.session_state[cancel_key] = False
                                st.rerun()

                st.markdown("---")

    except Exception as e:
        st.error(f"Error loading orders: {str(e)}")
    finally:
        conn.close()


def show_order_details(order):
    # Display order details grid
    st.markdown(f"""
        <style>
        .order-card {
    background: #1E1E1E;
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 20px;
        }

        .details-grid {
    display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 16px;
        }

        .detail-item {
    background: rgba(0, 0, 0, 0.2);
            padding: 16px;
            border-radius: 8px;
        }

        .detail-label {
    color: #94A3B8;
            font-size: 0.9rem;
            margin-bottom: 4px;
        }

        .detail-value {
    color: #E2E8F0;
            font-size: 1.1rem;
            font-weight: 500;
        }
        </style>

        <div class="order-card">
            <div class="details-grid">
                <div class="detail-item">
                    <div class="detail-label">Product</div>
                    <div class="detail-value">{order[-1]}</div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">Quantity</div>
                    <div class="detail-value">{order[5]}</div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">Price per item</div>
                    <div class="detail-value">₹{float(order[6]) / float(order[5]):.2f}</div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">Total Amount</div>
                    <div class="detail-value">₹{float(order[6]):.2f}</div>
                </div>
            </div>
        </div>
    """, unsafe_allow_html=True)

    # Display progress tracker
    progress_html = display_order_progress(order[7])
    st.markdown(progress_html, unsafe_allow_html=True)


# Add this helper function to update order status
def update_order_status():
    conn = sqlite3.connect('farm2market.db')
    c = conn.cursor()
    try:
        # Set default status for orders without status
        c.execute('''UPDATE orders 
                    SET status = 'pending' 
                    WHERE status IS NULL OR status = ''''')
        conn.commit()
    except Exception as e:
        print(f"Error updating order statuses: {e}")
    finally:
        conn.close()


def show_seller_profile(seller_id):
    """Display seller profile and products"""
    conn = sqlite3.connect('farm2market.db')
    c = conn.cursor()

    try:
        # Get seller info
        c.execute('''SELECT username, license_verified 
                    FROM users 
                    WHERE id = ? AND user_type = 'seller' ''', (seller_id,))
        result = c.fetchone()

        if result:
            username, verified = result

            st.header(f"Seller Profile: {username}")
            if verified:
                st.markdown("✅ **Verified Seller**")

            # Get seller's products
            c.execute('''SELECT * FROM products 
                        WHERE seller_id = ? AND quantity > 0
                        ORDER BY date_added DESC''', (seller_id,))
            products = c.fetchall()

            if products:
                st.subheader("Available Products")

                for product in products:
                    with st.container():
                        col1, col2 = st.columns([1, 2])

                        with col1:
                            if product[7]:  # image
                                try:
                                    image = Image.open(io.BytesIO(product[7]))
                                    st.image(image, width=150)
                                except:
                                    st.write("No image available")

                        with col2:
                            st.subheader(product[2])  # name
                            st.write(product[3])  # description
                            st.write(f"Price: ₹{float(product[4]):.2f}")
                            st.write(f"Available: {product[5]}")

                            if st.session_state.user and st.session_state.user[3] == 'buyer':
                                quantity = st.number_input(
                                    "Quantity",
                                    min_value=1,
                                    max_value=product[5],
                                    value=1,
                                    key=f"qty_{product[0]}"
                                )

                                if st.button("Add to Cart", key=f"add_{product[0]}"):
                                    if add_to_cart(st.session_state.user[0], product[0], quantity):
                                        st.success("Added to cart!")
            else:
                st.info("No products available from this seller")
        else:
            st.error("Seller not found")

    finally:
        conn.close()


def get_product_categories():
    """Return the list of available product categories"""
    return ["All", "Crops", "Dairy", "Fruits", "Vegetables", "Spices", "Other"]


def show_seller_orders():
    st.title("Orders for My Products")

    if not st.session_state.user or st.session_state.user[3] != 'seller':
        st.error("Access denied")
        return

    conn = sqlite3.connect('farm2market.db')
    c = conn.cursor()

    try:
        # Join orders with products to get seller's orders
        c.execute('''
            SELECT o.*, p.name as product_name 
            FROM orders o
            JOIN products p ON o.product_id = p.id
            WHERE p.seller_id = ?
            ORDER BY o.order_date DESC
        ''', (st.session_state.user[0],))

        orders = c.fetchall()

        status_filter = st.selectbox(
            "Filter by Status",
            ["All Orders", "Pending", "Processing", "Shipped", "Delivered", "Cancelled"]
        )

        total_orders = len(orders)
        cancelled_orders = len([o for o in orders if o[7].lower() == 'cancelled'])
        active_orders = total_orders - cancelled_orders

        # Order statistics
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Orders", total_orders)
        with col2:
            st.metric("Active Orders", active_orders)
        with col3:
            st.metric("Cancelled Orders", cancelled_orders)

        for order in orders:
            current_status = order[7].lower() if order[7] else 'pending'

            if status_filter != "All Orders" and current_status != status_filter.lower():
                continue

            with st.container():
                st.markdown("""<div style="border: 1px solid #ddd; padding: 15px; 
                          border-radius: 10px; margin: 10px 0;">""", unsafe_allow_html=True)

                col1, col2 = st.columns([3, 1])
                with col1:
                    st.subheader(f"Order #{order[0]}")
                    st.write(f"Product: {order[-1]}")  # product_name from JOIN
                with col2:
                    status_colors = {
                        'pending': '#FFA500',
                        'processing': '#3498DB',
                        'shipped': '#9B59B6',
                        'delivered': '#2ECC71',
                        'cancelled': '#E74C3C'
                    }
                    st.markdown(f"""
                        <div style="background-color: {status_colors.get(current_status, '#95A5A6')}; 
                        color: white; padding: 5px 10px; border-radius: 15px; 
                        text-align: center; font-weight: bold;">
                            {current_status.upper()}
                        </div>
                    """, unsafe_allow_html=True)

                col1, col2 = st.columns(2)
                with col1:
                    st.write("**Order Details:**")
                    st.write(f"Quantity: {order[5]}")
                    st.write(f"Price: ₹{float(order[6]):.2f}")
                    if current_status == 'cancelled':
                        st.error("⚠️ Order was cancelled by the buyer")

                with col2:
                    st.write("**Customer Information:**")
                    st.write(f"Name: {order[10]}")  # shipping_name
                    st.write(f"City: {order[14]}")  # shipping_city
                    st.write(f"Order Date: {order[8]}")

                # Show order status actions for non-cancelled orders
                if current_status not in ['cancelled', 'delivered']:
                    new_status = st.selectbox(
                        "Update Order Status",
                        ["processing", "shipped", "delivered"],
                        key=f"status_{order[0]}"
                    )
                    if st.button("Update Status", key=f"update_{order[0]}"):
                        c.execute('UPDATE orders SET status = ? WHERE id = ?',
                                  (new_status, order[0]))
                        conn.commit()
                        st.success(f"Order status updated to {new_status}")
                        time.sleep(1)
                        st.rerun()

                st.markdown("</div>", unsafe_allow_html=True)

        if not orders:
            st.info("No orders found")

    except Exception as e:
        st.error(f"Error fetching orders: {str(e)}")
    finally:
        conn.close()


def show_marketplace():
    st.title("Farm2Market Marketplace")

    # Add search and filter options
    col1, col2 = st.columns([2, 1])
    with col1:
        search = st.text_input("🔍 Search products")
    with col2:
        category = st.selectbox(
            "Category",
            ["All", "Crops", "Dairy", "Fruits", "Vegetables", "Spices", "Other"]
        )

    conn = sqlite3.connect('farm2market.db')
    c = conn.cursor()

    try:
        # Build query
        query = "SELECT * FROM products WHERE quantity > 0"
        params = []

        if search:
            query += " AND (name LIKE ? OR description LIKE ?)"
            params.extend([f"%{search}%", f"%{search}%"])

        if category != "All":
            query += " AND category = ?"
            params.append(category)

        c.execute(query, tuple(params))
        products = c.fetchall()

        if not products:
            st.info("No products found")
            return

        # Display products in grid
        cols = st.columns(3)
        for idx, product in enumerate(products):
            with cols[idx % 3]:
                with st.container():
                    if product[7]:  # image
                        try:
                            image = Image.open(io.BytesIO(product[7]))
                            st.image(image, use_column_width=True)
                        except:
                            st.warning("Image not available")

                    st.subheader(product[2])  # name
                    st.write(product[3])  # description
                    st.write(f"Price: ₹{float(product[4]):.2f}")
                    st.write(f"Available: {product[5]}")
                    st.write(f"Category: {product[6]}")

                    if st.session_state.user and st.session_state.user[3] == 'buyer':
                        quantity = st.number_input(
                            "Quantity",
                            min_value=1,
                            max_value=product[5],
                            value=1,
                            key=f"qty_{product[0]}"
                        )
                        st.markdown("---")
                        show_product_reviews_and_rating(product[0])

                        if st.button("Add to Cart", key=f"add_{product[0]}"):
                            if add_to_cart(st.session_state.user[0], product[0], quantity):
                                st.success("Added to cart!")
                                time.sleep(0.5)
                                st.rerun()
    finally:
        conn.close()


def show_admin_panel():
    if not st.session_state.user or st.session_state.user[3] != 'admin':
        st.error("Access denied")
        return

    tab1, tab2, tab3 = st.tabs(["Seller Verification", "User Management", "Orders"])

    with tab1:
        show_seller_verification()

    with tab2:
        show_user_management()

    with tab3:
        show_admin_orders()


def show_admin_orders():
    conn = sqlite3.connect('farm2market.db')
    c = conn.cursor()

    try:
        c.execute('''
            SELECT o.*, p.name as product_name, u.username as buyer_name, s.username as seller_name
            FROM orders o
            JOIN products p ON o.product_id = p.id
            JOIN users u ON o.user_id = u.id
            JOIN users s ON p.seller_id = s.id
            ORDER BY o.order_date DESC
        ''')
        orders = c.fetchall()

        status_filter = st.selectbox(
            "Filter by Status",
            ["All Orders", "Pending", "Processing", "Shipped", "Delivered", "Cancelled"]
        )

        # Order Statistics
        total_orders = len(orders)
        cancelled_orders = len([o for o in orders if o[7].lower() == 'cancelled'])
        active_orders = total_orders - cancelled_orders
        total_revenue = sum(float(o[6]) for o in orders if o[7].lower() != 'cancelled')

        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Orders", total_orders)
        with col2:
            st.metric("Active Orders", active_orders)
        with col3:
            st.metric("Cancelled Orders", cancelled_orders)
        with col4:
            st.metric("Total Revenue", f"₹{total_revenue:.2f}")

        for order in orders:
            current_status = order[7].lower() if order[7] else 'pending'

            if status_filter != "All Orders" and current_status != status_filter.lower():
                continue

            with st.container():
                st.markdown("""
                    <div style="border: 1px solid #ddd; padding: 15px; 
                    border-radius: 10px; margin: 10px 0; background-color: white;">
                """, unsafe_allow_html=True)

                col1, col2 = st.columns([3, 1])
                with col1:
                    st.subheader(f"Order #{order[0]}")
                with col2:
                    status_colors = {
                        'pending': '#FFA500',
                        'processing': '#3498DB',
                        'shipped': '#9B59B6',
                        'delivered': '#2ECC71',
                        'cancelled': '#E74C3C'
                    }
                    st.markdown(f"""
                        <div style="background-color: {status_colors.get(current_status, '#95A5A6')}; 
                        color: white; padding: 5px 10px; border-radius: 15px; 
                        text-align: center; font-weight: bold;">
                            {current_status.upper()}
                        </div>
                    """, unsafe_allow_html=True)

                col1, col2, col3 = st.columns(3)
                with col1:
                    st.write("**Order Details:**")
                    st.write(f"Product: {order[-3]}")  # product_name
                    st.write(f"Quantity: {order[5]}")
                    st.write(f"Total: ₹{float(order[6]):.2f}")

                with col2:
                    st.write("**Customer Details:**")
                    st.write(f"Buyer: {order[-2]}")  # buyer_name
                    st.write(f"Seller: {order[-1]}")  # seller_name
                    st.write(f"Order Date: {order[8]}")

                with col3:
                    st.write("**Shipping Details:**")
                    st.write(f"Name: {order[10]}")
                    st.write(f"Address: {order[13]}")
                    st.write(f"City: {order[14]}, {order[15]}")

                if current_status == 'cancelled':
                    st.error("⚠️ This order was cancelled by the buyer")

                st.markdown("</div>", unsafe_allow_html=True)

        if not orders:
            st.info("No orders found")

    except Exception as e:
        st.error(f"Error fetching orders: {str(e)}")
    finally:
        conn.close()


def edit_product(product_id):
    # Implementation for editing product
    st.error("Edit functionality not implemented yet")


def delete_product(product_id):
    """Delete a product and its related data from the database"""
    conn = sqlite3.connect('farm2market.db')
    c = conn.cursor()

    try:
        # Begin transaction
        c.execute('BEGIN TRANSACTION')

        # Delete related reviews
        c.execute('DELETE FROM reviews WHERE product_id = ?', (product_id,))

        # Delete related cart items
        c.execute('DELETE FROM cart WHERE product_id = ?', (product_id,))

        # Delete related orders (or update them to mark product as deleted)
        c.execute('''UPDATE orders 
                    SET description = description || ' (Product Deleted)'
                    WHERE product_id = ?''', (product_id,))

        # Finally delete the product
        c.execute('DELETE FROM products WHERE id = ?', (product_id,))

        # Commit all changes
        conn.commit()
        return True

    except Exception as e:
        conn.rollback()
        print(f"Error deleting product: {e}")
        return False
    finally:
        conn.close()


def show_checkout(cart_items):
    col1, col2 = st.columns([1, 5])
    with col1:
        if st.button("← Back"):
            st.session_state.current_page = st.session_state.get('previous_page', 'My Cart')
            st.rerun()
    with col2:
        st.title("Checkout 🛍️")

    # Order Summary
    st.header("Order Summary")
    total_amount = 0

    with st.container():
        for item in cart_items:
            col1, col2, col3 = st.columns([2, 1, 1])
            with col1:
                st.write(f"**{item[2]}**")  # Product name
            with col2:
                st.write(f"Quantity: {item[5]}")
            with col3:
                subtotal = float(item[4]) * item[5]
                st.write(f"₹{subtotal:.2f}")
                total_amount += subtotal

        st.markdown("---")
        st.subheader(f"Total Amount: ₹{total_amount:.2f}")

    # Checkout Form
    with st.form("checkout_form"):
        st.header("Shipping Information")

        col1, col2 = st.columns(2)
        with col1:
            name = st.text_input("Full Name*")
            email = st.text_input("Email*")
            phone = st.text_input("Phone Number*")

        with col2:
            address = st.text_area("Delivery Address*")
            city = st.text_input("City*")
            state = st.text_input("State*")
            pincode = st.text_input("PIN Code*")

        st.header("Payment Method")
        payment_method = st.selectbox(
            "Select Payment Method*",
            ["Cash on Delivery", "UPI", "Net Banking", "Card Payment"]
        )

        # Terms and conditions
        terms = st.checkbox("I agree to the terms and conditions*")

        submit = st.form_submit_button("Place Order", use_container_width=True)

        if submit:
            if not all([name, email, phone, address, city, state, pincode]):
                st.error("Please fill in all required fields")
                return

            if not terms:
                st.error("Please accept the terms and conditions")
                return

            # Basic validation
            if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
                st.error("Please enter a valid email address")
                return

            if not re.match(r"^\d{6}$", pincode):
                st.error("Please enter a valid 6-digit PIN code")
                return

            try:
                conn = sqlite3.connect('farm2market.db')
                c = conn.cursor()

                # Start transaction
                c.execute('BEGIN TRANSACTION')

                for item in cart_items:
                    # Create order for each cart item
                    c.execute('''INSERT INTO orders 
                                (user_id, product_id, name, description, quantity, price,
                                 status, shipping_name, shipping_email, shipping_phone,
                                 shipping_address, shipping_city, shipping_state,
                                 shipping_pincode, payment_method)
                                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                              (st.session_state.user[0], item[1], item[2], item[3],
                               item[5], float(item[4]) * item[5], 'pending',
                               name, email, phone, address, city, state, pincode,
                               payment_method))

                    # Update product quantity
                    c.execute('''UPDATE products 
                                SET quantity = quantity - ? 
                                WHERE id = ?''', (item[5], item[1]))

                # Clear user's cart
                c.execute('DELETE FROM cart WHERE user_id = ?',
                          (st.session_state.user[0],))

                # Commit transaction
                c.execute('COMMIT')

                st.success("Order placed successfully! 🎉")
                st.balloons()

                time.sleep(2)
                st.session_state.current_page = "My Orders"
                st.rerun()

            except Exception as e:
                c.execute('ROLLBACK')
                st.error(f"Error processing order: {str(e)}")
            finally:
                conn.close()


def process_checkout(name, email, phone, address, city, state, pincode,
                     payment_method, terms, product, quantity, cart_items, total_amount):
    # Validation
    if not all([name, email, phone, address, city, state, pincode]):
        st.error("Please fill all required fields")
        return False

    if not terms:
        st.error("Please accept the terms and conditions")
        return False

    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        st.error("Please enter a valid email address")
        return False

    if not re.match(r"^\d{6}$", pincode):
        st.error("Please enter a valid 6-digit PIN code")
        return False

    try:
        conn = sqlite3.connect('farm2market.db')
        c = conn.cursor()

        if product:
            c.execute('''INSERT INTO orders 
                        (user_id, product_id, name, description, quantity, price,
                        status, shipping_name, shipping_email, shipping_phone,
                        shipping_address, shipping_city, shipping_state,
                        shipping_pincode, payment_method)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                      (st.session_state.user[0], product[0], product[2], product[3],
                       quantity, total_amount, 'pending', name, email, phone,
                       address, city, state, pincode, payment_method))

            c.execute('UPDATE products SET quantity = quantity - ? WHERE id = ?',
                      (quantity, product[0]))

        elif cart_items:
            for item in cart_items:
                c.execute('''INSERT INTO orders 
                            (user_id, product_id, name, description, quantity,
                            price, status, shipping_name, shipping_email,
                            shipping_phone, shipping_address, shipping_city,
                            shipping_state, shipping_pincode, payment_method)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                          (st.session_state.user[0], item[1], item[2], item[3],
                           item[5], float(item[4]) * item[5], 'pending', name,
                           email, phone, address, city, state, pincode,
                           payment_method))

                c.execute('UPDATE products SET quantity = quantity - ? WHERE id = ?',
                          (item[5], item[1]))

            c.execute('DELETE FROM cart WHERE user_id = ?',
                      (st.session_state.user[0],))

        conn.commit()
        st.success("Order placed successfully!")
        time.sleep(1)
        return True

    except Exception as e:
        st.error(f"Error placing order: {str(e)}")
        return False
    finally:
        conn.close()


def calculate_total(product, quantity, cart_items):
    if product:
        return float(product[4]) * quantity
    elif cart_items:
        return sum(float(item[4]) * item[5] for item in cart_items)
    return 0


def display_order_summary(product, quantity, cart_items, total_amount):
    if product:
        st.write(f"Product: {product[2]}")
        st.write(f"Quantity: {quantity}")
    elif cart_items:
        for item in cart_items:
            st.write(f"Product: {item[2]} × {item[5]}")
            st.write(f"Subtotal: ${float(item[4]) * item[5]:.2f}")
    st.write(f"**Total Amount: ${total_amount:.2f}**")


def collect_shipping_details():
    return {
        "name": st.text_input("Full Name*"),
        "email": st.text_input("Email*"),
        "phone": st.text_input("Phone Number*"),
        "address": st.text_area("Delivery Address*"),
        "city": st.text_input("City*"),
        "state": st.text_input("State*"),
        "pincode": st.text_input("PIN Code*")
    }


def validate_shipping_details(details):
    required_fields = {
        "name": "Full Name",
        "email": "Email",
        "phone": "Phone Number",
        "address": "Delivery Address",
        "city": "City",
        "state": "State",
        "pincode": "PIN Code"
    }

    missing_fields = [field for field, value in details.items() if not value.strip()]
    if missing_fields:
        st.error(
            f"Please fill in the following required fields: {', '.join(required_fields[f] for f in missing_fields)}")
        return False

    if not re.match(r"[^@]+@[^@]+\.[^@]+", details["email"]):
        st.error("Please enter a valid email address")
        return False

    if not re.match(r"^\d{6}$", details["pincode"]):
        st.error("Please enter a valid 6-digit PIN code")
        return False

    return True


def process_order(shipping_details, payment_method, product, quantity, cart_items, total_amount):
    try:
        conn = sqlite3.connect('farm2market.db')
        c = conn.cursor()

        if product:
            create_single_order(c, product, quantity, shipping_details, payment_method, total_amount)
        elif cart_items:
            create_cart_orders(c, cart_items, shipping_details, payment_method)

        conn.commit()
        return True

    except Exception as e:
        st.error(f"Error placing order: {str(e)}")
        return False
    finally:
        conn.close()


def proceed_to_checkout(product=None, quantity=None, cart_items=None):
    if product:
        st.session_state.checkout_product = product
        st.session_state.checkout_quantity = quantity
    else:
        st.session_state.checkout_product = None
        st.session_state.checkout_quantity = None
        st.session_state.checkout_cart_items = cart_items

    # Update to ensure the Checkout page is in the list of pages for the user
    if st.session_state.user[3] == 'buyer':
        if "Checkout" not in st.session_state.pages:
            st.session_state.pages = list(st.session_state.pages) + ["Checkout"]

    st.session_state.previous_page = st.session_state.current_page
    st.session_state.checkout_cart_items = cart_items
    st.session_state.current_page = "Checkout"
    st.rerun()

# Add new table for reviews
def init_review_system():
    conn = sqlite3.connect('farm2market.db')
    c = conn.cursor()

    try:
        # Create reviews table
        c.execute('''CREATE TABLE IF NOT EXISTS reviews (
            id INTEGER PRIMARY KEY,
            product_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            rating INTEGER NOT NULL,
            comment TEXT,
            review_date DATETIME DEFAULT CURRENT_TIMESTAMP,
            seller_reply TEXT,
            reply_date DATETIME,
            FOREIGN KEY (product_id) REFERENCES products (id),
            FOREIGN KEY (user_id) REFERENCES users (id),
            CHECK (rating >= 1 AND rating <= 5)
        )''')

        conn.commit()
        print("Review system initialized successfully")

    except Exception as e:
        print(f"Error initializing review system: {str(e)}")
        conn.rollback()
    finally:
        conn.close()


def add_review(product_id: int, user_id: int, rating: int, comment: str) -> bool:
    conn = sqlite3.connect('farm2market.db')
    c = conn.cursor()

    try:
        # Check if user has already reviewed this product
        c.execute('''SELECT id FROM reviews 
                    WHERE product_id = ? AND user_id = ?''',
                  (product_id, user_id))
        existing_review = c.fetchone()

        if existing_review:
            # Update existing review
            c.execute('''UPDATE reviews 
                        SET rating = ?, comment = ?, review_date = CURRENT_TIMESTAMP 
                        WHERE product_id = ? AND user_id = ?''',
                      (rating, comment, product_id, user_id))
        else:
            # Add new review
            c.execute('''INSERT INTO reviews 
                        (product_id, user_id, rating, comment)
                        VALUES (?, ?, ?, ?)''',
                      (product_id, user_id, rating, comment))

        conn.commit()
        return True

    except Exception as e:
        print(f"Error adding review: {str(e)}")
        return False
    finally:
        conn.close()


def add_seller_reply(review_id: int, reply: str) -> bool:
    conn = sqlite3.connect('farm2market.db')
    c = conn.cursor()

    try:
        c.execute('''UPDATE reviews 
                    SET seller_reply = ?, reply_date = CURRENT_TIMESTAMP 
                    WHERE id = ?''',
                  (reply, review_id))
        conn.commit()
        return True

    except Exception as e:
        print(f"Error adding reply: {str(e)}")
        return False
    finally:
        conn.close()


def get_product_reviews(product_id: int) -> list:
    conn = sqlite3.connect('farm2market.db')
    c = conn.cursor()

    try:
        c.execute('''SELECT r.*, u.username 
                    FROM reviews r
                    JOIN users u ON r.user_id = u.id
                    WHERE r.product_id = ?
                    ORDER BY r.review_date DESC''',
                  (product_id,))
        return c.fetchall()
    finally:
        conn.close()


def show_product_reviews(product_id: int, is_seller: bool = False):
    reviews = get_product_reviews(product_id)

    if not reviews:
        st.info("No reviews yet")
        return

    # Calculate average rating
    avg_rating = sum(review[3] for review in reviews) / len(reviews)
    st.metric("Average Rating", f"{'⭐' * round(avg_rating)} ({avg_rating:.1f})")

    for review in reviews:
        with st.container():
            st.markdown("""
                <style>
                .review-card {
                    border: 1px solid #ddd;
                    border-radius: 10px;
                    padding: 15px;
                    margin: 10px 0;
                }
                </style>
            """, unsafe_allow_html=True)

            st.markdown('<div class="review-card">', unsafe_allow_html=True)

            # Review header
            col1, col2 = st.columns([3, 1])
            with col1:
                st.write(f"**{review[-1]}**")  # username
                st.write(f"{'⭐' * review[3]}")  # rating
            with col2:
                st.write(f"*{review[5]}*")  # review_date

            # Review content
            st.write(review[4])  # comment

            # Seller reply section
            if review[6]:  # if there's a reply
                st.markdown("""
                    <div style='background-color: #f0f2f6; padding: 10px; border-radius: 5px; margin-top: 10px;'>
                        <p><strong>Seller's Reply:</strong></p>
                        <p>{}</p>
                        <p><em>{}</em></p>
                    </div>
                """.format(review[6], review[7]), unsafe_allow_html=True)
            elif is_seller:
                with st.expander("Reply to this review"):
                    reply = st.text_area("Your reply", key=f"reply_{review[0]}")
                    if st.button("Submit Reply", key=f"submit_reply_{review[0]}"):
                        if add_seller_reply(review[0], reply):
                            st.success("Reply added successfully!")
                            st.rerun()

            st.markdown('</div>', unsafe_allow_html=True)


# Add review form for buyers
def show_review_form(product_id: int):
    with st.form(key=f"review_form_{product_id}"):
        st.write("Write a Review")
        rating = st.slider("Rating", 1, 5, 5)
        comment = st.text_area("Your Review")
        submit = st.form_submit_button("Submit Review")

        if submit:
            if add_review(product_id, st.session_state.user[0], rating, comment):
                st.success("Review submitted successfully!")
                st.rerun()
            else:
                st.error("Error submitting review")


def generate_user_qr(user_id, username, user_type):
    """Generate QR code for a user"""
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    # Encode user data
    data = f"farm2market://{user_id}:{username}:{user_type}"
    qr.add_data(data)
    qr.make(fit=True)

    # Create QR code image
    img = qr.make_image(fill_color="black", back_color="white")

    # Convert to bytes
    img_byte_arr = BytesIO()
    img.save(img_byte_arr, format='PNG')
    img_byte_arr = img_byte_arr.getvalue()

    return img_byte_arr


def save_user_qr(user_id):
    """Save QR code to database"""
    conn = sqlite3.connect('farm2market.db')
    c = conn.cursor()

    try:
        # Get user info
        c.execute('SELECT username, user_type FROM users WHERE id = ?', (user_id,))
        username, user_type = c.fetchone()

        # Generate QR code
        qr_code = generate_user_qr(user_id, username, user_type)

        # Save to database
        c.execute('''INSERT OR REPLACE INTO user_qr_codes (user_id, qr_code)
                    VALUES (?, ?)''', (user_id, qr_code))
        conn.commit()
        return True
    except Exception as e:
        print(f"Error saving QR code: {e}")
        return False
    finally:
        conn.close()


def scan_qr_code(image):
    """Scan QR code using OpenCV"""
    try:
        # Initialize QR code detector
        qr_detector = cv2.QRCodeDetector()

        # Convert image to grayscale
        if len(image.shape) == 3:
            gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
        else:
            gray = image

        # Detect and decode QR code
        retval, decoded_info, points, straight_qrcode = qr_detector.detectAndDecodeMulti(gray)

        if retval and decoded_info:
            return decoded_info[0]  # Return first detected QR code
        return None

    except Exception as e:
        print(f"Error scanning QR code: {e}")
        return None


def show_qr_scanner():
    st.title("📱 QR Code Scanner")
    st.write("Scan QR codes to quickly find sellers and products")

    # Upload QR code image
    uploaded_file = st.file_uploader(
        "Upload QR Code Image",
        type=['png', 'jpg', 'jpeg'],
        help="Upload a QR code image to scan"
    )

    if uploaded_file is not None:
        try:
            # Show uploaded image
            image = Image.open(uploaded_file)
            st.image(image, caption="Uploaded QR Code", width=300)

            # Convert uploaded file to opencv image
            file_bytes = np.asarray(bytearray(uploaded_file.seek(0) or uploaded_file.read()), dtype=np.uint8)
            img = cv2.imdecode(file_bytes, cv2.IMREAD_COLOR)

            # Initialize QR code detector
            qr_detector = cv2.QRCodeDetector()

            # Detect and decode
            retval, decoded_info, points, _ = qr_detector.detectAndDecodeMulti(img)

            if retval and decoded_info:
                # Print decoded info for debugging
                st.write("Debug - Decoded content:", decoded_info[0])

                if any(decoded_info):
                    decoded_text = decoded_info[0]

                    # Handle various QR code formats
                    if decoded_text.startswith('farm2market://'):
                        # Native app QR code
                        if "product/" in decoded_text:
                            # Product QR code
                            _, product_data = decoded_text.split('product/')
                            product_id, name, price = product_data.split(':')
                            st.success("Product QR Code scanned successfully!")
                            st.write(f"**Product:** {name}")
                            st.write(f"**Price:** ₹{float(price):.2f}")

                            if st.button("View Product"):
                                st.session_state['selected_product'] = int(product_id)
                                st.session_state.current_page = "Marketplace"
                                st.rerun()
                        else:
                            # User QR code
                            _, user_data = decoded_text.split('://')
                            user_id, username, user_type = user_data.split(':')

                            st.success("User QR Code scanned successfully!")
                            st.write(f"**Username:** {username}")
                            st.write(f"**Account Type:** {user_type.capitalize()}")

                            if user_type == 'seller':
                                show_seller_profile(int(user_id))
                    else:
                        # Try to process as a seller ID
                        try:
                            seller_id = int(decoded_text)
                            show_seller_profile(seller_id)
                        except ValueError:
                            st.warning("""
                                This appears to be a non-Farm2Market QR code. 
                                Content detected: {}

                                Please upload a QR code generated within the Farm2Market app.
                            """.format(decoded_text[:100]))  # Show first 100 chars for safety
            else:
                st.error("""
                    Could not detect a valid QR code in the image. Please ensure:
                    1. The image is clear and well-lit
                    2. The QR code is completely visible
                    3. The image is not blurry
                    4. You're using a QR code generated by Farm2Market
                """)

        except Exception as e:
            st.error(f"""
                Error processing QR code image. Please try again with a different image.
                Technical details: {str(e)}
            """)

    # Add helpful instructions
    with st.expander("ℹ️ How to use the QR Scanner"):
        st.markdown("""
            ### Scanning QR Codes
            1. Ensure you have a clear image of the QR code
            2. Click 'Browse files' to upload the QR code image
            3. The scanner will automatically process the QR code

            ### Supported QR Codes
            - Farm2Market Seller Profiles
            - Farm2Market Product QR Codes
            - Direct Seller ID QR Codes

            ### Troubleshooting
            If the scanner isn't working:
            - Make sure the image is clear and well-lit
            - Try taking a new picture of the QR code
            - Ensure you're using a QR code from Farm2Market
            - The QR code should be completely visible in the image
        """)


def show_my_qr():
    st.title("My QR Code")
    st.write("Share this QR code with others to let them find your profile easily")

    if not st.session_state.user:
        st.error("Please login to view your QR code")
        return

    # Generate and display QR code
    conn = sqlite3.connect('farm2market.db')
    c = conn.cursor()

    try:
        # Get user's QR code
        c.execute('SELECT qr_code FROM user_qr_codes WHERE user_id = ?',
                  (st.session_state.user[0],))
        result = c.fetchone()

        if not result:
            # Generate new QR code if not exists
            if save_user_qr(st.session_state.user[0]):
                c.execute('SELECT qr_code FROM user_qr_codes WHERE user_id = ?',
                          (st.session_state.user[0],))
                result = c.fetchone()

        if result:
            qr_image = Image.open(BytesIO(result[0]))

            # Display QR code with instructions
            col1, col2 = st.columns([1, 2])

            with col1:
                st.image(qr_image, caption="Your QR Code")

                # Add download button
                buf = BytesIO()
                qr_image.save(buf, format='PNG')
                st.download_button(
                    label="Download QR Code",
                    data=buf.getvalue(),
                    file_name="my_qr_code.png",
                    mime="image/png"
                )

            with col2:
                st.markdown("""
                    ### How to use your QR Code:
                    1. Download your QR code using the button
                    2. Share it with other users
                    3. They can scan it to quickly find your profile

                    #### For Sellers:
                    - Share this QR code on your physical store
                    - Add it to your business cards
                    - Include it in your promotional materials
                """)
        else:
            st.error("Error generating QR code")

    finally:
        conn.close()


def generate_product_qr(product_id, product_name, price):
    """Generate QR code for a specific product"""
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    # Encode product data
    data = f"farm2market://product/{product_id}:{product_name}:{price}"
    qr.add_data(data)
    qr.make(fit=True)

    # Create QR code image
    img = qr.make_image(fill_color="black", back_color="white")

    # Convert to bytes
    img_byte_arr = BytesIO()
    img.save(img_byte_arr, format='PNG')
    img_byte_arr = img_byte_arr.getvalue()

    return img_byte_arr


def show_seller_products():
    if not st.session_state.user or st.session_state.user[3] != 'seller':
        st.error("Access denied")
        return

    conn = sqlite3.connect('farm2market.db')
    c = conn.cursor()

    try:
        # Check seller verification
        c.execute('SELECT license_verified FROM users WHERE id = ?',
                  (st.session_state.user[0],))
        is_verified = c.fetchone()[0]

        if not is_verified:
            st.warning("Your seller account is pending verification.")
            return

        # Get seller's products
        c.execute('''SELECT * FROM products 
                    WHERE seller_id = ?
                    ORDER BY date_added DESC''',
                  (st.session_state.user[0],))
        products = c.fetchall()

        # Add new product button
        if st.button("➕ Add New Product", use_container_width=True):
            st.session_state.current_page = "Add Product"
            st.rerun()

        if not products:
            st.info("You haven't added any products yet.")
            return

        # Display products in a grid
        for product in products:
            with st.container():
                st.markdown("""
                    <div style="border: 1px solid #ddd; padding: 15px; 
                    border-radius: 10px; margin: 10px 0; 
                    background-color: rgba(255, 255, 255, 0.1);">
                """, unsafe_allow_html=True)

                col1, col2, col3 = st.columns([1, 2, 1])

                with col1:
                    if product[7]:  # image
                        try:
                            image = Image.open(io.BytesIO(product[7]))
                            st.image(image, width=150)
                        except:
                            st.write("No image available")

                with col2:
                    st.subheader(product[2])  # name
                    st.write(product[3])  # description
                    st.write(f"Price: ₹{float(product[4]):.2f}")
                    st.write(f"Stock: {product[5]}")
                    st.write(f"Category: {product[6]}")

                with col3:
                    delete_key = f'delete_{product[0]}'
                    confirm_key = f'confirm_{product[0]}'

                    if delete_key not in st.session_state:
                        st.session_state[delete_key] = False

                    if not st.session_state[delete_key]:
                        if st.button("🗑️ Delete", key=f"del_btn_{product[0]}",
                                     use_container_width=True):
                            st.session_state[delete_key] = True
                            st.rerun()
                    else:
                        st.warning("Are you sure you want to delete this product?")
                        col1, col2 = st.columns(2)
                        with col1:
                            if st.button("Yes", key=f"yes_{product[0]}"):
                                if delete_product(product[0]):
                                    st.success("Product deleted successfully!")
                                    time.sleep(1)
                                    st.rerun()
                                else:
                                    st.error("Error deleting product")
                        with col2:
                            if st.button("No", key=f"no_{product[0]}"):
                                st.session_state[delete_key] = False
                                st.rerun()

                    st.markdown("<br>", unsafe_allow_html=True)

                    if st.button("📝 Edit", key=f"edit_{product[0]}",
                                 use_container_width=True):
                        st.session_state.editing_product = product
                        st.session_state.current_page = "Edit Product"
                        st.rerun()

                st.markdown("</div>", unsafe_allow_html=True)

    except Exception as e:
        st.error(f"Error loading products: {str(e)}")
    finally:
        conn.close()


def show_product_reviews_and_rating(product_id):
    """Display reviews and rating for a product"""
    conn = sqlite3.connect('farm2market.db')
    c = conn.cursor()

    try:
        # Get all reviews for the product
        c.execute('''
            SELECT r.*, u.username 
            FROM reviews r
            JOIN users u ON r.user_id = u.id
            WHERE r.product_id = ?
            ORDER BY r.review_date DESC
        ''', (product_id,))
        reviews = c.fetchall()

        # Calculate average rating
        if reviews:
            avg_rating = sum(review[3] for review in reviews) / len(reviews)
            rating_display = "⭐" * round(avg_rating)
            st.write(f"**Rating:** {rating_display} ({avg_rating:.1f}/5.0) • {len(reviews)} reviews")
        else:
            st.write("No reviews yet")

        # Show review form for buyers who are logged in
        if st.session_state.user and st.session_state.user[3] == 'buyer':
            with st.expander("Write a Review"):
                with st.form(key=f"review_form_{product_id}"):
                    rating = st.slider("Rating", 1, 5, 5)
                    comment = st.text_area("Your Review")
                    submitted = st.form_submit_button("Submit Review")

                    if submitted:
                        if add_review(product_id, st.session_state.user[0], rating, comment):
                            st.success("Review submitted successfully!")
                            time.sleep(1)
                            st.rerun()
                        else:
                            st.error("Error submitting review")

        # Display existing reviews
        if reviews:
            with st.expander(f"Show Reviews ({len(reviews)})"):
                for review in reviews:
                    st.markdown("---")
                    col1, col2 = st.columns([3, 1])
                    with col1:
                        st.write(f"**{review[-1]}**")  # username
                        st.write("⭐" * review[3])  # rating
                    with col2:
                        st.write(f"*{review[5]}*")  # date
                    st.write(review[4])  # comment

                    # Show seller reply if exists
                    if review[6]:  # seller_reply exists
                        st.markdown("""
                            <div style='background-color: #f0f2f6; padding: 10px; 
                            border-radius: 5px; margin-top: 10px;'>
                                <p><strong>Seller's Reply:</strong></p>
                                <p>{}</p>
                                <p><em>{}</em></p>
                            </div>
                        """.format(review[6], review[7]), unsafe_allow_html=True)

    except Exception as e:
        st.error(f"Error loading reviews: {str(e)}")
    finally:
        conn.close()

def add_seller_reply(review_id, reply):
    conn = sqlite3.connect('farm2market.db')
    c = conn.cursor()

    try:
        c.execute('''UPDATE reviews 
                    SET seller_reply = ?, reply_date = CURRENT_TIMESTAMP 
                    WHERE id = ?''', (reply, review_id))
        conn.commit()
        return True
    except Exception as e:
        print(f"Error adding reply: {str(e)}")
        return False
    finally:
        conn.close()


def show_edit_product():
    """Show edit product form"""
    if not st.session_state.get("editing_product"):
        st.error("No product selected for editing")
        return

    product = st.session_state.editing_product
    st.title("Edit Product")

    with st.form("edit_product_form"):
        name = st.text_input("Product Name*", value=product[2])
        description = st.text_area("Description*", value=product[3])

        col1, col2, col3 = st.columns(3)
        with col1:
            price = st.number_input("Price (₹)*", min_value=0.01, value=float(product[4]), step=0.01)
        with col2:
            quantity = st.number_input("Quantity*", min_value=0, value=int(product[5]), step=1)
        with col3:
            category = st.selectbox("Category*",
                                    ["Crops", "Dairy", "Fruits", "Vegetables", "Spices", "Other"],
                                    index=["Crops", "Dairy", "Fruits", "Vegetables", "Spices", "Other"].index(
                                        product[6]))

        new_image = st.file_uploader("Update Product Image (leave empty to keep current)",
                                     type=["png", "jpg", "jpeg"])

        submitted = st.form_submit_button("Save Changes")

        if submitted:
            if not all([name, description, price > 0]):
                st.error("Please fill all required fields")
                return

            try:
                conn = sqlite3.connect('farm2market.db')
                c = conn.cursor()

                if new_image:
                    image_data = new_image.read()
                    c.execute('''UPDATE products 
                                SET name=?, description=?, price=?, quantity=?, 
                                    category=?, image=?
                                WHERE id=?''',
                              (name, description, price, quantity, category,
                               image_data, product[0]))
                else:
                    c.execute('''UPDATE products 
                                SET name=?, description=?, price=?, quantity=?, 
                                    category=?
                                WHERE id=?''',
                              (name, description, price, quantity, category,
                               product[0]))

                conn.commit()
                st.success("Product updated successfully!")

                # Clear editing state and return to products page
                st.session_state.editing_product = None
                st.session_state.current_page = "My Products"
                time.sleep(1)
                st.rerun()

            except Exception as e:
                st.error(f"Error updating product: {str(e)}")
            finally:
                conn.close()


def main():
    init_db()
    init_session_state()

    if "user" not in st.session_state:
        st.session_state.user = None
    if "current_page" not in st.session_state:
        st.session_state.current_page = "Login"

    if st.session_state["user"] is None:
        auth_option = st.sidebar.radio("Authentication", ["Login", "Register"])
        if auth_option == "Login":
            show_login()
        else:
            show_register()
        return

    st.sidebar.write(f"Welcome, {st.session_state.user[1]}!")

    # Update navigation for each user type (removed Checkout from visible pages)
    if st.session_state.user[3] == 'admin':
        pages = ["Admin Panel", "Marketplace", "QR Scanner", "My QR"]
    elif st.session_state.user[3] == 'seller':
        pages = ["My Products", "Add Product", "Orders", "Marketplace", "QR Scanner", "My QR"]
    else:  # buyer
        pages = ["Marketplace", "My Cart", "My Orders", "QR Scanner", "My QR"]

    # Only show these pages in the navigation
    selected_page = st.sidebar.radio("Navigation", pages)

    if selected_page != st.session_state.current_page and st.session_state.current_page != "Checkout":
        st.session_state.current_page = selected_page
        st.rerun()

    if st.sidebar.button("Logout"):
        st.session_state.user = None
        st.session_state.current_page = "Login"
        st.rerun()

    # Page routing including hidden Checkout page
    if st.session_state.current_page == "Checkout":
        cart_items = getattr(st.session_state, 'checkout_cart_items', None)
        if cart_items:
            show_checkout(cart_items)
        else:
            st.error("No items in checkout")
            st.session_state.current_page = "My Cart"
            st.rerun()
    elif st.session_state.current_page == "QR Scanner":
        show_qr_scanner()
    elif st.session_state.current_page == "My QR":
        show_my_qr()
    elif st.session_state.current_page == "Admin Panel":
        show_admin_panel()
    elif st.session_state.current_page == "Marketplace":
        show_marketplace()
    elif st.session_state.current_page == "My Cart":
        show_cart()
    elif st.session_state.current_page == "My Orders":
        show_orders()
    elif st.session_state.current_page == "My Products":
        show_seller_products()
    elif st.session_state.current_page == "Add Product":
        show_add_product()
    elif st.session_state.current_page == "Orders" and st.session_state.user[3] == 'seller':
        show_seller_orders()



if __name__ == "__main__":
    migrate_database()
    init_db()
    init_review_system()
    cleanup_categories()
    update_order_status()
    main()