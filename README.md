# Farm2Market
A web-based marketplace platform connecting farmers directly to consumers, built with Streamlit and SQLite. Farm2Market aims to eliminate middlemen, ensure fair prices for farmers, and provide consumers with fresh, locally-sourced agricultural products.

Features:

User Authentication System: Secure registration and login for buyers, sellers, and administrators
Seller Verification: Admin approval workflow for seller accounts with license verification
Product Management: Sellers can list, edit, and manage their agricultural products
Shopping Cart: Buyers can browse products, add to cart, and checkout seamlessly
Order Management: Complete order lifecycle from pending to delivered
QR Code Integration: Generate and scan QR codes for products and user profiles
Review System: Rate and review products with seller responses
Responsive UI: Modern, mobile-friendly interface

Technology Stack

Frontend & Backend: Streamlit
Database: SQLite
Image Processing: Pillow, OpenCV
QR Code Handling: qrcode
Data Validation: Regular expressions
Caching: Streamlit caching for performance optimization

Installation

Clone the repository: 
git clone https://github.com/yourusername/farm2market.git
cd farm2market

Install the required packages:
pip install -r requirements.txt

Run the application:
streamlit run apps.py

Usage:

Buyers: Register, browse products, add to cart, place orders, track deliveries
Sellers: Register with license verification, list products, manage inventory, process orders
Admins: Verify sellers, manage users, oversee marketplace operations

Database Schema:

Users: Authentication and role management
Products: Product listings with details and inventory
Orders: Order processing and tracking
Cart: Shopping cart functionality
Reviews: Product rating and review system
QR Codes: User and product QR code storage

Contributions are welcome! Please feel free to submit a Pull Request.

