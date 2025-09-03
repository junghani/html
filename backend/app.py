"""
Flask backend for the shop application.

This is a minimal API server implementing user registration, login and
product/point endpoints. It is designed to run inside a container on
Kubernetes/EKS. Secrets such as the database URI and JWT secret
are injected via environment variables.

For a real application you would expand these endpoints, add proper
error handling, authentication (e.g. JWT), and input validation.
"""

from datetime import datetime, timedelta
import os
import json
import logging

from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Flask application instance
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('SQLALCHEMY_DATABASE_URI', 'sqlite:///shop.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.environ.get('JWT_SECRET_KEY', 'change-me'))
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'change-me')

db = SQLAlchemy(app)
CORS(app)


class User(db.Model):
    """User account model.

    Fields:
    - id: primary key
    - email: unique user identifier
    - password_hash: hashed password
    - name: display name
    - phone: optional phone number
    - points_balance: integer points balance
    - created_at: registration timestamp
    """
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False) # Length Limit Changed @08/31
    name = db.Column(db.String(80), nullable=False)
    phone = db.Column(db.String(20))
    points_balance = db.Column(db.Integer, default=0, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    point_transactions = db.relationship(
        "PointTransaction",
        back_populates="user",
        cascade="all, delete-orphan",
    )

    def check_password(self, password: str) -> bool:
        """Verify a plaintext password against the stored hash."""
        return check_password_hash(self.password_hash, password)


class PointTransaction(db.Model):
    """Tracks changes to a user's point balance."""
    __tablename__ = 'point_transactions'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    delta = db.Column(db.Integer, nullable=False)
    reason = db.Column(db.String(255), nullable=False)
    note = db.Column(db.String(255))
    receipt_json = db.Column(db.JSON)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    user = db.relationship("User", back_populates="point_transactions")


class Product(db.Model):
    """Product catalog model."""
    __tablename__ = 'products'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    stock = db.Column(db.Integer, default=0, nullable=False)
    price = db.Column(db.Numeric(10, 2), nullable=False)


def init_db():
    """Initialize the database (create tables)."""
    with app.app_context():
        db.create_all()
        logger.info("Database tables created successfully")


@app.route('/', methods=['GET'])
def root():
    """Root endpoint for health checks."""
    return jsonify({'status': 'ok', 'service': 'shop-backend', 'version': '1.0.0'}), 200


@app.route('/api/auth/register', methods=['POST'])
def register():
    """Register a new user.

    Expects JSON with `email`, `password` and `name`. Returns a success
    message or an error if the email already exists.
    """
    try:
        data = request.get_json() or {}
        email = data.get('email', '').strip().lower()
        password = data.get('password', '').strip()
        name = data.get('name', '').strip()
        phone = data.get('phone', '').strip()

        logger.info(f"=== REGISTER DEBUG ===")
        logger.info(f"Email: '{email}', Password: '{password}', Name: '{name}'")

        # Input validation
        if not email or not password or not name:
            return jsonify({'error': 'Email, password and name are required'}), 400

        if len(password) < 6:
            return jsonify({'error': 'Password must be at least 6 characters long'}), 400

        # Check if user exists
        if User.query.filter_by(email=email).first():
            return jsonify({'error': 'Email already registered'}), 409

        password_hash = generate_password_hash(password)
        logger.info(f"Generated hash: {password_hash}")
        
        user = User(email=email, password_hash=password_hash, name=name, phone=phone)
        db.session.add(user)
        db.session.commit()

        logger.info(f"New user registered: {email}")
        return jsonify({'message': 'User registered successfully', 'user_id': user.id}), 201

    except Exception as e:
        logger.error(f"Registration error: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/auth/login', methods=['POST'])
def login():
    """Authenticate a user and return a dummy JWT.

    In a production environment you would issue a real JWT with expiry
    information. For simplicity this returns a static token.
    """
    try:
        data = request.get_json() or {}
        email = data.get('email', '').strip().lower()
        password = data.get('password', '').strip()
        
        # 디버깅 로그 추가
        logger.info(f"=== LOGIN DEBUG START ===")
        logger.info(f"Received data: {data}")
        logger.info(f"Email: '{email}', Password: '{password}', Password length: {len(password)}")
        
        if not email or not password:
            logger.info("Missing email or password")
            return jsonify({'error': 'Email and password are required'}), 400

        user = User.query.filter_by(email=email).first()
        logger.info(f"User found in DB: {user is not None}")
        
        if user:
            logger.info(f"User email in DB: '{user.email}'")
            logger.info(f"DB password hash: {user.password_hash}")
            logger.info(f"Attempting to check password: '{password}'")
            
            # 수동으로 해시 체크 과정 확인
            password_check = check_password_hash(user.password_hash, password)
            logger.info(f"Password check result: {password_check}")
            
            # 추가: 새로운 해시 생성해서 비교
            new_hash = generate_password_hash(password)
            logger.info(f"New hash for same password: {new_hash}")
        else:
            logger.info("No user found with this email")
        
        if not user or not user.check_password(password):
            logger.info(f"Authentication failed for email: '{email}'")
            return jsonify({'error': 'Invalid credentials'}), 401

        # Return a simple token (in real life generate JWT)
        token = f'dummy-token-{user.id}'
        logger.info(f"User logged in successfully: {email}")
        return jsonify({
            'token': token, 
            'user_id': user.id, 
            'name': user.name,
            'email': user.email,
            'points_balance': user.points_balance
        }), 200

    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/account/points', methods=['GET'])
def get_points():
    """Return the point balance and transaction history for a user.

    In a real application, user identification would come from the JWT.
    Here we take a `user_id` query parameter for demonstration.
    """
    try:
        user_id = request.args.get('user_id', type=int)
        if not user_id:
            return jsonify({'error': 'Missing user_id parameter'}), 400

        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404

        transactions = [
            {
                'id': t.id,
                'delta': t.delta,
                'reason': t.reason,
                'note': t.note,
                'created_at': t.created_at.isoformat(),
            }
            for t in user.point_transactions
        ]

        return jsonify({
            'points': user.points_balance, 
            'transactions': transactions,
            'user_name': user.name
        }), 200

    except Exception as e:
        logger.error(f"Get points error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/products', methods=['GET'])
def list_products():
    """Return a list of all products."""
    try:
        products = Product.query.all()
        items = [
            {
                'id': p.id,
                'name': p.name,
                'stock': p.stock,
                'price': float(p.price),
            }
            for p in products
        ]
        return jsonify({'items': items, 'count': len(items)}), 200

    except Exception as e:
        logger.error(f"List products error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/products/<int:prod_id>', methods=['GET'])
def get_product(prod_id):
    """Return details for a single product."""
    try:
        product = Product.query.get(prod_id)
        if not product:
            return jsonify({'error': 'Product not found'}), 404
        
        return jsonify({
            'id': product.id,
            'name': product.name,
            'stock': product.stock,
            'price': float(product.price),
        }), 200

    except Exception as e:
        logger.error(f"Get product error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/health', methods=['GET'])
def health():
    """Simple health check endpoint."""
    try:
        # Test database connection
        db.session.execute(db.text('SELECT 1'))
        db_status = 'ok'
    except Exception as e:
        logger.error(f"Database health check failed: {str(e)}")
        db_status = 'error'
    
    return jsonify({
        'status': 'ok', 
        'service': 'shop-backend',
        'database': db_status,
        'timestamp': datetime.utcnow().isoformat()
    }), 200


@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors."""
    return jsonify({'error': 'Endpoint not found'}), 404


@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors."""
    logger.error(f"Internal server error: {str(error)}")
    return jsonify({'error': 'Internal server error'}), 500


if __name__ == '__main__':
    # Create DB tables when running locally (uses sqlite if no DB provided)
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=False)