from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from decimal import Decimal
from flask_bcrypt import Bcrypt


app = Flask(__name__)
bcrypt = Bcrypt(app)


# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:password@localhost/stock_trading_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database
db = SQLAlchemy(app)

# Define User model


class User(db.Model):
    __tablename__ = 'user'

    user_id = db.Column(db.BigInteger, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.Enum('customer', 'admin'),
                     nullable=False, default='customer')
    full_name = db.Column(db.String(100), nullable=False)
    cash_balance = db.Column(db.Numeric(15, 2), nullable=False, default=0.00)
    created_at = db.Column(db.DateTime, nullable=False,
                           default=datetime.utcnow)

    def deposit_funds(self, amount):
        if amount > 0:
            self.cash_balance += Decimal(str(amount))
            db.session.commit()
            return True
        return False

# Define Stock model


class Stock(db.Model):
    __tablename__ = 'stock'

    stock_id = db.Column(db.BigInteger, primary_key=True)
    ticker = db.Column(db.String(10), unique=True, nullable=False)
    company_name = db.Column(db.String(100), nullable=False)
    current_price = db.Column(db.Numeric(15, 2), nullable=False)
    volume = db.Column(db.BigInteger, nullable=False, default=0)
    day_high = db.Column(db.Numeric(15, 2), nullable=False)
    day_low = db.Column(db.Numeric(15, 2), nullable=False)
    opening_price = db.Column(db.Numeric(15, 2), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False,
                           default=datetime.utcnow)

    def update_price(self, new_price):
        if new_price > 0:
            self.current_price = Decimal(str(new_price))
            if new_price > self.day_high:
                self.day_high = Decimal(str(new_price))
            if new_price < self.day_low:
                self.day_low = Decimal(str(new_price))
            db.session.commit()
            return True
        return False

# Define Portfolio model


class Portfolio(db.Model):
    __tablename__ = 'portfolio'

    portfolio_id = db.Column(db.BigInteger, primary_key=True)
    user_id = db.Column(db.BigInteger, db.ForeignKey(
        'user.user_id'), nullable=False)
    stock_id = db.Column(db.BigInteger, db.ForeignKey(
        'stock.stock_id'), nullable=False)
    shares_owned = db.Column(db.BigInteger, nullable=False, default=0)

    __table_args__ = (db.UniqueConstraint(
        'user_id', 'stock_id', name='unique_user_stock'),)

# Define Transaction model


class Transaction(db.Model):
    __tablename__ = 'transaction'

    transaction_id = db.Column(db.BigInteger, primary_key=True)
    user_id = db.Column(db.BigInteger, db.ForeignKey(
        'user.user_id'), nullable=False)
    stock_id = db.Column(db.BigInteger, db.ForeignKey(
        'stock.stock_id'), nullable=False)
    type = db.Column(db.Enum('buy', 'sell'), nullable=False)
    quantity = db.Column(db.BigInteger, nullable=False)
    price = db.Column(db.Numeric(15, 2), nullable=False)
    transaction_date = db.Column(
        db.DateTime, nullable=False, default=datetime.utcnow)

# Define Order model


class Order(db.Model):
    __tablename__ = 'order'

    order_id = db.Column(db.BigInteger, primary_key=True)
    user_id = db.Column(db.BigInteger, db.ForeignKey(
        'user.user_id'), nullable=False)
    stock_id = db.Column(db.BigInteger, db.ForeignKey(
        'stock.stock_id'), nullable=False)
    type = db.Column(db.Enum('buy', 'sell'), nullable=False)
    quantity = db.Column(db.BigInteger, nullable=False)
    order_type = db.Column(db.Enum('market', 'limit'), nullable=False)
    limit_price = db.Column(db.Numeric(15, 2), nullable=True)
    status = db.Column(db.Enum('pending', 'completed',
                       'cancelled'), nullable=False, default='pending')
    created_at = db.Column(db.DateTime, nullable=False,
                           default=datetime.utcnow)


# Create tables
with app.app_context():
    db.create_all()

# Basic routes for each page


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password, password):
            session['user_id'] = user.user_id
            session['username'] = user.username
            session['role'] = user.role
            flash('Logged in successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')
            return redirect(url_for('login'))
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        full_name = request.form['full_name']
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return redirect(url_for('register'))

        if not full_name or not username or not email or not password:
            flash('Please fill in all fields', 'error')
            return redirect(url_for('register'))

        try:
            passwd_hash = bcrypt.generate_password_hash(
                password).decode('utf-8')

            new_user = User(full_name=full_name, username=username,
                            email=email, password=passwd_hash)
            db.session.add(new_user)
            db.session.commit()
            flash('User added successfully!', 'success')
            return redirect(url_for('register'))
        except Exception as e:
            flash(f'Error adding user: {str(e)}', 'error')
            return redirect(url_for('register'))

    return render_template('register.html')


@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')


@app.route('/market')
def market():
    return render_template('market.html')


@app.route('/trade/<ticker>')
def trade(ticker):
    return render_template('trade.html', ticker=ticker)


@app.route('/transaction_history')
def transaction_history():
    return render_template('transaction_history.html')


@app.route('/cash_management')
def cash_management():
    return render_template('cash_management.html')


@app.route('/admin/dashboard')
def admin_dashboard():
    return render_template('admin_dashboard.html')


app.secret_key = "your_super_secret_key_here"

if __name__ == '__main__':
    app.run(debug=True)
