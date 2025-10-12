from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
from decimal import Decimal
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from functools import wraps
import re
import os
import pytz
from flask import abort
import pandas_market_calendars as mcal
from dotenv import load_dotenv
import random
import threading
import time
import atexit

load_dotenv()

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY')

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)

# Global variable to track if price updater has started
price_updater_started = False
price_updater_thread = None


class User(UserMixin, db.Model):
    __tablename__ = 'user'

    id = db.Column(db.BigInteger, primary_key=True)
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
            new_price_decimal = Decimal(str(new_price))
            self.current_price = new_price_decimal
            
            # Update day high if new price is higher
            if new_price_decimal > self.day_high:
                self.day_high = new_price_decimal
            
            # Update day low if new price is lower
            if new_price_decimal < self.day_low:
                self.day_low = new_price_decimal
            
            return True
        return False


class Portfolio(db.Model):
    __tablename__ = 'portfolio'

    portfolio_id = db.Column(db.BigInteger, primary_key=True)
    user_id = db.Column(db.BigInteger, db.ForeignKey(
        'user.id'), nullable=False)
    stock_id = db.Column(db.BigInteger, db.ForeignKey(
        'stock.stock_id'), nullable=False)
    shares_owned = db.Column(db.BigInteger, nullable=False, default=0)

    __table_args__ = (db.UniqueConstraint(
        'user_id', 'stock_id', name='unique_user_stock'),)


class Transaction(db.Model):
    __tablename__ = 'transaction'

    transaction_id = db.Column(db.BigInteger, primary_key=True)
    user_id = db.Column(db.BigInteger, db.ForeignKey(
        'user.id'), nullable=False)
    stock_id = db.Column(db.BigInteger, db.ForeignKey(
        'stock.stock_id'), nullable=False)
    type = db.Column(db.Enum('buy', 'sell'), nullable=False)
    quantity = db.Column(db.BigInteger, nullable=False)
    price = db.Column(db.Numeric(15, 2), nullable=False)
    transaction_date = db.Column(
        db.DateTime, nullable=False, default=datetime.utcnow)


class Order(db.Model):
    __tablename__ = 'order'

    order_id = db.Column(db.BigInteger, primary_key=True)
    user_id = db.Column(db.BigInteger, db.ForeignKey(
        'user.id'), nullable=False)
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


class MarketSettings(db.Model):
    __tablename__ = 'market_settings'

    id = db.Column(db.Integer, primary_key=True)
    manual_override = db.Column(db.Boolean, nullable=False, default=False)
    is_open = db.Column(db.Boolean, nullable=False, default=False)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    updated_by = db.Column(db.BigInteger, db.ForeignKey('user.id'), nullable=True)


with app.app_context():
    db.create_all()
    # Initialize market settings if not exists
    if not MarketSettings.query.first():
        default_settings = MarketSettings(manual_override=False, is_open=False)
        db.session.add(default_settings)
        db.session.commit()


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != "admin":
            abort(401)
        return f(*args, **kwargs)
    return decorated_function


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def update_stock_prices():
    """Background task to update stock prices every minute"""
    with app.app_context():
        while True:
            try:
                stocks = Stock.query.all()
                for stock in stocks:
                    # Generate random change between -10% and +10%
                    change_percent = random.uniform(-0.10, 0.10)
                    new_price = float(stock.current_price) * (1 + change_percent)
                    
                    # Ensure price doesn't go below $0.01
                    new_price = max(new_price, 0.01)
                    
                    # Update the stock price
                    stock.update_price(new_price)
                    
                    # Also update volume with some random activity
                    volume_change = random.randint(100, 10000)
                    stock.volume += volume_change
                
                db.session.commit()
                print(f"Stock prices updated at {datetime.utcnow()}")
                
            except Exception as e:
                print(f"Error updating stock prices: {e}")
                db.session.rollback()
            
            # Wait for 60 seconds before next update
            time.sleep(60)


def start_price_updater():
    """Start the background price updater thread"""
    global price_updater_thread, price_updater_started
    
    if not price_updater_started:
        price_updater_thread = threading.Thread(target=update_stock_prices, daemon=True)
        price_updater_thread.start()
        price_updater_started = True
        print("Stock price updater started")


def stop_price_updater():
    """Stop the background price updater thread"""
    global price_updater_thread
    if price_updater_thread and price_updater_thread.is_alive():
        # Since it's a daemon thread, it will terminate when main thread exits
        print("Stopping price updater...")


def market_hours_info():
    # Get market settings
    settings = MarketSettings.query.first()
    
    # If manual override is enabled, return the override status
    if settings and settings.manual_override:
        return {
            "is_open": settings.is_open,
            "next_close": "Manual Override Active",
            "next_open": "Manual Override Active",
            "manual_override": True
        }
    
    # Otherwise, use NYSE calendar
    nyse = mcal.get_calendar('NYSE')
    now = datetime.now(pytz.timezone('America/New_York'))

    schedule = nyse.schedule(tz='America/New_York', start_date=now.date() - timedelta(days=7),
                             end_date=now.date() + timedelta(days=7))

    today_schedule = schedule[(schedule['market_open'] <= now) & (
        schedule['market_close'] >= now)]
    upcoming = schedule[schedule['market_open'] > now]

    if not today_schedule.empty:
        next_close = today_schedule.iloc[0]['market_close']
        return {
            "is_open": True,
            "next_close": next_close.strftime('%A, %b %d at %I:%M %p EST'),
            "next_open": None,
            "manual_override": False
        }
    else:
        next_open = upcoming.iloc[0]['market_open'] if not upcoming.empty else None
        next_close = upcoming.iloc[0]['market_close'] if not upcoming.empty else None
        return {
            "is_open": False,
            "next_open": next_open.strftime('%A, %b %d at %I:%M %p EST') if next_open else None,
            "next_close": next_close.strftime('%A, %b %d at %I:%M %p EST') if next_close else None,
            "manual_override": False
        }


# Start price updater when the first request comes in
@app.before_request
def before_first_request():
    global price_updater_started
    if not price_updater_started:
        start_price_updater()


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
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            flash('Logged in successfully!', 'success')
            login_user(user)
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
        elif len(password) < 8:
            flash('Password must be at least 8 characters', 'error')
            return redirect(url_for('register'))
        elif re.search(r"\d", password) is None:
            flash('Password must have at least 1 digit', 'error')
            return redirect(url_for('register'))
        elif re.search(r"[A-Z]", password) is None:
            flash('Password must have at least 1 uppercase letter', 'error')
            return redirect(url_for('register'))
        elif re.search(r"[a-z]", password) is None:
            flash('Password must have at least 1 lowercase letter', 'error')
            return redirect(url_for('register'))
        elif re.search(r"[ !#$%&'()*+,-./[\\\]^_`{|}~"+r'"]', password) is None:
            flash('Password must have at least 1 symbol', 'error')
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


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


@app.route('/market')
def market():
    stocks = Stock.query.all()

    return render_template('market.html', stocks=stocks, market_hours=market_hours_info())


@app.route('/trade/<ticker>', methods=['GET', 'POST'])
@login_required
def trade(ticker):
    stock = Stock.query.filter_by(ticker=ticker).first()
    if not stock:
        flash('Stock not found', 'error')
        return redirect(url_for('market'))

    user = current_user

    portfolio_item = Portfolio.query.filter_by(
        user_id=user.id, stock_id=stock.stock_id).first()
    user_shares = portfolio_item.shares_owned if portfolio_item else 0
    
    market_info = market_hours_info()

    if request.method == 'POST':
        if user.role != 'admin' and not market_info['is_open']:
            flash(
                f'Trading is currently unavailable. Market will reopen at {market_info.get("next_open", "TBD")}.', 'error')
            return redirect(url_for('dashboard'))

        action = request.form['action']
        shares = int(request.form['shares'])

        if shares <= 0:
            flash('Enter a valid number of shares', 'error')
            return redirect(url_for('trade', ticker=ticker))

        # Refresh stock data to get current price at time of transaction
        db.session.refresh(stock)
        current_price = stock.current_price

        if action == 'buy':
            total_cost = shares * current_price
            if user.cash_balance < total_cost:
                flash('Insufficient funds', 'error')
            else:
                new_transaction = Transaction(
                    user_id=user.id,
                    stock_id=stock.stock_id,
                    type='buy',
                    quantity=shares,
                    price=current_price  # Use current price at transaction time
                )

                user.cash_balance -= total_cost

                if portfolio_item:
                    portfolio_item.shares_owned += shares
                else:
                    portfolio_item = Portfolio(
                        user_id=user.id,
                        stock_id=stock.stock_id,
                        shares_owned=shares
                    )
                    db.session.add(portfolio_item)

                db.session.add(new_transaction)
                db.session.commit()

                flash(
                    f'Successfully bought {shares} shares of {stock.ticker} at ${current_price:.2f}', 'success')
                return redirect(url_for('dashboard'))

        elif action == 'sell':
            if not portfolio_item or portfolio_item.shares_owned < shares:
                flash('Not enough shares to sell', 'error')
            else:
                total_value = shares * current_price

                new_transaction = Transaction(
                    user_id=user.id,
                    stock_id=stock.stock_id,
                    type='sell',
                    quantity=shares,
                    price=current_price  # Use current price at transaction time
                )

                user.cash_balance += total_value

                portfolio_item.shares_owned -= shares
                if portfolio_item.shares_owned == 0:
                    db.session.delete(portfolio_item)

                db.session.add(new_transaction)
                db.session.commit()

                flash(
                    f'Successfully sold {shares} shares of {stock.ticker} at ${current_price:.2f}', 'success')
                return redirect(url_for('dashboard'))

    return render_template('trade.html', stock=stock, user=user, user_shares=user_shares, market_open=market_info['is_open'])


@app.route('/admin/dashboard', methods=['GET', 'POST'])
@admin_required
@login_required
def admin_dashboard():
    if request.method == 'POST':
        if 'add_stock' in request.form:
            ticker = request.form['ticker'].upper()
            company_name = request.form['company_name']
            try:
                current_price = Decimal(request.form['current_price'])
                day_high = Decimal(request.form['day_high'])
                day_low = Decimal(request.form['day_low'])
                volume = int(request.form['volume'])
            except:
                flash('Invalid input values', 'error')
                return redirect(url_for('admin_dashboard'))

            if Stock.query.filter_by(ticker=ticker).first():
                flash('Stock with this ticker already exists', 'error')
            else:
                new_stock = Stock(
                    ticker=ticker,
                    company_name=company_name,
                    current_price=current_price,
                    day_high=day_high,
                    day_low=day_low,
                    opening_price=current_price,
                    volume=volume
                )
                db.session.add(new_stock)
                db.session.commit()
                flash(f'Stock {ticker} added successfully', 'success')

        elif 'edit_stock_id' in request.form:
            stock_id = int(request.form['edit_stock_id'])
            stock = Stock.query.get(stock_id)
            if stock:
                try:
                    stock.current_price = Decimal(
                        request.form['current_price'])
                    stock.day_high = Decimal(request.form['day_high'])
                    stock.day_low = Decimal(request.form['day_low'])
                    stock.volume = int(request.form['volume'])
                    db.session.commit()
                    flash(
                        f'Stock {stock.ticker} updated successfully', 'success')
                except:
                    flash('Invalid input values for stock update', 'error')
            else:
                flash('Stock not found', 'error')

        elif 'delete_stock_id' in request.form:
            stock_id = int(request.form['delete_stock_id'])
            stock = Stock.query.get(stock_id)
            if stock:
                db.session.delete(stock)
                db.session.commit()
                flash(f'Stock {stock.ticker} deleted successfully', 'success')
            else:
                flash('Stock not found', 'error')
        
        elif 'market_override' in request.form:
            settings = MarketSettings.query.first()
            action = request.form['market_override']
            
            if action == 'enable_override':
                settings.manual_override = True
                settings.is_open = True
                settings.updated_by = current_user.id
                db.session.commit()
                flash('Manual override enabled - Market is now OPEN', 'success')
            elif action == 'disable_override':
                settings.manual_override = False
                settings.updated_by = current_user.id
                db.session.commit()
                flash('Manual override disabled - Using NYSE calendar', 'success')
            elif action == 'open_market':
                settings.is_open = True
                settings.updated_by = current_user.id
                db.session.commit()
                flash('Market manually opened', 'success')
            elif action == 'close_market':
                settings.is_open = False
                settings.updated_by = current_user.id
                db.session.commit()
                flash('Market manually closed', 'warning')

        return redirect(url_for('admin_dashboard'))
    
    stocks = Stock.query.all()
    market_info = market_hours_info()
    settings = MarketSettings.query.first()
    
    return render_template('admin_dashboard.html', stocks=stocks, market_info=market_info, settings=settings)


@app.route('/dashboard')
@login_required
def dashboard():
    # Get portfolio items with stock info
    portfolio_items = db.session.query(Portfolio, Stock).join(
        Stock, Portfolio.stock_id == Stock.stock_id
    ).filter(
        Portfolio.user_id == current_user.id,
        Portfolio.shares_owned > 0
    ).all()

    # Format for template
    formatted_items = []
    portfolio_value = 0
    for portfolio, stock in portfolio_items:
        formatted_items.append({
            'portfolio': portfolio,
            'stock': stock
        })
        portfolio_value += portfolio.shares_owned * stock.current_price

    # Get recent transactions (last 5)
    recent_transactions = db.session.query(Transaction, Stock).join(
        Stock, Transaction.stock_id == Stock.stock_id
    ).filter(
        Transaction.user_id == current_user.id
    ).order_by(
        Transaction.transaction_date.desc()
    ).limit(5).all()

    formatted_transactions = []
    for transaction, stock in recent_transactions:
        formatted_transactions.append({
            'transaction': transaction,
            'stock': stock
        })

    return render_template('dashboard.html',
                           portfolio_items=formatted_items,
                           portfolio_value=portfolio_value,
                           recent_transactions=formatted_transactions)


@app.route('/transaction_history')
@login_required
def transaction_history():
    # Get all transactions for current user
    transactions = db.session.query(Transaction, Stock).join(
        Stock, Transaction.stock_id == Stock.stock_id
    ).filter(
        Transaction.user_id == current_user.id
    ).order_by(
        Transaction.transaction_date.desc()
    ).all()

    formatted_transactions = []
    for transaction, stock in transactions:
        formatted_transactions.append({
            'transaction': transaction,
            'stock': stock
        })

    return render_template('history.html', transactions=formatted_transactions)


@app.route('/cash_management')
@login_required
def cash_management():
    return render_template('management.html')


@app.route('/deposit', methods=['POST'])
@login_required
def deposit():
    try:
        amount = float(request.form['amount'])
        if amount <= 0:
            flash('Please enter a valid amount', 'error')
        else:
            current_user.cash_balance += Decimal(str(amount))
            db.session.commit()
            flash(f'Successfully deposited ${amount:.2f}', 'success')
    except Exception as e:
        flash(f'Error processing deposit: {str(e)}', 'error')

    return redirect(url_for('cash_management'))


@app.route('/withdraw', methods=['POST'])
@login_required
def withdraw():
    try:
        amount = float(request.form['amount'])
        if amount <= 0:
            flash('Please enter a valid amount', 'error')
        elif amount > current_user.cash_balance:
            flash('Insufficient funds', 'error')
        else:
            current_user.cash_balance -= Decimal(str(amount))
            db.session.commit()
            flash(f'Successfully withdrew ${amount:.2f}', 'success')
    except Exception as e:
        flash(f'Error processing withdrawal: {str(e)}', 'error')

    return redirect(url_for('cash_management'))


@app.errorhandler(401)
def unauthorized_error(error):
    return render_template("401.html"), 401


@app.errorhandler(404)
def not_found_error(error):
    return render_template("404.html"), 404


# Register cleanup function
atexit.register(stop_price_updater)

if __name__ == '__main__':
    # Start price updater when running directly
    start_price_updater()
    app.run(debug=True)