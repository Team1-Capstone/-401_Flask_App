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
import threading
import time
import random

load_dotenv()

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY')

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)


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
            self.current_price = Decimal(str(new_price))
            if new_price > self.day_high:
                self.day_high = Decimal(str(new_price))
            if new_price < self.day_low:
                self.day_low = Decimal(str(new_price))
            db.session.commit()
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
    average_buy_price = db.Column(db.Numeric(15, 2), nullable=False, default=0.00)

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
    price_simulation_enabled = db.Column(db.Boolean, nullable=False, default=True)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    updated_by = db.Column(db.BigInteger, db.ForeignKey('user.id'), nullable=True)


class MarketSchedule(db.Model):
    __tablename__ = 'market_schedule'

    schedule_id = db.Column(db.BigInteger, primary_key=True)
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=False)
    market_state = db.Column(db.Enum('open', 'closed'), nullable=False)
    status = db.Column(db.Enum('active', 'completed', 'cancelled'), nullable=False, default='active')
    created_by = db.Column(db.BigInteger, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    notes = db.Column(db.String(255), nullable=True)


with app.app_context():
    db.create_all()
    # Initialize market settings if not exists
    if not MarketSettings.query.first():
        default_settings = MarketSettings(manual_override=False, is_open=False, price_simulation_enabled=True)
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


# Background task to update stock prices
def update_stock_prices():
    while True:
        time.sleep(60)  # Wait 60 seconds
        
        with app.app_context():
            try:
                # Check and execute scheduled market actions
                check_scheduled_actions()
                
                settings = MarketSettings.query.first()
                
                # Only update prices if simulation is enabled
                if not settings or not settings.price_simulation_enabled:
                    continue
                
                stocks = Stock.query.all()
                
                for stock in stocks:
                    # Generate random percentage change between -10% and +10%
                    percent_change = random.uniform(-10, 10)
                    
                    # Calculate new price
                    current = float(stock.current_price)
                    change_amount = current * (percent_change / 100)
                    new_price = current + change_amount
                    
                    # Ensure price doesn't go below $0.01
                    new_price = max(0.01, new_price)
                    
                    # Update stock price
                    stock.current_price = Decimal(str(round(new_price, 2)))
                    
                    # Update day high/low
                    if new_price > float(stock.day_high):
                        stock.day_high = Decimal(str(round(new_price, 2)))
                    if new_price < float(stock.day_low):
                        stock.day_low = Decimal(str(round(new_price, 2)))
                    
                    # Update volume with random trading activity
                    volume_change = random.randint(1000, 50000)
                    stock.volume += volume_change
                
                db.session.commit()
                print(f"[{datetime.now()}] Stock prices updated successfully")
                
            except Exception as e:
                print(f"Error updating stock prices: {str(e)}")
                db.session.rollback()


def check_scheduled_actions():
    """Check for scheduled market actions and execute them"""
    try:
        now = datetime.utcnow()
        
        # Get all pending scheduled actions that should be executed
        scheduled_actions = MarketSchedule.query.filter(
            MarketSchedule.status == 'pending',
            MarketSchedule.start_time <= now
        ).all()
        
        settings = MarketSettings.query.first()
        
        for action in scheduled_actions:
            # Execute the scheduled action
            if action.action == 'open':
                settings.manual_override = True
                settings.is_open = True
                settings.updated_by = action.created_by
                print(f"[{datetime.now()}] Scheduled market OPEN executed")
            elif action.action == 'close':
                settings.manual_override = True
                settings.is_open = False
                settings.updated_by = action.created_by
                print(f"[{datetime.now()}] Scheduled market CLOSE executed")
            
            # Mark action as executed
            action.status = 'executed'
            action.executed_at = now
        
        if scheduled_actions:
            db.session.commit()
            
    except Exception as e:
        print(f"Error executing scheduled actions: {str(e)}")
        db.session.rollback()


# Start the background price updater thread
price_updater_thread = threading.Thread(target=update_stock_prices, daemon=True)
price_updater_thread.start()


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
    avg_buy_price = portfolio_item.average_buy_price if portfolio_item else 0
    
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

        # Get the EXACT current price at the moment of transaction
        current_stock_price = stock.current_price

        if action == 'buy':
            total_cost = shares * current_stock_price
            if user.cash_balance < total_cost:
                flash('Insufficient funds', 'error')
            else:
                # Record transaction at EXACT price at time of purchase
                new_transaction = Transaction(
                    user_id=user.id,
                    stock_id=stock.stock_id,
                    type='buy',
                    quantity=shares,
                    price=current_stock_price  # Price at time of purchase
                )

                user.cash_balance -= total_cost

                if portfolio_item:
                    # Calculate new average buy price
                    total_shares = portfolio_item.shares_owned + shares
                    total_cost_basis = (portfolio_item.shares_owned * portfolio_item.average_buy_price) + (shares * current_stock_price)
                    portfolio_item.average_buy_price = total_cost_basis / total_shares
                    portfolio_item.shares_owned += shares
                else:
                    portfolio_item = Portfolio(
                        user_id=user.id,
                        stock_id=stock.stock_id,
                        shares_owned=shares,
                        average_buy_price=current_stock_price
                    )
                    db.session.add(portfolio_item)

                db.session.add(new_transaction)
                db.session.commit()

                flash(
                    f'Successfully bought {shares} shares of {stock.ticker} at ${current_stock_price:.2f} per share', 'success')
                return redirect(url_for('dashboard'))

        elif action == 'sell':
            if not portfolio_item or portfolio_item.shares_owned < shares:
                flash('Not enough shares to sell', 'error')
            else:
                # Sell at CURRENT market price
                total_value = shares * current_stock_price

                # Record transaction at EXACT price at time of sale
                new_transaction = Transaction(
                    user_id=user.id,
                    stock_id=stock.stock_id,
                    type='sell',
                    quantity=shares,
                    price=current_stock_price  # Current market price
                )

                user.cash_balance += total_value

                portfolio_item.shares_owned -= shares
                if portfolio_item.shares_owned == 0:
                    db.session.delete(portfolio_item)

                db.session.add(new_transaction)
                db.session.commit()

                flash(
                    f'Successfully sold {shares} shares of {stock.ticker} at ${current_stock_price:.2f} per share', 'success')
                return redirect(url_for('dashboard'))

    return render_template('trade.html', stock=stock, user=user, user_shares=user_shares, 
                         avg_buy_price=avg_buy_price, market_open=market_info['is_open'])


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
        
        elif 'price_simulation' in request.form:
            settings = MarketSettings.query.first()
            action = request.form['price_simulation']
            
            if action == 'enable':
                settings.price_simulation_enabled = True
                db.session.commit()
                flash('Price simulation enabled - Prices will update every minute', 'success')
            elif action == 'disable':
                settings.price_simulation_enabled = False
                db.session.commit()
                flash('Price simulation disabled', 'warning')
        
        elif 'schedule_action' in request.form:
            try:
                start_date_str = request.form['start_date']
                start_time_str = request.form['start_time']
                end_date_str = request.form['end_date']
                end_time_str = request.form['end_time']
                market_state = request.form['market_state']
                notes = request.form.get('notes', '')
                
                # Combine date and time
                start_datetime_str = f"{start_date_str} {start_time_str}"
                end_datetime_str = f"{end_date_str} {end_time_str}"
                start_datetime = datetime.strptime(start_datetime_str, '%Y-%m-%d %H:%M')
                end_datetime = datetime.strptime(end_datetime_str, '%Y-%m-%d %H:%M')
                
                # Check if the scheduled time is in the future
                if start_datetime <= datetime.utcnow():
                    flash('Start time must be in the future', 'error')
                elif end_datetime <= start_datetime:
                    flash('End time must be after start time', 'error')
                else:
                    new_schedule = MarketSchedule(
                        start_time=start_datetime,
                        end_time=end_datetime,
                        market_state=market_state,
                        notes=notes,
                        created_by=current_user.id
                    )
                    db.session.add(new_schedule)
                    db.session.commit()
                    flash(f'Market period scheduled from {start_datetime.strftime("%Y-%m-%d %H:%M")} to {end_datetime.strftime("%Y-%m-%d %H:%M")}', 'success')
            except ValueError as e:
                flash('Invalid date/time format', 'error')
            except Exception as e:
                flash(f'Error scheduling action: {str(e)}', 'error')
        
        elif 'cancel_schedule_id' in request.form:
            schedule_id = int(request.form['cancel_schedule_id'])
            schedule = MarketSchedule.query.get(schedule_id)
            if schedule and schedule.status == 'pending':
                schedule.status = 'cancelled'
                db.session.commit()
                flash('Scheduled action cancelled', 'success')
            else:
                flash('Schedule not found or already executed', 'error')

        return redirect(url_for('admin_dashboard'))
    
    stocks = Stock.query.all()
    market_info = market_hours_info()
    settings = MarketSettings.query.first()
    
    # Get all scheduled actions
    scheduled_periods = MarketSchedule.query.filter(
        MarketSchedule.status.in_(['active', 'completed', 'cancelled'])
    ).order_by(MarketSchedule.start_time.desc()).limit(20).all()
    
    return render_template('admin_dashboard.html', 
                         stocks=stocks, 
                         market_info=market_info, 
                         settings=settings,
                         scheduled_periods=scheduled_periods)


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
    total_gain_loss = 0
    
    for portfolio, stock in portfolio_items:
        current_value = portfolio.shares_owned * stock.current_price
        cost_basis = portfolio.shares_owned * portfolio.average_buy_price
        gain_loss = current_value - cost_basis
        gain_loss_percent = (gain_loss / cost_basis * 100) if cost_basis > 0 else 0
        
        formatted_items.append({
            'portfolio': portfolio,
            'stock': stock,
            'current_value': current_value,
            'cost_basis': cost_basis,
            'gain_loss': gain_loss,
            'gain_loss_percent': gain_loss_percent
        })
        portfolio_value += current_value
        total_gain_loss += gain_loss

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
                           total_gain_loss=total_gain_loss,
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


if __name__ == '__main__':
    app.run(debug=True)