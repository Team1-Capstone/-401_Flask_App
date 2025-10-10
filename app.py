from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, time
from decimal import Decimal
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from functools import wraps
import re
from flask import abort
from markethours import MarketHours


app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:password@localhost/stock_trading_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = "650a5cb8a4e921d0f8a4bb24d0bc30cc53304f3ccf1d8486e90e0b52218d4ee4b0c6c277c3e47834964cc7b04cf150685e86fff261c8db0285a367d209b75f63"

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


with app.app_context():
    db.create_all()


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
    market_hours = {
        'is_open': MarketHours().market_has_opened,
        'opens_at': MarketHours().open.strftime('%A, %b %d at %I:%M %p EST'),
        'closes_at': MarketHours().close.strftime('%A, %b %d at %I:%M %p EST')
    }

    return render_template('market.html', stocks=stocks, market_hours=market_hours)


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

    if request.method == 'POST':
        if user.role != 'admin' and MarketHours.market_has_closed():
            flash(f'Trading will reopen at {MarketHours().open}.', 'error')
            return redirect(url_for('dashboard'))

        action = request.form['action']
        shares = int(request.form['shares'])

        if shares <= 0:
            flash('Enter a valid number of shares', 'error')
            return redirect(url_for('trade', ticker=ticker))

        if action == 'buy':
            total_cost = shares * stock.current_price
            if user.cash_balance < total_cost:
                flash('Insufficient funds', 'error')
            else:
                new_transaction = Transaction(
                    user_id=user.id,
                    stock_id=stock.stock_id,
                    type='buy',
                    quantity=shares,
                    price=stock.current_price
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
                    f'Successfully bought {shares} shares of {stock.ticker}', 'success')
                return redirect(url_for('dashboard'))

        elif action == 'sell':
            if not portfolio_item or portfolio_item.shares_owned < shares:
                flash('Not enough shares to sell', 'error')
            else:
                total_value = shares * stock.current_price

                new_transaction = Transaction(
                    user_id=user.id,
                    stock_id=stock.stock_id,
                    type='sell',
                    quantity=shares,
                    price=stock.current_price
                )

                user.cash_balance += total_value

                portfolio_item.shares_owned -= shares
                if portfolio_item.shares_owned == 0:
                    db.session.delete(portfolio_item)

                db.session.add(new_transaction)
                db.session.commit()

                flash(
                    f'Successfully sold {shares} shares of {stock.ticker}', 'success')
                return redirect(url_for('dashboard'))

    return render_template('trade.html', stock=stock, user=user, user_shares=user_shares)


'''
#OLD ROUTES TO LOOK AT FOR DEFAULT


@app.route('/transaction_history')
@login_required
def transaction_history():
    return render_template('transaction_history.html')
'''
'''
@app.route('/cash_management')
@login_required
def cash_management():
    return render_template('cash_management.html')
'''


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

        return redirect(url_for('admin_dashboard'))
    stocks = Stock.query.all()
    return render_template('admin_dashboard.html', stocks=stocks)


# ====================================================================n
# new ROUTES DELETE COMMENT WHEN REDENDENCY IS NO LONGER NEEDED =====
# ===================================================================

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


if __name__ == '__main__':
    app.run(debug=True)
