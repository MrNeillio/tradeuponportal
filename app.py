from flask import render_template_string
from flask import Flask, render_template, redirect, url_for, request
from flask import flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_migrate import Migrate
from flask import make_response
from flask import session  # Import session to clear it
from datetime import datetime
from sqlalchemy import DECIMAL, func
from werkzeug.security import generate_password_hash
from flask_wtf import FlaskForm
from wtforms import DecimalField, SubmitField, StringField, PasswordField, BooleanField
from wtforms.validators import DataRequired, NumberRange, DataRequired, Length, EqualTo, Regexp
from flask import Flask
from flask_cors import CORS
from decimal import Decimal



app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['REMEMBER_COOKIE_DURATION'] = 0  # Prevents long-term login persistence
app.config['SESSION_PROTECTION'] = "strong"  # Ensure sessions are strict
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_TYPE'] = "filesystem"  # Store sessions in a file system, which resets easily
CORS(app, origins="http://127.0.0.1")  # Allow your frontend domain

db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()  # Log the user out
    session.clear()  # Clear session data
    response = make_response(redirect(url_for('login')))  # Redirect to login page
    response.delete_cookie('remember_token')  # Delete cookies if set
    response.delete_cookie('session')
    return response

login_manager.session_protection = "strong"



class LogPaymentForm(FlaskForm):
    amount = DecimalField('Payment Amount', places=2, validators=[DataRequired()])
    is_defaulted = BooleanField('Mark as Defaulted')  # Add this line for the checkbox
    

class Payment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    loan_id = db.Column(db.Integer, db.ForeignKey('loan.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<Payment {self.id} - Loan {self.loan_id} - ${self.amount}>'

# User Model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    phone_number = db.Column(db.String(20), nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False)
    loyalty_points = db.Column(db.Integer, default=0)  # New field for loyalty points

#REGISTER MODEL 
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=5, max=150), Regexp(r'^\S+$', message="Username cannot contain spaces.")])
    first_name = StringField('First Name', validators=[DataRequired(), Length(min=2, max=100)])
    last_name = StringField('Last Name', validators=[DataRequired(), Length(min=2, max=100)])
    phone_number = StringField('Phone Number', validators=[DataRequired(), Regexp(r'^\+?1?\d{1,15}$', message="Invalid phone number format.")])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=5), Regexp(r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$', message="Password must be at least 8 characters, contain a number, and a special character.")])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password', message='Passwords must match.')])


#Loan Model
class Loan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    loan_type = db.Column(db.String(100), nullable=False)
    collateral_item = db.Column(db.String(100), nullable=False)
    loan_amount = db.Column(db.Float, nullable=False)
    opening_balance = db.Column(db.Float, nullable=False)  # Initial loan amount
    current_balance = db.Column(DECIMAL(10, 2), nullable=False, default=0.0)
    due_date = db.Column(db.Date, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('loans', lazy=True))
    status = db.Column(db.String(50), default='Active')  # 'Active' or 'Settled'
    settled_date = db.Column(db.Date, nullable=True)  # New field to track the settled date
    
    def settle_loan(self):
        print(f"Settling loan with ID {self.id}, previous balance: {self.current_balance}")
        self.status = 'Settled'
        self.current_balance = round(0.0, 2)  # Round to two decimal places
        db.session.commit()
        print(f"Loan ID {self.id} settled, new balance: {self.current_balance}")

# Message Model
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    subject = db.Column(db.String(150), nullable=False)
    body = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    read = db.Column(db.Boolean, default=False)
    
    sender = db.relationship('User', foreign_keys=[sender_id], backref=db.backref('sent_messages', lazy=True))
    recipient = db.relationship('User', foreign_keys=[recipient_id], backref=db.backref('received_messages', lazy=True))

with app.app_context():
    db.create_all()





with app.app_context():
    db.create_all()

# User Loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))  # Use Session.get() instead of Query.get()
   




# Message Model 

@app.route('/send_message', methods=['GET', 'POST'])
@login_required
def send_message():
    if current_user.role != 'admin':
        return redirect(url_for('customer_portal'))  # Restrict non-admin users

    users = User.query.all()  # Get all users for message selection

    if request.method == 'POST':
        recipient_id = request.form['recipient_id']
        subject = request.form['subject']
        body = request.form['body']
        
        # Send the message
        message = Message(sender_id=current_user.id, recipient_id=recipient_id, 
                          subject=subject, body=body)
        db.session.add(message)
        db.session.commit()

        return redirect(url_for('customer_portal'))  # Redirect after sending message

    return render_template('send_message.html', users=users)

#DELETE MESSAGE 

@app.route('/message/delete/<int:message_id>', methods=['POST'])
@login_required
def delete_message(message_id):
    message = Message.query.get_or_404(message_id)

    # Check if the message belongs to the current user (or if they are an admin)
    if message.recipient_id != current_user.id and current_user.role != 'admin':
        flash('You are not authorized to delete this message.', 'danger')
        return redirect(url_for('view_messages'))  # Redirect to inbox if not authorized

    # Delete the message
    db.session.delete(message)
    db.session.commit()

    flash('Message deleted successfully.', 'success')
    return redirect(url_for('view_messages'))  # Redirect to inbox or appropriate page


#User View Message

@app.route('/messages')
@login_required
def view_messages():
    messages = Message.query.filter_by(recipient_id=current_user.id).order_by(Message.timestamp.desc()).all()
    unread_count = Message.query.filter_by(recipient_id=current_user.id, read=False).count()

    print(Message.body)  # This will show the body content in the terminal/log
    return render_template('view_messages.html', messages=messages, unread_count=unread_count)
    
    

@app.route('/test_html')
def test_html():
    test_message = "<b>This should be bold</b><br><i>This should be italic</i>"
    return render_template_string("{{ message | safe }}", message=test_message)


# View Message Model

@app.route('/message/<int:message_id>', methods=['GET', 'POST'])
@login_required
def view_message(message_id):
    message = Message.query.get_or_404(message_id)

    # Debug: Check if the message body contains HTML
    print(f"Message body: {message.body}")

    if not message.read:
        message.read = True
        db.session.commit()

    if request.method == 'POST':
        reply_body = request.form['body']
        reply = Message(sender_id=current_user.id, recipient_id=message.sender_id, 
                        subject="Re: " + message.subject, body=reply_body)
        db.session.add(reply)
        db.session.commit()
        return redirect(url_for('view_messages'))

    return render_template('view_message.html', message=message)






# ADMIN VIEW SENT MESSAGES

@app.route('/sent_messages')
@login_required
def sent_messages():
    if current_user.role != 'admin':
        return redirect(url_for('customer_portal'))  # Restrict non-admin users

    messages = Message.query.filter_by(sender_id=current_user.id).order_by(Message.timestamp.desc()).all()
    return render_template('sent_messages.html', messages=messages)


# ADMIN PORTAL ROUTE

@app.route('/admin_portal')
@login_required
def admin_portal():
    if current_user.role == 'admin':
        return render_template('admin_portal.html')
    return redirect(url_for('customer_portal'))  # Redirect non-admin users to customer portal



# ADD LOAN ROUTE

@app.route('/add_loan', methods=['GET', 'POST'])
@login_required
def add_loan():
    if current_user.role != 'admin':
        return redirect(url_for('customer_portal'))
    
    users = User.query.all()
    
    if request.method == 'POST':
        loan_type = request.form['loan_type']
        collateral_item = request.form['collateral_item']
        loan_amount = float(request.form['loan_amount'])
        due_date = datetime.strptime(request.form['due_date'], '%Y-%m-%d').date()
        user_id = int(request.form['user_id'])
        
        loan = Loan(loan_type=loan_type, collateral_item=collateral_item,
                    loan_amount=loan_amount, opening_balance=loan_amount,
                    current_balance=loan_amount, due_date=due_date, user_id=user_id)
        
        db.session.add(loan)
        db.session.commit()
        
        # Flash success message
        flash('Loan successfully added!', 'success')
        
        return redirect(url_for('add_loan'))
    
    return render_template('add_loan.html', users=users)






# USER SEARCH
from sqlalchemy import func

@app.route('/admin_search_user', methods=['GET', 'POST'])
@login_required
def admin_search_user():
    if current_user.role != 'admin':
        return redirect(url_for('customer_portal'))  # Ensure only admins can access

    user = None
    total_balance = 0  # Initialize total balance
    active_loans = []  # Initialize active loans list
    past_loans = []  # Initialize past loans list
    defaulted_loans = []  # Initialize defaulted loans list
    
    error_message = None

    if request.method == 'POST':
        search_query = request.form.get('search_query', '').strip().lower()  # Use .get() to avoid KeyError

        if search_query:
            # Check if the search query is for a username or phone number
            if search_query.isnumeric():  # If it's a number, we assume it's a phone number
                user = User.query.filter(User.phone_number == search_query).first()
            else:
                # Search by exact username or by both first name and last name together
                name_parts = search_query.split()
                if len(name_parts) == 2:  # We expect both first and last name
                    first_name, last_name = name_parts
                    user = User.query.filter(
                        (func.lower(User.username) == search_query) |  # Apply .lower() for case-insensitive username comparison
                        (User.phone_number == search_query) | 
                        (func.concat(func.lower(User.first_name), ' ', func.lower(User.last_name)) == search_query)
                    ).first()
                else:
                    user = User.query.filter(
                        (func.lower(User.username) == search_query) |  # Apply .lower() for case-insensitive username comparison
                        (User.phone_number == search_query) |
                        (func.concat(func.lower(User.first_name), ' ', func.lower(User.last_name)) == search_query)
                    ).first()

            if user:
                # Calculate total outstanding balance for active loans
                total_balance = sum(loan.loan_amount for loan in user.loans if loan.status == 'Active')

                # Fetch active loans
                active_loans = [loan for loan in user.loans if loan.status == 'Active']

                # Fetch past loans (including defaulted loans)
                past_loans = [loan for loan in user.loans if loan.status != 'Active']

                # Filter out defaulted loans (ensure 'Defaulted' status is being set properly)
                defaulted_loans = [loan for loan in past_loans if loan.status == 'Defaulted']
            else:
                error_message = "User not found."
        else:
            error_message = "Please enter a search query."

    return render_template('admin_search_user.html', 
                           user=user, 
                           total_balance=total_balance, 
                           active_loans=active_loans, 
                           past_loans=past_loans, 
                           defaulted_loans=defaulted_loans, 
                           error_message=error_message)









# PAYMENT LOG
# PAYMENT LOG
@app.route('/log_payment/<int:loan_id>', methods=['GET', 'POST'])
@login_required
def log_payment(loan_id):
    loan = Loan.query.get_or_404(loan_id)
    form = LogPaymentForm()

    if request.method == 'POST' and form.validate_on_submit():
        payment_amount = form.amount.data

        # Convert the payment_amount to Decimal
        payment_amount = Decimal(payment_amount)

        # Check if payment_amount is greater than loan_amount
        if payment_amount > loan.loan_amount:
            flash('Payment amount cannot be greater than the loan amount.', 'danger')
            return redirect(url_for('admin_search_user', loan_id=loan.id))  # Redirect back to the payment form

        # Log the new payment
        new_payment = Payment(loan_id=loan.id, amount=payment_amount, timestamp=datetime.utcnow())
        db.session.add(new_payment)

        # Ensure loan.loan_amount is also a Decimal
        loan.loan_amount = Decimal(loan.loan_amount) - payment_amount  # Convert both to Decimals

        # If the loan is settled, update status
        if loan.loan_amount <= 0:
            loan.loan_amount = Decimal('0.00')
            loan.status = 'Settled'
            loan.settled_date = datetime.now().date()

        # Check if the payment is marked as defaulted
        is_defaulted = form.is_defaulted.data  # Check if the checkbox is ticked

        if is_defaulted:
            loan.status = 'Defaulted'  # Set the loan status to Defaulted
            loan.loan_amount = Decimal('0.00')  # Set the loan balance to 0

        db.session.commit()

        # Flash success message
        flash('Payment logged successfully and balance updated!', 'success')
        return redirect(url_for('admin_search_user'))  # Redirect after successful payment

    return render_template('log_payment_form.html', form=form, loan=loan)







# OUTSTANDING BALANCE ROUTE

@app.route('/outstanding_balance')
@login_required
def outstanding_balance():
    total_balance = sum(loan.loan_amount for loan in current_user.loans)
    return render_template('outstanding_balance.html', total_balance=total_balance)













# PAST LOANS ROUTE

@app.route('/active_loans')
@login_required
def active_loans():
    # Get active loans
    active_loans = Loan.query.filter_by(user_id=current_user.id, status='Active').all()

    # Get past loans
    past_loans = Loan.query.filter(
        Loan.user_id == current_user.id, 
        Loan.status.in_(['Settled', 'Defaulted'])
    ).all()

    # Render the active_loans.html template with both active and past loans
    return render_template('active_loans.html', active_loans=active_loans, past_loans=past_loans)








# LOYALTY POINTS ROUTE

@app.route('/loyalty_points', methods=['GET', 'POST'])
@login_required
def loyalty_points():
    users = User.query.all()  # Fetch all users from the database

    if request.method == 'POST':
        user_id = request.form['user_id']
        points_to_add = int(request.form['points_to_add'])

        user = User.query.get(user_id)
        if user:
            user.loyalty_points += points_to_add
            db.session.commit()

    return render_template('loyalty_points.html', users=users)



# ADMIN CHANGE PASSWORD

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if current_user.role != 'admin':
        return redirect(url_for('customer_portal'))  # Restrict non-admin users
    
    users = User.query.all()  # Get all users from the database
    if request.method == 'POST':
        user_id = request.form['user_id']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        
        # Ensure passwords match
        if new_password == confirm_password:
            user_to_change = User.query.get(user_id)
            hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            user_to_change.password = hashed_password
            db.session.commit()
            return redirect(url_for('customer_portal'))  # Redirect to admin portal after password change
    
    return render_template('change_password.html', users=users)

# EDIT PASSWORD ROUTE
 
@app.route('/edit_password', methods=['GET', 'POST'])
@login_required
def edit_password():
    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        
        if new_password == confirm_password:
            hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            current_user.password = hashed_password
            db.session.commit()
            return redirect(url_for('customer_portal'))  # Redirect to the portal after password change
    
    return render_template('edit_password.html')







# CHANGE ROLE

@app.route('/change_role', methods=['GET', 'POST'])
@login_required
def change_role():
    if current_user.role != 'admin':
        return "Access denied. Only admins can change roles."

    selected_user = None
    error_message = None
    
    if request.method == 'POST':
        if 'change_role' in request.form:  # When changing role
            username = request.form['username']
            new_role = request.form['new_role']
            
            # Case-insensitive search (using ilike for PostgreSQL or lower() for MySQL)
            selected_user = User.query.filter(User.username.ilike(f'%{username}%')).first()

            if selected_user:
                # Prevent admin from changing their own role
                if selected_user.id == current_user.id:
                    error_message = "Admins cannot change their own role."
                else:
                    selected_user.role = new_role
                    db.session.commit()
                    return redirect(url_for('customer_portal'))  # Redirect after role change
            else:
                error_message = "User not found."

        else:  # When searching for a user
            username = request.form['username']
            
            # Case-insensitive search (using ilike for PostgreSQL or lower() for MySQL)
            selected_user = User.query.filter(User.username.ilike(f'%{username}%')).first()
            if not selected_user:
                error_message = "User not found."

    return render_template('change_role.html', selected_user=selected_user, error_message=error_message)









# CUSTOMER PORTAL ROUTE

@app.route('/customer_portal')
@login_required
def customer_portal():

    unread_message_count = Message.query.filter_by(recipient_id=current_user.id, read=False).count()
    
    return render_template('customer_portal.html', unread_message_count=unread_message_count)


# LOGIN ROUTE

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('customer_portal'))

    if request.method == 'POST':
        username = request.form['username'].strip().lower()  # Normalize to lowercase
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password, password):
            session.clear()  # Clear old session data before logging in
            session.modified = True  # Ensure session changes apply
            login_user(user, remember=False)  # No persistent login
            return redirect(url_for('customer_portal'))

    return render_template('login.html')








# Register Route
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()

    if form.validate_on_submit():
        # Normalize the username to lowercase
        username = form.username.data.strip().lower()
        first_name = form.first_name.data
        last_name = form.last_name.data
        phone_number = form.phone_number.data
        password = form.password.data
        role = 'customer'  # Default role for new users
        loyalty_points = 0

        # Hash the password
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # Check if the username already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose a different one.', 'danger')
            return redirect(url_for('register'))

        # Create the new user
        new_user = User(username=username, first_name=first_name, last_name=last_name, phone_number=phone_number, password=hashed_password, role=role, loyalty_points=loyalty_points)
        
        # Add the new user to the database
        db.session.add(new_user)
        db.session.commit()

        flash('Your account has been created! You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html', form=form)










@app.route('/')
def home():
    if current_user.is_authenticated:  # If user is already logged in, redirect them
        return redirect(url_for('customer_portal'))
    else: 
        return render_template('login.html')

if __name__ == "__main__":
    app.run(debug=True)












