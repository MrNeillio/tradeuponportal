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
from sqlalchemy import DECIMAL


app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['REMEMBER_COOKIE_DURATION'] = 0  # Prevents long-term login persistence
app.config['SESSION_PROTECTION'] = "strong"  # Ensure sessions are strict
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_TYPE'] = "filesystem"  # Store sessions in a file system, which resets easily

db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.session_protection = "strong"




# User Model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False)
    loyalty_points = db.Column(db.Integer, default=0)  # New field for loyalty points

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

        return redirect(url_for('admin_portal'))  # Redirect after sending message

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
    print(Message.body)  # This will show the body content in the terminal/log
    return render_template('view_messages.html', messages=messages)
    
    

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
        
        return redirect(url_for('customer_portal'))
    
    return render_template('add_loan.html', users=users)





# USER SEARCH
@app.route('/admin_search_user', methods=['GET', 'POST'])
@login_required
def admin_search_user():
    if current_user.role != 'admin':
        return redirect(url_for('customer_portal'))  # Ensure only admins can access

    user = None
    error_message = None

    if request.method == 'POST':
        username = request.form['username']
        user = User.query.filter_by(username=username).first()

        if not user:
            error_message = "User not found."

    return render_template('admin_search_user.html', user=user, error_message=error_message)


# PAYMENT LOG
@app.route('/log_payment/<int:loan_id>', methods=['GET', 'POST'])
@login_required
def log_payment(loan_id):
    if current_user.role != 'admin':
        return redirect(url_for('customer_portal'))  # Restrict non-admin users
    
    loan = Loan.query.get_or_404(loan_id)  # Get the loan or return a 404 if not found

    if request.method == 'POST':
        payment_amount = float(request.form['payment_amount'])

        # Ensure the payment is less than or equal to the loan amount
        if payment_amount <= loan.loan_amount:
            loan.loan_amount -= payment_amount

            if loan.loan_amount <= 0:
                loan.loan_amount = 0
                loan.status = 'Settled'  # Mark loan as settled
                loan.settled_date = datetime.now().date()

            db.session.commit()
            return redirect(url_for('admin_search_user'))  # Redirect after logging the payment

    return render_template('log_payment.html', loan=loan)


# OUTSTANDING BALANCE ROUTE

@app.route('/outstanding_balance')
@login_required
def outstanding_balance():
    total_balance = sum(loan.loan_amount for loan in current_user.loans)
    return render_template('outstanding_balance.html', total_balance=total_balance)






# ACTIVE LOANS ROUTE

@app.route('/active_loans')
@login_required
def active_loans():
    loans = Loan.query.filter_by(user_id=current_user.id, status='Active').all()
    return render_template('active_loans.html', loans=loans)





# PAST LOANS ROUTE

@app.route('/past_loans')
@login_required
def past_loans():
    loans = Loan.query.filter_by(user_id=current_user.id, status='Settled').all()
    return render_template('past_loans.html', loans=loans)






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
            selected_user = User.query.filter_by(username=username).first()

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
            selected_user = User.query.filter_by(username=username).first()
            if not selected_user:
                error_message = "User not found."

    return render_template('change_role.html', selected_user=selected_user, error_message=error_message)








# CUSTOMER PORTAL ROUTE

@app.route('/customer_portal')
@login_required
def customer_portal():
    return render_template('customer_portal.html')


# LOGIN ROUTE

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('customer_portal'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password, password):
            session.clear()  # Clear old session data before logging in
            session.modified = True  # Ensure session changes apply
            login_user(user, remember=False)  # No persistent login
            return redirect(url_for('customer_portal'))

    return render_template('login.html')








# REGISTER ROUTE

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password == confirm_password:
            # Check if it's the first user in the database
            first_user = User.query.first()  # Get the first user in the database (if any)
            
            # If there's no user, assign admin role to the first user
            if not first_user:
                role = 'admin'
            else:
                role = 'customer'
            
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            new_user = User(username=username, password=hashed_password, role=role)
            db.session.add(new_user)
            db.session.commit()
            
            # Debug: Check if the user was added and the role is correctly assigned
            print(f"New user created: {new_user.username} with role {new_user.role}")
            
            return redirect(url_for('login'))
        
    return render_template('register.html')


@app.route('/logout', methods=['GET', 'POST'])  # Accept POST requests too
@login_required
def logout():
    logout_user()
    session.clear()  # Clears all session data
    response = make_response(redirect(url_for('login')))
    response.delete_cookie('remember_token')
    response.delete_cookie('session')
    return response











@app.route('/')
def home():
    if current_user.is_authenticated:  # If user is already logged in, redirect them
        return redirect(url_for('customer_portal'))
    else: 
        return render_template('login.html')

if __name__ == "__main__":
    app.run(debug=True)












