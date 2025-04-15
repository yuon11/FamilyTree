from flask import Flask, render_template, redirect, url_for, flash, request, session
import boto3
import os
import jwt
from botocore.exceptions import ClientError
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Email, Length, EqualTo
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature

app = Flask(__name__)
mail = Mail(app)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['MAIL_SERVER'] = 'smtp.your-email-provider.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your-email@example.com'
app.config['MAIL_PASSWORD'] = 'your-email-password'


app.config['SECRET_KEY'] = 'your_secret_key'
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# AWS Cognito Setup
client = boto3.client('cognito-idp', region_name='us-west-2')

USER_POOL_ID = 'us-east-2_II9NpY4Sm'  # Replace with your Cognito User Pool ID
CLIENT_ID = 'rb1iq7rng5e2bbn2n7s4qduf9'  # Replace with your Cognito App Client ID
# Dummy Cognito keys and ID token decoding for example purposes
COGNITO_PUBLIC_KEY = "your-cognito-public-key"  # Replace with actual key or method to fetch it

# Function to decode ID token
def decode_token(id_token):
    try:
        decoded_token = jwt.decode(id_token, COGNITO_PUBLIC_KEY, algorithms=['RS256'])
        return decoded_token
    except jwt.ExpiredSignatureError:
        flash("Session expired. Please log in again.", "danger")
        return None
    except jwt.InvalidTokenError:
        flash("Invalid token. Please log in again.", "danger")
        return None

def get_secret():
    secret_name = "your_secret_key_name"
    region_name = "us-west-2"  # Replace with your AWS region

    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(service_name='secretsmanager', region_name=region_name)

    try:
        get_secret_value_response = client.get_secret_value(SecretId=secret_name)
        secret = get_secret_value_response['SecretString']
        return secret
    except ClientError as e:
        # Handle error if secret can't be fetched
        return None

# Password Recovery Form
class PasswordRecoveryForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email()])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=6)])
    submit = SubmitField('Sign Up')

# RESET PASSWORD
class PasswordResetForm(FlaskForm):
    password = PasswordField('New Password', validators=[InputRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[InputRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')

# Sign-up form
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=20)])
    email = StringField('Email', validators=[InputRequired(), Email()])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[InputRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')


# Login form
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email()])
    password = PasswordField('Password', validators=[InputRequired()])
    submit = SubmitField('Login')


@app.route('/reset_password_request', methods=['GET','POST'])
def reset_password_request():
    form = PasswordRecoveryForm()
    if form.validate_on_submit():
        email = form.email.data
        # Generate a token with a 1-hour expiration time
        token = serializer.dumps(email, salt='password-reset-salt')
        
        # Generate the password reset URL
        reset_url = url_for('reset_password_request', token=token, _external=True)
        
        # Send email with reset URL
        msg = Message('Password Reset Request', sender='noreply@yourapp.com', recipients=[email])
        msg.body = f'Please click the link to reset your password: {reset_url}'
        mail.send(msg)
        
        flash('A password reset link has been sent to your email.', 'info')
        return redirect(url_for('index')) 
    return render_template('reset_password_request.html', form=form)

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    form = PasswordResetForm()
    
    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=3600)  # 1 hour expiration
    except (SignatureExpired, BadSignature):
        flash('The password reset link is invalid or has expired.', 'danger')
        return redirect(url_for('reset_password_request'))
    
    if form.validate_on_submit():
        # Update the user’s password in your database
        new_password = form.password.data
        # Here, you'd normally hash the password and update it in the database
        flash('Your password has been updated!', 'success')
        return redirect(url_for('login'))
    
    return render_template('reset_password.html', form=form)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegistrationForm()

    if form.validate_on_submit():
        try:
            response = client.sign_up(
                ClientId=CLIENT_ID,
                Username=form.username.data,
                Password=form.password.data,
                UserAttributes=[{'Name': 'email', 'Value': form.email.data}]
            )
            flash('Sign-up successful! Please check your email to confirm your account.', 'success')
            return redirect(url_for('login'))

        except ClientError as e:
            flash(f"Error during sign-up: {e.response['Error']['Message']}", 'danger')
    return render_template('signup.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        try:
            # Authenticate the user with Cognito
            response = client.initiate_auth(
                ClientId=CLIENT_ID,
                AuthFlow='USER_PASSWORD_AUTH',
                AuthParameters={
                    'USERNAME': form.email.data,
                    'PASSWORD': form.password.data
                }
            )

            # Store user tokens (ID Token, Access Token) in session
            session['id_token'] = response['AuthenticationResult']['IdToken']
            session['access_token'] = response['AuthenticationResult']['AccessToken']
            flash('Login successful!', 'success')
            return redirect(url_for('landing'))
        except ClientError as e:
            flash(f"Login error: {e.response['Error']['Message']}", 'danger')
    return render_template('login.html', form=form)

# User landing page route
@app.route('/landing')
def landing():
    if 'id_token' not in session:
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('login'))
    
    # Decode the ID token to get user details
    user_info = decode_token(session['id_token'])
    
    if user_info is None:
        return redirect(url_for('login'))
    
    # Pass user information to the template
    return render_template('landing.html', user_info=user_info)

@app.route('/')
def index():
    if 'id_token' in session:
        return "You are logged in!"
    # return "Welcome to the home page!"
    # return render_template('F:\\Users\\Yuon\\PersonalProjects\\FamilyTree\\index.html')
    # get the current working directory
    current_working_directory = os.getcwd()

    return render_template('index.html')


@app.route('/logout')
def logout():
    session.pop('id_token', None)
    session.pop('access_token', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(debug=True)
