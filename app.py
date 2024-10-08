from flask import Flask, render_template, redirect, url_for, flash, request, session
import boto3
from botocore.exceptions import ClientError
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Email, Length, EqualTo

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'

# AWS Cognito Setup
client = boto3.client('cognito-idp', region_name='us-west-2')

USER_POOL_ID = 'us-east-2_II9NpY4Sm'  # Replace with your Cognito User Pool ID
CLIENT_ID = 'rb1iq7rng5e2bbn2n7s4qduf9'  # Replace with your Cognito App Client ID

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
            return redirect(url_for('index'))

        except ClientError as e:
            flash(f"Login error: {e.response['Error']['Message']}", 'danger')

    return render_template('login.html', form=form)


@app.route('/')
def index():
    if 'id_token' in session:
        return "You are logged in!"
    return "Welcome to the home page!"


@app.route('/logout')
def logout():
    session.pop('id_token', None)
    session.pop('access_token', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(debug=True)
