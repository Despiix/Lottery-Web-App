# IMPORTS
import bcrypt
from flask import Blueprint, render_template, flash, redirect, url_for, session, request
from flask_login import logout_user, login_user, current_user, login_required
from markupsafe import Markup
from datetime import datetime
from app import logging
from functools import wraps

from app import db
from models import User
from users.forms import RegisterForm, LoginForm, ChangePassword

# CONFIG
users_blueprint = Blueprint('users', __name__, template_folder='templates')


# Access Control - restrict access to certain roles
def requires_roles(*roles):
    def wrapper(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            # check if the current user is authenticated
            if current_user.is_authenticated:
                # if the user does not have the specified role restrict the access
                if current_user.role not in roles:
                    # Log the unauthorized access attempt
                    logging.warning(f'Unauthorized Access [%s, %s, %s, %s]',
                                    current_user.id,
                                    current_user.email,
                                    current_user.role,
                                    request.remote_addr)
                    return render_template('error_handlers/403.html')
            else:
                # add the unauthenticated attempt to access a restricted page to the log file
                logging.warning('SECURITY - Unauthenticated User Access [%s]', request.remote_addr)
                return render_template('error_handlers/403.html'), 403
            return f(*args, **kwargs)

        return wrapped

    return wrapper


# VIEWS
# view registration
@users_blueprint.route('/register', methods=['GET', 'POST'])
def register():
    # create signup form object
    form = RegisterForm()

    # if request method is POST or form is valid
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        # if this returns a user, then the email already exists in database

        # if email already exists redirect user back to signup page with error message so user can try again
        if user:
            flash('Email address already exists')
            return render_template('users/register.html', form=form)

        # create a new user with the form data
        new_user = User(email=form.email.data,
                        firstname=form.firstname.data,
                        lastname=form.lastname.data,
                        phone=form.phone.data,
                        password=form.password.data,
                        role='user',
                        postcode=form.postcode.data,
                        dateOfBirth=form.dateOfBirth.data
                        )

        # add the new user to the database
        db.session.add(new_user)
        db.session.commit()

        logging.warning('SECURITY - New User Registration [%s, %s]', form.email.data, request.remote_addr)

        session['email'] = new_user.email

        # sends user to login page
        return redirect(url_for('users.setup_2fa'))
    # if request method is GET or form not valid re-render signup page
    return render_template('users/register.html', form=form)


@users_blueprint.route('/change password', methods=['GET', 'POST'])
@requires_roles('user', 'admin')
@login_required
def change_password():
    form = ChangePassword()

    if form.validate_on_submit():

        # Verify current password
        if current_user.verify_password(form.current_password.data):
            # Check if the new password is equal to the prev one
            # The new password needs to be hashed in order to check
            if bcrypt.checkpw(form.new_password.data.encode('utf-8'), current_user.password):
                flash('New password cannot be the same as previous one')
                return render_template('users/change_password.html', form=form)

            # Hash the new password that is added to the db
            current_user.password = bcrypt.hashpw(form.new_password.data.encode('utf-8'), bcrypt.gensalt())
            # Update user's password in the db
            db.session.commit()

            flash('Password updated successfully!')
            return redirect(url_for('users.account'))

        flash('Current password is incorrect.')
        return render_template('users/change_password.html', form=form)

    return render_template('users/change_password.html', form=form)


# view user login, the user has 3 attempts to log in
@users_blueprint.route('/login', methods=['GET', 'POST'])
def login():
    # if the authentication attempts are not in the session initialize them
    if not session.get('authentication_attempts'):
        session['authentication_attempts'] = 0
    # Create an instance of the Login form
    form = LoginForm()
    if form.validate_on_submit():
        # Query the user by the email entered in the form
        user = User.query.filter_by(email=form.username.data).first()
        if not user or not user.verify_password(form.password.data) or not user.verify_post_code(
                form.postcode.data) or not user.verify_pin(form.auth_pin.data):
            # if the information does not match then send out a message to show how many attempts remain
            logging.warning('SECURITY - LogIn Attempt [%s, %s]', form.username.data, request.remote_addr)
            # increment the authentication attempts
            session['authentication_attempts'] += 1
            # if the attempts exceed 3 then lock the page and provide a reset link
            if session.get('authentication_attempts') >= 3:
                flash(Markup('Number of incorrect login attempts exceeded.'
                             ' Please click <a href="/reset">here</a> to reset.'))
                return render_template('users/login.html')
            # shows the user how many attempts they have left
            attempts_remaining = 3 - session.get('authentication_attempts')
            flash('Please check your login details and try again, '
                  '{} login attempts remaining'.format(3 - session.get('authentication_attempts')))
            return render_template('users/login.html', form=form)
        # Login the user and reset the login attempts count
        login_user(user)
        current_user.successfulLogins = 0
        # Write the successful login to the log file
        logging.warning('SECURITY - New LogIn [%s, %s, %s]', current_user.id, current_user.email, request.remote_addr)
        # update the users login time and current / previous ip
        current_user.prevLoginDateTime = current_user.logInDateTime
        current_user.logInDateTime = datetime.now()
        current_user.ipLast = current_user.ipCurrent
        current_user.ipCurrent = request.remote_addr
        current_user.successfulLogins += 1
        db.session.commit()
        # check the role of the user and redirect them to the correct page
        if current_user.role != 'admin':
            return redirect(url_for('lottery.lottery'))
        else:
            return redirect(url_for('admin.admin'))
    return render_template('users/login.html', form=form)


@users_blueprint.route('/logout')
@requires_roles('user', 'admin')
@login_required
def logout():
    # Write the logout to the logs
    logging.warning('SECURITY - User Log Out [%s, %s, %s]', current_user.id, current_user.email, request.remote_addr)
    # logout the user then redirect them to the home page
    logout_user()
    return redirect(url_for('index'))


# view user account
@users_blueprint.route('/account')
@requires_roles('user', 'admin')
@login_required
def account():
    # render the account page using the current user's info
    return render_template('users/account.html',
                           acc_no=current_user.id,
                           email=current_user.email,
                           firstname=current_user.firstname,
                           lastname=current_user.lastname,
                           phone=current_user.phone,
                           postcode=current_user.postcode,
                           dateOfBirth=current_user.dateOfBirth)


@users_blueprint.route('/setup_2fa')
def setup_2fa():
    # Check if username is in the app session
    if 'email' not in session:
        return redirect(url_for('index'))
    # Retrieve the user based on the email stored in the session
    user = User.query.filter_by(email=session['email']).first()
    if not user:
        return redirect(url_for('index'))

    del session['email']

    return render_template('users/setup_2fa.html', email=user.email, uri=user.get_2fa_uri())


@users_blueprint.route('/reset')
# reset the count of authentication attempts
def reset():
    session['authentication_attempts'] = 0
    return redirect(url_for('users.login'))
