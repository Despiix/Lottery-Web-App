# IMPORTS
import logging
import os

import csp as csp
from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_qrcode import QRcode
from flask_login import LoginManager
from flask_talisman import Talisman


class SecurityFilter(logging.Filter):

    def filter(self, record):
        return 'SECURITY' in record.getMessage()


# log config
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
file_handler = logging.FileHandler('lottery.log', 'a')
file_handler.setLevel(logging.WARNING)
file_handler.addFilter(SecurityFilter())
formatter = logging.Formatter('%(asctime)s : %(message)s', '%m/%d/%Y %I:%M:%S %p')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

# CONFIG
app = Flask(__name__)
app.config['SECRET_KEY'] = 'LongAndRandomSecretKey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///lottery.db'
app.config['SQLALCHEMY_ECHO'] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['RECAPTCHA_PUBLIC_KEY'] = os.getenv('RECAPTCHA_PUBLIC_KEY')
app.config['RECAPTCHA_PRIVATE_KEY'] = os.getenv('RECAPTCHA_PRIVATE_KEY')

# initialise database
db = SQLAlchemy(app)
qrcode = QRcode(app)
# Setting up Talisman

csp = {
    # allow loading of the Bulma CSS framework resource
    'default-src': ['\'self\'',
                    'https://cdnjs.cloudflare.com/ajax/libs/bulma/0.7.2/css/bulma.min.css'],
    'frame-src': ['\'self\'',
                  'https://www.google.com/recaptcha/',
                  'https://recaptcha.google.com/recaptcha/'],
    'script-src': ['\'self\'',
                   '\'unsafe-inline\'',
                   'https://www.google.com/recaptcha/',
                   'https://www.gstatic.com/recaptcha/'],
    'img-src': ['data:'],
    'font-src': ['\'self\'',
                 'https://fonts.gstatic.com']
}

talisman = Talisman(app, content_security_policy=csp)

# LogIn Manager
login_manager = LoginManager()
login_manager.login_view = 'users/login'
login_manager.init_app(app)

from models import User


@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))


# HOME PAGE VIEW
@app.route('/')
def index():
    return render_template('main/index.html')


# BLUEPRINTS
# import blueprints
from users.views import users_blueprint
from admin.views import admin_blueprint
from lottery.views import lottery_blueprint

# register blueprints with app
app.register_blueprint(users_blueprint)
app.register_blueprint(admin_blueprint)
app.register_blueprint(lottery_blueprint)


# Error handling pages
@app.errorhandler(400)
def function_name(error):
    return render_template('error_handlers/400.html'), 400


@app.errorhandler(403)
def function_name(error):
    return render_template('error_handlers/403.html'), 403


@app.errorhandler(404)
def function_name(error):
    return render_template('error_handlers/404.html'), 404


@app.errorhandler(500)
def internal_error(error):
    return render_template('error_handlers/500.html'), 500


@app.errorhandler(503)
def internal_error(error):
    return render_template('error_handlers/503.html'), 503


if __name__ == "__main__":
    # Establishing HTTPS
    # Had to also edit the  flask config in order for it to work
    app.run(ssl_context=('cert.pem', 'key.pem'))
