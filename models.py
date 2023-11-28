import pyotp

from app import db, app
from flask_login import UserMixin, current_user
from datetime import datetime
from cryptography.fernet import Fernet
import bcrypt
import rsa
import pickle

class User(db.Model, UserMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)

    # User authentication information.
    email = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(100), nullable=False)
    pin_key = db.Column(db.String(32), nullable=False, default=pyotp.random_base32())

    # User information
    firstname = db.Column(db.String(100), nullable=False)
    lastname = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(100), nullable=False)
    postcode = db.Column(db.String(100), nullable=False)
    dateOfBirth = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(100), nullable=False, default='user')
    registrationDate = db.Column(db.DateTime, nullable=False)
    logInDateTime = db.Column(db.DateTime, nullable=False)
    prevLoginDateTime = db.Column(db.DateTime, nullable=False)
    ipCurrent = db.Column(db.String(100), nullable=False)
    ipLast = db.Column(db.String(100), nullable=True)
    successfulLogins = db.Column(db.Integer, nullable=True)

    # Symmetric encryption
    # postkey = db.Column(db.BLOB, nullable=False )

    # Define the relationship to Draw
    draws = db.relationship('Draw')

    public_key = db.Column(db.BLOB, nullable=False)
    private_key = db.Column(db.BLOB, nullable=False)

    def __init__(self, email, firstname, lastname, phone, password, role, postcode, dateOfBirth):
        self.email = email
        self.firstname = firstname
        self.lastname = lastname
        self.phone = phone
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        self.role = role
        self.dateOfBirth = dateOfBirth
        self.postcode = postcode
        self.registrationDate = datetime.now()
        self.logInDateTime = None
        self.prevLoginDateTime = None
        self.ipCurrent = None
        self.ipLast = None
        self.successfulLogins = 0
        # self.postkey = Fernet.generate_key()
        publickey, privatekey = rsa.newkeys(512)
        self.public_key = pickle.dumps(publickey)
        self.private_key = pickle.dumps(privatekey)

    def verify_pin(self, pin_key):
        return pyotp.TOTP(self.pin_key).verify(pin_key)

    def get_2fa_uri(self):
        return str(pyotp.totp.TOTP(self.pin_key).provisioning_uri(name=self.email, issuer_name='CSC2031 Blog'))

    def verify_post_code(self, postcode):
        return self.postcode == postcode

    def verify_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password)

# SYMMETRIC ENCRYPTION
'''
def encrypt(data, postkey):
    return Fernet(postkey).encrypt(bytes(data, 'utf-8'))

def decrypt(data, postkey):
    return Fernet(postkey).decrypt(data).decode('utf-8')
'''

def encrypt(data, public_key):
    rsa_key = pickle.loads(current_user.public_key)
    return rsa.encrypt(data.encode(), rsa_key)

def decrypt(data, private_key):
    rsa_key = pickle.loads(current_user.private_key)
    return rsa.decrypt(data, rsa_key).decode('utf_8')

class Draw(db.Model):
    __tablename__ = 'draws'

    id = db.Column(db.Integer, primary_key=True)

    # ID of user who submitted draw
    user_id = db.Column(db.Integer, db.ForeignKey(User.id), nullable=False)

    # 6 draw numbers submitted
    numbers = db.Column(db.String(100), nullable=False)

    # Draw has already been played (can only play draw once)
    been_played = db.Column(db.BOOLEAN, nullable=False, default=False)

    # Draw matches with master draw created by admin (True = draw is a winner)
    matches_master = db.Column(db.BOOLEAN, nullable=False, default=False)

    # True = draw is master draw created by admin. User draws are matched to master draw
    master_draw = db.Column(db.BOOLEAN, nullable=False)

    # Lottery round that draw is used
    lottery_round = db.Column(db.Integer, nullable=False, default=0)

    # def __init__(self, user_id, numbers, master_draw, lottery_round, postkey):
    def __init__(self, user_id, numbers, master_draw, lottery_round, public_key):
        self.user_id = user_id
        self.numbers = encrypt(numbers, public_key) # (... , postkey)
        self.been_played = False
        self.matches_master = False
        self.master_draw = master_draw
        self.lottery_round = lottery_round

    def view_draws(self, public_key): # (self, postkey)
        return decrypt(self.numbers, public_key) # ...(self.numbers, postkey)

def verify_password(self,password):
    return self.password == password

def init_db():
    with app.app_context():
        db.drop_all()
        db.create_all()
        admin = User(email='admin@email.com',
                     password='Admin1!',
                     firstname='Alice',
                     lastname='Jones',
                     phone='0191-123-4567',
                     role='admin')

        db.session.add(admin)
        db.session.commit()
