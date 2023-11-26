from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, SubmitField, PasswordField, EmailField
from wtforms.validators import Email, DataRequired, EqualTo, ValidationError, Length
from datetime import datetime
import re


def character_check(form, field):
    excluded_chars = "* ? ! ' ^ + % & / ( ) = } ] [ { $ # @ < >"

    for char in field.data:
        if char in excluded_chars:
            raise ValidationError(f"Character {char} is not allowed. ")


def validate_phone(form, field):
    form.phone_validation_already_called = True  # It has been called, Flag = True
    if not re.match(r'^\d{4}-\d{3}-\d{4}$', field.data):
        raise ValidationError("Phone number must be in XXXX-XXX-XXXX format")


def validate_DOB(form, field):
    if not re.match(r'^\d{2}/\d{2}/\d{4}$', field.data):
        raise ValidationError("Date of Birth must be in DD/MM/YYYY format")

    # Assigns the parts of data to the correct variables
    day, month, year = map(int, field.data.split('/'))

    # Check if year starts with 19 or 20 and is followed by two digits
    if not (1900 <= year <= 2099):
        raise ValidationError("Year must be between 1900 and 2099")

    # Checks if month is between 1 and 12
    if not 1 <= month <= 12:
        raise ValidationError("Month must be between 1 and 12")

    # Checks if day is between 1 and 31
    if not 1 <= day <= 31:
        raise ValidationError("Day must be between 1 and 31")

    # Sets dates that have 30 days
    if month in [4, 6, 9, 11] and day > 30:
        raise ValidationError("Invalid: This month has only 30 days")

    if month == 2:
        # Checks if Feb has 28 or 29 days
        is_leap_year = year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)
        if (is_leap_year and day > 29) or (not is_leap_year and day > 28):
            raise ValidationError("Invalid date: February has 28 days or 29 in a leap year")

    try:
        dob = datetime.strptime(field.data, '%d/%m/%Y')
    except ValueError:
        raise ValidationError("Invalid date format")

    # Check if the date of birth is in the future
    if dob > datetime.now():
        raise ValidationError("Date of Birth cannot be in the future")


def validate_post_code(form, field):
    if not re.match(r"^[A-Z]{1,2}[0-9R][0-9A-Z]? [0-9][A-Z]{2}$", field.data):
        raise ValidationError("Invalid postcode format. Expected formats: 'XY YXX', 'XYY YXX', 'XXY YXX'.")


def validate_password(form, password):
    if len(password.data) > 12 or len(password.data) < 6:
        raise ValidationError('Password length must be between 6 and 12 characters')

    p = re.compile(r'(?=.*\d)(?=.*[A-Z])(?=.*[a-z])(?=.*\W)')
    if not p.match(password.data):
        raise ValidationError('Password must contain 1 digit,'
                              ' 1 uppercase letter and 1 special character')


class RegisterForm(FlaskForm):
    email = EmailField(validators=[DataRequired(), Email()])
    firstname = StringField(validators=[DataRequired(), character_check])
    lastname = StringField(validators=[DataRequired(), character_check])
    dateOfBirth = StringField(validators=[DataRequired(), validate_DOB])
    phone = StringField(validators=[DataRequired(), validate_phone])
    postcode = StringField(validators=[DataRequired(), validate_post_code])
    password = PasswordField(validators=[DataRequired()])
    confirm_password = PasswordField(validators=[DataRequired(), EqualTo('password',
                                                                         message='Passwords do not match')])
    submit = SubmitField()


class LoginForm(FlaskForm):
    username = StringField(validators=[DataRequired(), Email()])
    password = PasswordField(validators=[DataRequired()])
    postcode = StringField(validators=[DataRequired(), validate_post_code])
    auth_pin = StringField(validators=[DataRequired(), Length(min=6, max=6)])
    recaptcha = RecaptchaField()
    submit = SubmitField()

class ChangePassword(FlaskForm):
    current_password = PasswordField(validators=[DataRequired()])
    new_password = PasswordField(validators=[DataRequired()])
    confirm_new_password = PasswordField(validators=[DataRequired(), EqualTo('password',
                                                                             message='Passwords do not match')])