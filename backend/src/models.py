import json
import uuid

import bcrypt
import mongoengine
from flask_mongoengine import MongoEngine
from scipy.misc import derivative
#from csbt import db
from datetime import datetime, date, timedelta
from csbt.src.util import constants
from csbt.src.util.helper_functions import (getTimeStamp, get_current_time_zone_date, get_time_stamp)
from bson.json_util import dumps, loads
def __unicode__(self):
    return self.name
''' CLASS DEFINITIONS.'''

db = MongoEngine()

class User(db.Document):
    """Model for User."""

    first_name = db.StringField()
    last_name = db.StringField()
    user_name = db.StringField(unique=True)
    email_id = db.StringField(unique=True)
    role = db.ListField(db.StringField())
    activation_flag = db.StringField()
    date_created = db.DateTimeField(default = getTimeStamp())


class OldPasswordsInfo(db.EmbeddedDocument):

    One = db.BinaryField()
    Two = db.BinaryField()

class UserAuthInfo(db.Document):

    user_id = db.ReferenceField("User")
    meta ={"collection_name": "user_auth_info"}
    password = db.BinaryField()
    last_passwords =  db.EmbeddedDocumentField(OldPasswordsInfo)
    password_expiry_date = db.DateTimeField()


class UserAuthLogs(db.Document):

    user_id = db.ReferenceField("User")
    login_timestamp = db.DateTimeField()
    login_status = db.StringField()
    ip_address = db.StringField()


class UserSessionTimeout(db.Document):

    refresh_token = db.StringField()
    auth_token = db.StringField(unique=True)
    user_name = db.StringField()
    last_activity = db.DateTimeField()


class OtpDetails(db.EmbeddedDocument):
    otp = db.StringField()
    otp_expiration_time = db.DateTimeField()
    token = db.StringField()


class UserOtpInfo(db.Document):
    ID = db.ReferenceField("User", primary_key=True)
    otp_info = db.ListField(db.EmbeddedDocumentField(OtpDetails))


# class UserOtpInfo(db.Document):
#     ID = db.ReferenceField("User")
#     otp = db.StringField()
#     otp_expiration_time = db.DateTimeField()
#     token = db.StringField()


# class Roles(db.Document):
#     """Model for Roles."""
#     Roles = db.ListField(db.StringField())

