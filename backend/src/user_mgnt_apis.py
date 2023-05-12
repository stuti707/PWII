import ast
import os
from random import randint

from flask import Blueprint, request, current_app
from flask import jsonify, session
from bson.json_util import dumps, loads
from csbt.src.util.models import *
import bson
import json
import jwt
import hashlib
from csbt.src.util.cache import cache_handler
from datetime import datetime, timedelta, timezone
import app
from csbt.src.util.token_handler import (token_required)
from csbt.src.util.email_notification import (send_forgot_password_link)
from mongoengine import NotUniqueError
from tzlocal import get_localzone
import pytz
import bcrypt

expiry_days = 90
user_management = Blueprint("user_management", __name__)
loginAttempts = {}
''' API's for USER MANAGEMENT '''


def get_current_time_zone_date():
    local_tz = get_localzone()
    return datetime.now(timezone.utc).astimezone(local_tz)


"""
    Input : User Object
    Output : status message(string)
    Description : Create user by storing user object
"""


@user_management.route('/user', methods=['POST'])
@token_required
def create_user():
    """Function to handle POST request to create User."""
    obj = request.get_json()
    # Adding the salt to password and hashing it
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(obj['password'].encode(), salt)

    # 'New User SignUp'
    try:
        user = User(email_id=obj['email_id'])
        print(obj['first_name'])
        print(obj)
        user.first_name = obj['first_name']
        user.last_name = obj['last_name']
        user.user_name = obj['user_name']
        user.role = obj['role']
        user.activation_flag = obj['activation_flag']
        user.save()

        user_auth = UserAuthInfo()
        user_auth.user_id = user
        user_auth.password = hashed
        old_passwords = OldPasswordsInfo()
        # old_passwords.One = hashed
        # old_passwords.Two = hashed
        old_passwords.One = None
        old_passwords.Two = None

        user_auth.last_passwords = old_passwords
        # user_auth.last_passwords['One'] = hashed
        # user_auth.last_passwords['Two'] = hashed
        user_auth.password_expiry_date = datetime.today().date() + timedelta(expiry_days)
        user_auth.save()

        # user_auth_logs = UserAuthLogs()
        # user_auth_logs.user_id = user
        # user_auth_logs.user_creation = datetime.today()
        # user_auth_logs.last_login = datetime.today()
        # user_auth_logs.login_status = "Successful"
        # user_auth_logs.save()

    except NotUniqueError as e:
        x = e.args[0]
        field = list(ast.literal_eval(x[ x.index("{", x.index("keyPattern")) : x.index("}", x.index("keyPattern")) + 1 ]).keys())[0]
        return f"duplicate {field}", 400

    # password_salt = bcrypt.gensalt()
    # date = get_current_time_zone_date()
    # obj['password'] = bcrypt.hashpw(obj['password'].encode("utf-8"), password_salt)
    # user_auth_obj = UserAuthInfo()
    # user_auth_obj.password_salt = password_salt.decode()
    # user_auth_obj.last_password_updated_date = date
    # user_auth_obj.last_passwords = [{"date":date, "password":obj['password']}]
    # user_auth_obj.save()
    # try:
    #     user_obj = User(**(obj))
    #     #user_obj.user_auth_info = user_auth_obj
    #     user_obj.save()
    # except NotUniqueError as e:
    #     x = e.args[0]
    #     field = list(ast.literal_eval(x[ x.index("{", x.index("keyPattern")) : x.index("}", x.index("keyPattern")) + 1 ]).keys())[0]
    #     return f"duplicate {field}", 400

    status_msg = "User created and saved successfully!"
    return (jsonify(status_msg))


"""
    Input: Upadated User Object
    Output: Status Message(String)
    Description: Updates User , Updates exiting record of user with updated user object
"""


@user_management.route('/user', methods=['PUT'])
@token_required
def update_user():
    """Function to handle PUT request to update User."""
    upd_obj = request.get_json()
    user_id = upd_obj['_id']['$oid']
    # User.objects.get(id=bson.objectid.ObjectId(
    #     upd_obj["_id"]["$oid"])).delete()
    upd_obj.pop('_id')
    upd_obj.pop("date_created")

    User.objects(id = bson.objectid.ObjectId(user_id)).update(**upd_obj)

    status_msg = "User Updated and saved successfully!"
    return (jsonify(status_msg))


"""
    Input : 
    Output : List of User
    Description : Return the list of user objects in database
"""


@user_management.route('/user-list', methods=['GET'])
@token_required
def user_list():
    """Function to handle GET request to get users list."""
    users_list = User.objects()
    return (users_list.to_json())


"""
    Input: Id(mongodb Id)
    Output: User Object matching id
    Description : returns the user object which have mongod id that matched with id comes with request
"""


@user_management.route('/get-user-by-id', methods=['GET'])
@token_required
def get_user_by_id():
    """Function to handle GET request to get a user by userId """
    user_obj_id = request.args.get('userid')
    user_obj = User.objects.get(id=bson.objectid.ObjectId(user_obj_id))
    return user_obj.to_json()


"""
    Input: User Name
    Output: User Object
    Description: returns the user object having username that matches with username comes wit request
"""


@user_management.route('/get-user-by-username', methods=['GET'])
@token_required
def get_user_by_username():
    """Function to handle GET request to get a user by userId """
    user_obj_id = request.args.get('username')
    print(user_obj_id);
    user_obj = User.objects(user_name=user_obj_id).only("user_name", "first_name", "last_name", "email_id")
    return user_obj.to_json()


"""
    Input: Id(Mongodb Id)
    Output: status message
    Description: Deletes the user from system by deleting record from database
"""


@user_management.route('/delete-user', methods=['PUT'])
@token_required
def delete_user_by_id():
    """Function to handle PUT request to delete a user by userId"""
    user_obj_id = request.args.get('userid')
    User.objects.get(id=bson.objectid.ObjectId(user_obj_id)).delete()
    status_msg = "User deleted successfully!"
    return (jsonify(status_msg))


"""
    Input: Id(MongodbID), new Status
    Output: status Message(string)
    Description: Updates the user status.
"""


@user_management.route('/set-user-status', methods=['PUT'])
@token_required
def set_user_status():
    """Function to handle PUT request to activate or de-activate a user"""
    user_obj_id = request.args.get('userid')
    activation_flag = request.args.get('activation_flag')
    User.objects.get(id=bson.objectid.ObjectId(user_obj_id)
                     ).update(activation_flag=activation_flag)
    return jsonify("Updated user's Status.")


"""
    Input: Id(MongodbId), 
"""


@user_management.route('/get-user-status', methods=['GET'])
@token_required
def get_user_status():
    """Function to handle GET request to get activation status of user."""
    user_obj_id = request.args.get('userid')
    activation_flag = request.args.get('activation_flag')
    if activation_flag == "Active":
        return jsonify("Active")
    else:
        return jsonify("Inactive")


@user_management.route("/delete-role/<role_name>", methods=['DELETE'])
@token_required
def delete_role(role_name):
    try:
        Roles.objects(role_name=role_name).delete();
    except:
        return jsonify("No such role exists"), 400

    return jsonify("deleted")


"""
    Input: Role 
    Output: status message(string)
    Description: Creates new role in system with default rights 
"""


@user_management.route('/create-role', methods=['POST'])
@token_required
def create_role():
    """Function to handle POST request to create a role and sync it with rights with some default rights set initially."""
    role = request.get_json()

    if Roles.objects(role_name=role['role_name']).count() == 0:

        admin_rights = Roles.objects().get(role_name='Admin').rights

        all_modules = list(admin_rights.to_mongo().keys())
        new_role_modules = role['rights'].keys()
        modules_not_added = [x for x in all_modules if x not in new_role_modules]

        for mod in modules_not_added:
            role['rights'][mod] = {}
            for right in admin_rights[mod].keys():
                role['rights'][mod][right] = 'N'

        singlerole = Roles(role_name=role['role_name'], rights=role['rights'])
        singlerole.save()
        return jsonify("Role Added Successfully")
    else:
        return jsonify("Role already exists!")


"""
    Input:
    Output: List of roles
    Description: Return list of roles in system
"""


@user_management.route('/get-roles', methods=['GET'])
@token_required
def get_roles_list():
    """Function to handle GET request to get Roles list."""

    roles = Roles.objects.filter().values_list('role_name')
    return json.dumps(loads(dumps(roles)))
    # earlier_roles = Roles.objects()
    # earlier_roles_ = earlier_roles[0].Roles
    # return json.dumps(earlier_roles_)


"""
    Input:  updated rights object
    Output: status message(string)
    Description: updates right object in database by replacing it with updated object
"""


@user_management.route('/rights', methods=['PUT'])
@token_required
def update_rights():
    """Function to handle PUT request to update Rights."""
    upd_obj = request.get_json()
    Roles.objects.get(id=bson.objectid.ObjectId(
        upd_obj["_id"]["$oid"])).update(set__rights=upd_obj['rights'])
    # upd_obj.pop('_id')
    # upd_obj_ = Pages(**upd_obj)
    # upd_obj_.save()
    status_msg = "Roles and Rights Updated and saved successfully!"
    return (jsonify(status_msg))


def get_subscribed_modules():
    modules = []
    with open("./csbt/resources/subscribed_modules.json", 'r') as f:
        s_data = loads(f.read())
    modules = [key for key, value in s_data.items() if value == 'Y']
    # modules = s_data.keys()
    modules = modules + ['study', "user_management"]
    return list(modules)


"""
    Input: username
    Output: list of rights
    Description: checks the roles of the user and return list of rights 
                    according to roles of the user
"""


@user_management.route('/get-rights', methods=['GET'])
@token_required
def get_rights_list():
    """Function to handle GET request to get Rights."""
    username = request.args.get('username')
    modules = get_subscribed_modules()

    print(modules)
    pipeline = [{"$match": {"user_name": username}},
                {"$lookup": {"from": "roles", "localField": "role", "foreignField": "role_name", "as": "rights"}},
                {"$project": {"role": 1, "rights.rights": 1}}]
    rights = loads(dumps(User.objects.aggregate(pipeline)))
    if rights:
        rights = rights[0]
    else:
        return "No User Found", 401
    # page_obj = Pages.objects()[0]
    userRights = {}
    # roles = rights['role']

    user_rsrs = []
    is_ecrf_subscribed = 'eCRF' in modules;
    for mod in modules:
        userRights[mod] = []
        user_rsrs = [r['rights'][mod] for r in rights['rights']]
        tmp = []
        for obj in user_rsrs:
            tmp = tmp + [key for key, value in obj.items() if value == 'Y']
        userRights[mod] = list(set(tmp))

    if not is_ecrf_subscribed:
        
        userRights['eCRF'] = list(rights['rights'][0]['rights']['eCRF'].keys())
        userRights['eCRF'].remove('create_ecrf')
    #user_rsrs = [r for f in rights['rights']]
    # import pdb;
    # pdb.set_trace()
    # keys = rights['rights']
    # rights = rights['rights']
    # for right in rights:
    #     for key in keys:
    #         if right['rights'][key] == 'Y' and key not in userRights:
    #             userRights.append(key)

    return json.dumps(userRights)
    # return json.dumps(eval(page_obj.to_json()))


@user_management.route('/role-right/<role_name>', methods=['GET'])
def get_role_right(role_name):
    rights = Roles.objects(role_name=role_name)
    return json.dumps(eval(rights.to_json()))


@user_management.route('/rights-obj', methods=['GET'])
def rights_obj():
    rights = Roles.objects()
    return json.dumps(eval(rights.to_json()))


'''
    Input : User Email Id
    Output : boolean value 
    Description: Verifies if the email present the database or not.returns true if present else not.
'''


def is_email_present(email):
    """ Function to check if email-id is present in the database."""
    all_users = User.objects()
    if len(all_users) > 0:
        all_emailids = [x.email_id for x in all_users]
        if email in all_emailids:
            return True
        else:
            return False
    else:
        return False


'''
    Input : email Id
    Output : email ID, token
    Description : Validates OTP
'''


@user_management.route('/otp-validation', methods=['POST'])
def otp_validation():
    obj = request.get_json()
    email = obj['email']
    otp = obj['otp']
    print("obj: ", obj)

    user = User.objects.get(email_id=email)
    username = user.user_name
    refID = user.id

    current_time = datetime.now()

    # retrieve the latest 'otp_info' document for the user
    user_otp_info = UserOtpInfo.objects(ID=refID).order_by('-otp_info.otp_expiration_time').first()
    # user_otp_info = UserOtpInfo1.objects(ID=refID)
    # user_otp_info = UserOtpInfo1.objects.get(ID=refID).order_by('-otp_info.otp_expiration_time').first()

    # retrieve the latest 'otp_expiration_time' for the user
    latest_otp_expiration_time = user_otp_info.otp_info[-1].otp_expiration_time

    # check if the latest OTP has expired
    if latest_otp_expiration_time <= current_time:
        return jsonify("Token Expired"), 401
    else:
        if otp == user_otp_info.otp_info[-1].otp:
            print('success')
            token = user_otp_info.otp_info[-1].token
            return jsonify({'username': username, 'token': token})
        else:
            return (jsonify("Incorrect OTP")), 401

    # user_otp_info = UserOtpInfo1.objects(ID=refID).order_by('-otp_info.otp_expiration_time').first()
    # user_otp_info = UserOtpInfo1.objects.get(ID=refID)
    # print(user_otp_info.otp_info)
    #
    # for obj in user_otp_info.otp_info:
    #     for otps in obj:
    #         print(otps)
    #     print(type(obj))
    # print(user_otp_info)
    # # latest_otp = user_otp_info.otp_info.otp
    #
    # # token = user_otp_info.otp_info.token
    # print('otp generated: ', user_otp_info.otp_info.otp)
    # print('otp received: ', otp)
    #
    # if user_otp_info.otp_info.otp_expiration_time <= current_time:
    #     print("TimeUp")
    #     return jsonify("Token Expired")
    # else:
    #     if otp == user_otp_info.otp_info.otp:
    #         print('success')
    #         return jsonify("validation Successful")
    #         # return jsonify({'username': username, 'token': token})
    #     else:
    #         return jsonify("Incorrect otp")


'''
    Input : email Id
    Output : success message
    Description : Sends email with reset password link or OTP to the mail id received with request
                    token is also sent with link which holds validity of link
'''


@user_management.route('/forgot-passwd', methods=['POST'])
def forgot_passwd():
    """Function to handle POST request to reset password with email authentication."""
    obj = request.get_json()
    print(obj)
    email = obj['email']
    source = obj['function_called']
    email_flag = is_email_present(email)
    if email_flag == True:

        user = User.objects.get(email_id=email)
        refID = user.id
        user_auth = UserAuthInfo.objects.get(user_id=refID)
        password_str = user_auth.password.decode()

        payload = {
            "user_name": user.user_name,
            "exp": datetime.utcnow() + timedelta(minutes=5)
        }
        key_value = user.user_name.encode("utf-8") + password_str.encode("utf-8")
        SECRET_KEY = hashlib.md5(key_value).hexdigest()

        reset_token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")

        if source == "Reset Password":
            res = send_forgot_password_link(email, user.user_name, token=reset_token)

        if source == "Forgot Password":
            otp = str(randint(100000, 999999))  # Generates 6 Digit OTP
            expiration_time = datetime.now() + timedelta(minutes=5)

            try:
                user_otp_info = UserOtpInfo.objects.get(ID=refID)

            except db.DoesNotExist:
                user_otp_info = UserOtpInfo()
                user_otp_info.ID = user
            otp_details = OtpDetails(otp=otp, otp_expiration_time=expiration_time, token=reset_token)
            user_otp_info.otp_info.append(otp_details)
            user_otp_info.save()

            res = send_forgot_password_link(email, user.user_name, otp=otp)

        if res == 'Success':
            # server = smtplib.SMTP(
            #     current_app.config["MAIL_SERVER"], current_app.config["MAIL_PORT"])
            # server.ehlo()
            # server.starttls()
            # server.login(current_app.config["MAIL_USERNAME"],
            #              current_app.config["MAIL_PASSWORD"])
            # msg = MIMEMultipart()
            # msg['From'] = current_app.config["MAIL_USERNAME"]
            # msg['To'] = email
            # msg['subject'] = "password Reset"
            # email_body = "<h2>Greetings from Fresh Gravity</h2><br><p><a href='http://localho         st:4200/#/reset/" + \
            # reset_token.decode(
            #         'utf-8')+"'>click here</a> To reset your password.</p><p>If that link didnt worked then please contact admin</p>"
            # msg.attach(MIMEText(email_body, 'html'))
            # text = msg.as_string()
            # server.sendmail(current_app.config["MAIL_USERNAME"], email, text)
            # server.quit()
            return (jsonify("EMAIL SENT SUCCESSFULLY!"))
        else:
            return jsonify("Failed to send Email")
    else:
        return (jsonify("Email Not Present.")), 401


@user_management.route('/validate-reset-password-token', methods=['POST'])
def validate_reset_password_token():
    obj = request.get_json()
    reset_token = obj['reset_token']
    user_name = obj['user_name']
    user = User.objects.get(user_name=user_name)
    refID = user.id
    user_auth = UserAuthInfo.objects.get(user_id=refID)
    password_str = user_auth.password.decode()

    key_value = user.user_name.encode("utf-8") + password_str.encode("utf-8")
    SECRET_KEY = hashlib.md5(key_value).hexdigest()
    try:
        payload = jwt.decode(reset_token, SECRET_KEY, algorithms="HS256")
        return jsonify("Token Valid"), 200

    except Exception as e:
        print(e)
        return jsonify("Invalid Token"), 400


"""
    Input: New password, token
    Output: status message
    Description: updates password in system, token - to verify validity of reset link.
"""


@user_management.route('/reset', methods=['POST'])
def reset_passwd():
    """Function to handle POST request to reset the password."""
    data = request.get_json()
    print(data)
    reset_token = data['token']
    user_name = data['user_name']
    new_password = data["password"]
    user = User.objects.get(user_name=user_name)
    refID = user.id
    user_auth = UserAuthInfo.objects.get(user_id=refID)
    today = datetime.today()
    if bcrypt.checkpw(new_password.encode(), user_auth.password):
        print("Password shouldn't match last 3 password")
        return jsonify("SAME_AS_OLD_PASSWORD"), 400
    elif user_auth.last_passwords.One is not None:
        if bcrypt.checkpw(new_password.encode(), user_auth.last_passwords.One):
            print("Password shouldn't match last 3 password")
            return jsonify("SAME_AS_OLD_PASSWORD"), 400
        elif user_auth.last_passwords.Two is not None:
            if bcrypt.checkpw(new_password.encode(), user_auth.last_passwords.Two):
                print("Password shouldn't match last 3 password")
                return jsonify("SAME_AS_OLD_PASSWORD"), 400

    password_str = user_auth.password.decode()
    key_value = user_name.encode("utf-8") + password_str.encode("utf-8")
    SECRET_KEY = hashlib.md5(key_value).hexdigest()
    try:
        print("inside try block!!!!!!")
        payload = jwt.decode(reset_token, SECRET_KEY, algorithms="HS256")
        print('Token is still valid')
        expiry_date = today + timedelta(expiry_days)
        salt = bcrypt.gensalt()
        new_hashed = bcrypt.hashpw(new_password.encode(), salt)
        pass_two = user_auth.last_passwords.One
        pass_one = user_auth.password

        fields = {
            'password': new_hashed,
            'last_passwords': {
                'One': pass_one,
                'Two': pass_two
            },
            'password_expiry_date': expiry_date
        }
        user_auth.update(**fields)
        return json.dumps("Password updated successfully!")

    except Exception as e:
        print("runnnnn!!! ", e)
        return "URL Expired", 400

    # if(bcrypt.checkpw(new_password.encode(), user_auth.password) or
    #         bcrypt.checkpw(new_password.encode(), user_auth.last_passwords[0].One) or
    #         bcrypt.checkpw(new_password.encode(), user_auth.last_passwords[0].Two)):
    #     print("Password shouldn't match last 3 password")
    #     return jsonify("SAME_AS_OLD_PASSWORD"), 400

    # if new_password == user.password:
    #     return "SAME_AS_OLD_PASSWORD", 400
    #
    # key_value = user.user_name.encode("utf-8") + user.password.encode("utf-8")
    # SECRET_KEY = hashlib.md5(key_value).hexdigest()
    #
    # try:
    #     payload = jwt.decode(reset_token, SECRET_KEY, algorithms="HS256")
    #     User.objects.get(user_name=user_name).update(
    #         password=new_password)
    #
    # except Exception as e:
    #     print(e)
    #     return "URL Expired", 400
    # return json.dumps("Password updated successfully!")


"""
    Input: Uid(username),pwd(password)
    Output: boolean
    Description: checks if userid and password in valid
"""


def is_user_valid(uid, pwd):
    """ Function to check if user is valid or not. """

    if User.objects(user_name=uid).count() == 0:
        return 'No User Found'
    user = User.objects.get(user_name=uid)
    refID = user.id
    user_auth = UserAuthInfo.objects.get(user_id=refID)

    if user.activation_flag == 'InActive':
        return 'Account Blocked'

    if bcrypt.checkpw(pwd.encode(), user_auth.password):
        return True


"""
    Input: Username, Number of minutes
    Output: Auth Token
    Description: Create new auth token which valid for minutes sent as argument.
                 username is encoded in authtoken
"""


def create_token(username, minute):
    token = jwt.encode({
        'public_id': username,
        'exp': datetime.utcnow() + timedelta(minutes=minute)
    }, current_app.config['SECRET_KEY'], algorithm="HS256")

    return token


"""
    Input : Refresh Token, username
    Output : New Auth Token
    Description: checks if refresh token is valid,if valid then returns to auth token
"""


@user_management.route('/refresh-token', methods=['POST'])
def refresh_auth_token():
    refresh_token = request.form['refresh_token']
    username = request.form['username']

    try:
        data = jwt.decode(refresh_token, current_app.config['SECRET_KEY'], algorithms="HS256")
        resp = {}
        resp['auth_token'] = create_token(username, 1)

        if UserSessionTimeout.objects(refresh_token = refresh_token).count() != 0:

            fields = {
                "refresh_token":refresh_token,
                "user_name":username,
                'auth_token': resp['auth_token'],
                'last_activity': datetime.now()
            }
            user_session_timeout = UserSessionTimeout(**fields)
            user_session_timeout.save()

        return json.dumps(resp)
    except Exception as e:
        print(e)
        print("Refresh Token is invalid")
        return jsonify({"Message": "Refresh Token is Invalid"}), 401


"""
    Input :  username
    Output : Boolean
    Description: checks if password has expired, if expired False
"""


# @user_management.route('/reset', methods=['POST'])
def password_expiry(username):
    user = User.objects.get(user_name=username)
    refID = user.id
    user_auth = UserAuthInfo.objects.get(user_id=refID)
    today = datetime.today()
    if user_auth.password_expiry_date.date() <= today.date():
        return False
    # rp_flag = reset_passwd()
    # return rp_flag
    else:
        return True


"""
    Input : Username, Password
    Output: json object containing auth_token,refresh_token,roles
    Descrition: validates username and password, if valid returns json object as output
"""


@user_management.route('/login', methods=['POST'])
def login_user():
    """ Function to handle POST request to do login with username and password."""

    data = request.get_json()
    username = data["username"]
    password = data["password"]
    valid_user_flag = is_user_valid(username, password)

    if valid_user_flag == 'No User Found':
        return jsonify('No User Found'), 401
    elif valid_user_flag == 'Account Blocked':
        return jsonify('Account Blocked'), 401
    user_obj = User.objects().get(user_name=username)
    if valid_user_flag:
        password_expiry_flag = password_expiry(username)
        if password_expiry_flag:
            data = {}
            token = create_token(username, 1)
            data['auth_token'] = token
            data['refresh_token'] = create_token(username, 1000)
            data['roles'] = user_obj.role
            if username in loginAttempts.keys():
                del loginAttempts[username]
            with open("./csbt/resources/subscribed_modules.json", 'r') as f:
                user = User.objects.get(user_name=username)

                # if UserSessionTimeout.objects(user_name=username).count() != 0:
                #     user_session_timeout = UserSessionTimeout.objects.get(user_name=username)
                #     fields = {
                #         'token': data['auth_token'],
                #         'last_activity': datetime.now()
                #     }
                #     user_session_timeout.update(**fields)
                # else:
                user_session_timeout = UserSessionTimeout()
                # user_session_timeout.ID = user
                user_session_timeout.refresh_token = data['refresh_token']
                user_session_timeout.auth_token = data['auth_token']
                user_session_timeout.user_name = username
                user_session_timeout.last_activity = datetime.now()
                user_session_timeout.token = data['auth_token']
                user_session_timeout.save()

                # user_auth_logs = UserAuthLogs.objects.get(user_name=username)
                # fields = {
                #     'last_login': datetime.today(),
                #     'login_status': 'Successful'
                # }
                # user_auth_logs.update(**fields)
                s_data = loads(f.read())
            data['s_data'] = s_data
            return json.dumps(data)

        elif not password_expiry_flag:
            return jsonify('Password Expired'), 401
    else:
        # user = User.objects.get(user_name=username)
        # refID = user.id

        # user_auth_logs = UserAuthLogs.objects.get(ID = refID)
        # fields = {
        #     'last_login': datetime.today(),
        #     'login_status': 'UnSuccessful'
        # }
        # user_auth_logs.update(**fields)

        if username in loginAttempts.keys():
            loginAttempts[username] = loginAttempts[username] + 1
            if loginAttempts[username] >= 3:
                User.objects.get(user_name=username).update(set__activation_flag='InActive')
                return jsonify("Account Blocked"), 401
        else:
            loginAttempts[username] = 1
        return jsonify("Invalid Credentials! " + str(3 - loginAttempts[username]) + " Attempts Left"), 401


"""
    Input: 
    Output: Status Message(String)
    Description: Saves the system feedback object in database
"""


@user_management.route('/system-feedback', methods=['POST'])
@token_required
def system_feedback():
    data = request.get_json()
    data['date'] = datetime.now().strftime("%I:%M%p on %B %d, %Y")
    obj = SystemFeedback(**data)
    obj.save()

    return jsonify("Saved Successfully!")


@user_management.route("/setup-system", methods=['GET'])
def setup_sysetm():
    dir_path = "./csbt/resources/database_collections/"
    for file in os.listdir(dir_path):
        coll_name = file.split(".")[0]
        insert_data = []
        with open(dir_path + file) as f:
            data = loads(f.read())
        print(file)
