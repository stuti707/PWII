from flask import current_app
from functools import wraps
from flask.globals import request
from flask.json import jsonify
import jwt
from datetime import datetime, timedelta
import hashlib
import os

from csbt.src.util.models import *

SESSION_TIMEOUT = 1800   # 30 minutes into seconds
endpoints_not_to_check = ["forgot-passwd", "reset", "refresh-token", "login"]


def session_timeout(token):

    if UserSessionTimeout.objects(auth_token=token).count() != 0:
        user_session = UserSessionTimeout.objects.get(auth_token=token)
        last_activity = user_session.last_activity
        print('******************************', last_activity, '****************************')
        if last_activity is not None and (datetime.now() - last_activity) > timedelta(seconds=SESSION_TIMEOUT):
            # User has been inactive for too long - log them out
            UserSessionTimeout.objects.get(auth_token=token).delete()
            # decoded_token = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms="HS256")
            # print(decoded_token)
            # decoded_token_jti = decoded_token['jti']
            # revoked_tokens.add(decoded_token_jti)

            return True
        fields = {
            'last_activity': datetime.now()
        }
        user_session.update(**fields)
        return False


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if request.path.split("/")[1] in endpoints_not_to_check:
            return f(*args, *kwargs)

        try:
            if 'Authorization' in request.headers:
                token = request.headers['Authorization'].split('Bearer ')[1]
                if session_timeout(token):
                    return jsonify("SESSION EXPIRED"), 440
                else:
                    data = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms="HS256")
                    print("Token Valid")
        except Exception as e:
            print("Token not found", e)
            return jsonify({"Message": "Token is Invalid"}), 401
        return f(*args, **kwargs)

    return decorated
