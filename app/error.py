from functools import wraps
from flask import request
from mongoengine.errors import NotUniqueError

def handleErrors(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.get_json() is None:
            return AppError.badRequest("No Json Data Sent")
        try:
            res = f(*args, **kwargs)
            return res
        except KeyError as e:
            return AppError.badRequest('Key not found: '+str(e.args[0]))
        except NotUniqueError as e:
            return AppError.conflict('Value Already exists')
    return decorated_function

class AppError:
    @classmethod
    def error(cls,msg,code=500):
        return cls.throwerror(msg,code)

    @classmethod
    def badRequest(cls,msg,code=400):
        return cls.throwerror(msg,code)

    @classmethod
    def conflict(cls,msg,code=409):
        return cls.throwerror(msg,code)

    @classmethod
    def throwerror(cls,msg,code):
        return ({
            'error':msg,
            'code':code
        },code)
