from flask import Blueprint,request
from flask_bcrypt import Bcrypt
from flask_jwt_extended import create_access_token,create_refresh_token,get_jwt_identity,jwt_required
from datetime import timedelta
from mongoengine.errors import ValidationError

from app.error import  handleErrors,AppError
from app.models import  Users,RegisterKeys


auth = Blueprint('auth',__name__,url_prefix='/auth')

bcrypt = Bcrypt()


@auth.route('/signup',methods=['POST'])
@handleErrors
def signup():
    data = request.get_json()

    username = data['username']
    password = data['password']
    referralkey = data['referralKey']

    if len(password)<8:
        return AppError.badRequest('Password must have length greater than or equal to 8')

    password = bcrypt.generate_password_hash(password)  #Generates Hash of Password for Security
    try:
        checkKey = RegisterKeys.objects(id=referralkey).first()
        if checkKey == None:
            return AppError.conflict('Referral Key is Invalid')
    except ValidationError:
        return AppError.conflict('Referral Key is Invalid')
    newUser = Users(username=username,password=password,referredBy=checkKey.by.id)
    newUser.save()

    #Ignore this section (Referral Code Generation)
    checkKey.delete()
    keys = []
    for _ in range(3):
        keys.append(RegisterKeys(by=newUser.id))
    RegisterKeys.objects.insert(keys)
  
    return {'userId':str(newUser.id),
    'username':username},200

@auth.route('/signin',methods=['POST'])
@handleErrors
def signin():
    data = request.get_json()
    username = data['username']
    password = data['password']
    user = Users.objects(username=username).first()
    if user == None:
        return AppError.error("Username does not exists.")
    if not bcrypt.check_password_hash(user.password,password):
        return AppError.error("Invalid Password.")
    res = {}
    res['username'] = username
    res['accessToken'] = create_access_token(str(user.id),expires_delta=timedelta(days=1))
    res['refreshToken'] = create_refresh_token(str(user.id))
    return res,200

@auth.route('/refresh',methods=['POST'])
@jwt_required(refresh=True)   # To check if Refresh Token is Valid or Not
def refresh():
    identity = get_jwt_identity()
    res = {}
    res['accessToken'] = create_access_token(identity)
    return res,200