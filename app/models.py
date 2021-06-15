

from app import db

class Users(db.Document):
    username = db.StringField(required=True,unique=True)
    password = db.StringField(required=True)
    referredBy = db.ReferenceField('RegisterKeys')

class RegisterKeys(db.Document):
    by = db.ReferenceField('Users',required=True)

class SyncData(db.Document):
    of = db.ReferenceField('Users',required=True)
    url = db.StringField(required = True,unique_with='of')
    thumb = db.StringField(required = True)
    title = db.StringField()
    type = db.StringField(required=True)


