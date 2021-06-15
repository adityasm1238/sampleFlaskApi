from flask import Blueprint,request,jsonify
from flask_jwt_extended import get_jwt_identity,jwt_required
from app.error import handleErrors

from app.models import RegisterKeys, SyncData

user = Blueprint('user',__name__,url_prefix='/user')

@user.route('/getReferralKeys',methods=['POST'])
@jwt_required()
def getKeys():
    identity = get_jwt_identity()
    keys = RegisterKeys.objects(by=identity)
    res = [str(x.id) for x in keys]
    return jsonify(res),200

@user.route('/sync',methods=['POST'])
@handleErrors
@jwt_required()
def sync():
    identity = get_jwt_identity()
    data = request.get_json()
    syncArray = data['syncArray']
    syncItemsAdd = []
    syncItemsDelete = []
    for i in syncArray:
        if i['cmd'] == 'ADD':
            syncItemsAdd.append(SyncData(type=i['type'],url=i['url'],thumb=i['thumb'],title=i['title'],of=identity))
        else:
            syncItemsDelete.append(i['url'])
    urlToCheck = [x['url'] for x in syncItemsAdd]
    duplicates = SyncData.objects(of=identity,url__in=urlToCheck)
    if duplicates.count()!=0:
        dupUrls = []
        for i in duplicates:
            dupUrls.append(i.url)
        syncItemsAdd = list(filter(lambda x:x.url not in dupUrls,syncItemsAdd))
    if len(syncItemsAdd)!=0:
        SyncData.objects.insert(syncItemsAdd)
    if len(syncItemsDelete)!=0:
        SyncData.objects(of=identity,url__in=syncItemsDelete).delete()
    database = SyncData.objects(of=identity).limit(100)
    res = {}
    res['syncArray'] = database.exclude('id').exclude('of')
    if database.count()<100:
        res['next'] = None
    else:
        res['next'] = 100
    return res,200

@user.route('/getData/<start>')
@jwt_required()
def getData(start):
    start = int(start)
    identity = get_jwt_identity()
    database = SyncData.objects(of=identity).skip(start).limit(100)
    res = {}
    res['syncArray'] = database.exclude('id').exclude('of')
    if database.count()<100:
        res['next'] = None
    else:
        res['next'] = 100
    return res,200


    