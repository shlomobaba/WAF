import sqlDetector
import inspect
from urllib.parse import unquote
import base64
import chardet
import json
def checkRequestRisk(userRequest):
    userRequests=parseUserRequest(userRequest)
    totalRisk = 0
    sqlInjectionRisk = 0
    tempRiskList = []
    for i in dir(sqlDetector):
        item = getattr(sqlDetector, i)
        if callable(item):
            try:
                for req in userRequests:
                    tempRiskList += [item(req)]
                sqlInjectionRisk += max(tempRiskList)
                tempRiskList.clear()
            except:
                pass
    totalRisk = sqlInjectionRisk
    return totalRisk


def parseUserRequest(userRequests):
    decodedRequest=[]
    try:
        valuesInJson=json.loads(userRequests)
        valuesInJson=valuesInJson.values()
        userRequests=valuesInJson
        print(len(userRequests))
    except Exception as e:
        if userRequests is not list:
            userRequests=[userRequests]

    for userRequest in userRequests:
        userRequest=str(userRequest)
        base64Decode=isBase64(userRequest)
        if(base64Decode!=False and base64Decode is not None):
            userRequest=base64Decode
            decodedRequest+=[userRequest]
            decodedRequest+=[unquote(userRequest)]
            decodedRequest+=[unquote(unquote(userRequest))]
            decodedRequest += [ascii(userRequest)]
            decodedRequest += [unquote(ascii(userRequest))]

        else:
            decodedRequest+=[userRequest]
            decodedRequest += [unquote(userRequest)]
            decodedRequest += [unquote(unquote(userRequest))]
            decodedRequest += [ascii(userRequest)]
            base64DecodeTry = isBase64(unquote(userRequest))
            decodedRequest += [unquote(ascii(userRequest))]
            if (base64DecodeTry != False and base64DecodeTry is not None):
                decodedRequest += base64DecodeTry


    return decodedRequest

def isBase64(s):
    try:
        s += "=="
        decodedStr=base64.b64decode(s).decode()
        return decodedStr
    except Exception:
        return False