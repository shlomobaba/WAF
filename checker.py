import sqlDetector
import xxe_detector
import inspect
from urllib.parse import unquote
import base64
import json
import re
import xssDetector
import xssAICheck
from riskLevel import riskLevel
import string
import os
import codecs
import osiDetector
import osAICheck
RE_BASE64 = "^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?$"
def checkRequestRisk(userRequest):
    userRequests=parseUserRequest(userRequest)
    totalRisk = 0
    sqlInjectionRisk = 0
    xssRisk=0
    tempRiskList = []
    for i in dir(sqlDetector):
        item = getattr(sqlDetector, i)
        if callable(item):
            try:
                for req in userRequests:
                    try:
                        tempRiskList += [item(req)]
                    except Exception:
                        continue
                sqlInjectionRisk += max(tempRiskList)
                tempRiskList.clear()
            except Exception as e:
                continue
    j=0
    allSuspectedXSSAttack=[0]*len(userRequests)
    for i in dir(xssDetector):
        item = getattr(xssDetector, i)
        if callable(item):
            try:
                for req in userRequests:
                    try:
                        suspectedRisk=[item(req)]
                        tempRiskList += suspectedRisk
                        allSuspectedXSSAttack[j]+=suspectedRisk
                    except:
                        continue
                j+=1
                xssRisk += max(tempRiskList)
                tempRiskList.clear()
            except:
                continue
        j=0
    if(xssRisk>2):
        indexed_numbers = list(enumerate(allSuspectedXSSAttack))
        sorted_numbers = sorted(indexed_numbers, key=lambda x: x[1], reverse=True)
        index1 = sorted_numbers[0][0]
        index2 = sorted_numbers[1][0]
    try:
            if(xssAICheck.checkForXSS(userRequests[index1]) or xssAICheck.checkForXSS(userRequests[index2])):
                    xssRisk+=riskLevel.HIGH_RISK
    except:
        pass
    osiRisk=0
    j = 0
    allSuspectedOSIAttack = [0] * len(userRequests)
    for i in dir(osiDetector):
        item = getattr(osiDetector, i)
        if callable(item):
            try:
                for req in userRequests:
                    try:
                        suspectedRisk = [item(req)]
                        tempRiskList += suspectedRisk
                        allSuspectedOSIAttack[j]+=suspectedRisk
                        j+=1
                    except Exception:
                        continue
                osiRisk += max(tempRiskList)
                tempRiskList.clear()
            except Exception as e:
                continue
        j=0
    if (osiRisk >= 3):
        indexed_numbers = list(enumerate(allSuspectedOSIAttack))
        sorted_numbers = sorted(indexed_numbers, key=lambda x: x[1], reverse=True)
        index1 = sorted_numbers[0][0]
        index2 = sorted_numbers[1][0]
    try:
        if (osAICheck.checkForOsInjection(userRequests[index1]) or osAICheck.checkForOsInjection(userRequests[index2])):
            osiRisk += riskLevel.HIGH_RISK
    except:
        pass
    totalRisk = max(sqlInjectionRisk, xssRisk,osiRisk)
    return totalRisk


def parseUserRequest(userRequests):
    decodedRequest=[]
    try:
        valuesInJson=json.loads(userRequests)
        valuesInJson=valuesInJson.values()
        userRequests=valuesInJson
    except Exception as e:
        if isinstance(userRequests, list)==False:
            userRequests=[userRequests]

    for userRequest in userRequests:
        userRequest=str(userRequest)
        decodedRequest+=[userRequest]
        unquotedStr=unquote(userRequest)
        decodedRequest+=[unquotedStr]
        decodedRequest += [codecs.decode(unquotedStr, 'unicode_escape')]
        decodedRequest+=[unquote(unquote(userRequest))]
        decodedRequest += [ascii(userRequest)[1:-1]]
        decodedRequest += [unquote(ascii(userRequest))[1:-1]]
        base64Decoded=isBase64(userRequest)
        if (base64Decoded!=userRequest):
            decodedRequest+=[base64Decoded]
            unquotedStr2=unquote(base64Decoded)
            decodedRequest += [unquotedStr2]
            decodedRequest += [codecs.decode(unquotedStr, 'unicode_escape')]
            decodedRequest += [unquote(unquote(base64Decoded))]
            decodedRequest += [ascii(base64Decoded)[1:-1]]
            decodedRequest += [isBase64(unquote(base64Decoded))]
            decodedRequest += [unquote(ascii(base64Decoded))[1:-1]]


    return decodedRequest

def isBase64(s):
    if(len(s)>2 and s[:-2]):
        s+="=="
    if s is None or not re.search(RE_BASE64, s):
        try:
            return base64.b64decode(s).decode()
        except:
            return s
    else:
        try:
            return base64.b64decode(s).decode()
        except:
            return base64.b64decode(s)
