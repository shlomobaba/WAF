import re
import sqlite_database
from riskLevel import riskLevel
def get_table_name_and_col_names(query):
    re_col_names = re.compile('SELECT (.*) FROM',flags=re.I)
    re_table_name = re.compile('FROM (\w*)',flags=re.I)
    col_names = re_col_names.findall(string = query)[0].split(',')
    table_name = re_table_name.findall(string = query)[0]
    return table_name,col_names


def checkForSelect(userRequest):
    if(re.search(re.compile(r""".*\bSELECT\b.+""",re.I),userRequest)):
        if(re.search(re.compile(r""".*\bSELECT\b.+\bFROM\b.+""",re.I),userRequest)):
            sql_values = get_table_name_and_col_names(userRequest)
            if(sqlite_database.DataBase().demo_table_check(sql_values.first(),sql_values.second())):
                return riskLevel.CRITICAL_RISK
            else:
                return riskLevel.MEDIUM_RISK
            return riskLevel.HIGH_RISK
        return riskLevel.MEDIUM_RISK
    return riskLevel.NO_RISK


def checkForOr(userRequest):
    if(re.search(re.compile(r""".*\bOR\b.*""",re.I),userRequest)):
        sql_values = get_table_name_and_col_names(userRequest)
        if(sqlite_database.DataBase().demo_table_check(sql_values.first(),sql_values.second())):
            return riskLevel.MEDIUM_RISK
        else:
            return riskLevel.NO_RISK
        return riskLevel.LOW_RISK
    return riskLevel.NO_RISK

def checkForSuspiciousCharacters(userRequest):
    risk=0
    if (re.search(re.compile(r""".*--.*""", re.I), userRequest)):
        risk+=riskLevel.LOW_RISK
    if (re.search(re.compile(r""".*'.*""", re.I), userRequest)):
        risk += riskLevel.LOW_RISK
        if (re.search(re.compile(r""".*".*""", re.I), userRequest)):
            risk += riskLevel.LOW_RISK
    return risk

def checkForTrueArgument(userRequest):
    if (re.search(re.compile(r"""\d+[.]?\d*=\d+[.]?\d*""", re.I), userRequest)):
        matches=re.findall(re.compile(r"""\d+[.]?\d*=\d+[.]?\d*""", re.I), userRequest)
        for match in matches:
            equalsIndex=str(match).find("=")
            if(str(match)[:equalsIndex]==str(match)[equalsIndex+1:]):
                return riskLevel.HIGH_RISK
    return riskLevel.NO_RISK
def checkForUnion(userRequest):
    if (re.search(re.compile(r""".*(\bunion\b | \bunion\b \ball\b) select""", re.I), userRequest)):
        injection = userRequest.replace("union ","")

        return riskLevel.CRITICAL_RISK
    return riskLevel.NO_RISK

def checkForDealy(userRequest):
    if (re.search(re.compile(r""".* \bwaitfor\b \bdelay\b \d{2}:\d{2}.*""", re.I), userRequest)):
        return riskLevel.HIGH_RISK
    return riskLevel.NO_RISK
def checkForSleep(userRequest):
    if (re.search(re.compile(r""".* \bpg_sleep(.*\d+)\b.*""", re.I), userRequest)):
        return riskLevel.HIGH_RISK
    return riskLevel.NO_RISK
