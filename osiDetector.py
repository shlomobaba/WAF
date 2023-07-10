import re
from riskLevel import riskLevel

def checkForOpenOsPrompt(userRequest):
    if (re.search(re.compile(r""".*(cmd|net|powershell|tftp|ftp).*""",re.I),userRequest)):
        return riskLevel.HIGH_RISK
    return riskLevel.NO_RISK
def checkForSuspicoiusLocation(userRequest):
    if (re.search(re.compile(r""".*(/bin/id|usr/bin).*""",re.I),userRequest)):
        return riskLevel.HIGH_RISK
    return riskLevel.NO_RISK

def checkForNameOfCurrentUser(userRequest):
    if (re.search(re.compile(r""".*\bwhoami\b.*""", re.I), userRequest)):
        return riskLevel.HIGH_RISK
    return riskLevel.NO_RISK

def checkForOsDetails(userRequest):
    if (re.search(re.compile(r""".*(\buname\b \b-a\b|\bver\b).*""", re.I), userRequest)):
        return riskLevel.HIGH_RISK
    return riskLevel.NO_RISK

def checkForNetworkDetails(userRequest):
    if (re.search(re.compile(r""".*(\bifconfig\b|\bipconfig\b).*""", re.I), userRequest)):
        return riskLevel.HIGH_RISK
    return riskLevel.NO_RISK

def checkForNetworkConnections(userRequest):
    if (re.search(re.compile(r""".*(\bnetstat\b).*""", re.I), userRequest)):
        return riskLevel.HIGH_RISK
    return riskLevel.NO_RISK

def checkForRunningProcesses(userRequest):
    if (re.search(re.compile(r""".*(ps -ef|tasklist).*""", re.I), userRequest)):
        return riskLevel.HIGH_RISK
    return riskLevel.NO_RISK

def suspicoiusCharcters(userRequest):
    if (re.search(re.compile(r""".*(>|&{1,2}|\|{1,2}).*""", re.I), userRequest)):
        return riskLevel.LOW_RISK
    return riskLevel.NO_RISK
def excuteNewUnixCommand(userRequest):
    if (re.search(re.compile(r""".*(Newline|;|0x0a|\n|`.*`|\$(.*)).*""", re.I), userRequest)):
        return riskLevel.LOW_RISK
    return riskLevel.NO_RISK
def lookForEcho(userRequest):
    if (re.search(re.compile(r""".*echo.*""", re.I), userRequest)):
        return riskLevel.MEDIUM_RISK
    return riskLevel.NO_RISK

def lookForFileRetrivalAttempt(userRequest):
    if (re.search(re.compile(r""".*wget.*""", re.I), userRequest)):
        if (re.search(re.compile(r""".*wget.*(http[s]?://.*|txt|php|htm|js)""", re.I), userRequest)):
            return riskLevel.CRITICAL_RISK
        return riskLevel.MEDIUM_RISK
    return riskLevel.NO_RISK

def checkForCmdEnvironmentVariablesChange(userRequest):
    if (re.search(re.compile(r""".*set.*""", re.I), userRequest)):
        return riskLevel.LOW_RISK
    return riskLevel.NO_RISK

def checkForUserDataRetrivalAttempt(userRequest):
    if (re.search(re.compile(r""".*getent.*""", re.I), userRequest)):
        return riskLevel.HIGH_RISK
    return riskLevel.NO_RISK