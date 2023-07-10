import re
from riskLevel import riskLevel

def script_regex(userRequest):
    if(re.search(re.compile(r"""<script>|</script>""",re.I),userRequest)):
        return riskLevel.MEDIUM_RISK
    return riskLevel.NO_RISK

def  on_action(userRequest):
    if(re.search(re.compile(r"""javascript:|on\w*=""",re.I),userRequest)):
        return riskLevel.HIGH_RISK
    if (re.search(re.compile(r"""on\w*=""", re.I), userRequest)):
        return riskLevel.LOW_RISK
    return riskLevel.NO_RISK
def popUp_regex(userRequest):
    if(re.search(re.compile(r"""\b(alert|confirm|prompt)\b\s*\(""",re.I),userRequest)):
        return riskLevel.MEDIUM_RISK
    return riskLevel.NO_RISK
def constructor_regex(userRequest):
    if(re.search(re.compile(r"""\bconstructor\b""",re.I),userRequest)):
        return riskLevel.LOW_RISK
    return riskLevel.NO_RISK
def cookie_steal(userRequest):
    if re.search(re.compile(r"""\bdocument\b.*\bcookie\b""",re.I), userRequest):
        return riskLevel.HIGH_RISK
    elif re.search(re.compile(r"""\bdocument\b""",re.I),userRequest):
        return riskLevel.MEDIUM_RISK
    return riskLevel.NO_RISK

def eval(userRequest):
    if re.search(re.compile(r"""\beval\b\s*\([^\)]+?\)""",re.I), userRequest):
        return riskLevel.HIGH_RISK
    return riskLevel.NO_RISK

def img_src(userRequest):
    if re.search(re.compile(r"""(?:<|%3c)\s*img(?:/|\s).*?(?:src|dnysrc|lowsrc)\s*=""",re.I), userRequest):
        return riskLevel.MEDIUM_RISK
    return riskLevel.NO_RISK

def hash_location(userRequest):
    if re.search(re.compile(r"""\blocation\b.*?\..*?\bhash\b""",re.I), userRequest):
        return riskLevel.HIGH_RISK
    return riskLevel.NO_RISK

def document_cookie(userRequest):
    if re.search(re.compile(r"""\bdocument\b.*\bcookie\b""",re.I), userRequest):
        return riskLevel.HIGH_RISK
    return riskLevel.NO_RISK

def find_link(userRequest):
    totalRiskLevel=riskLevel.NO_RISK
    if re.search(re.compile(r"""\bhref\b""", re.I), userRequest):
        totalRiskLevel=riskLevel.LOW_RISK
    if re.search(re.compile(r"""(\bbase\b|\ba\b).?\bhref\b""",re.I), userRequest):
       totalRiskLevel=riskLevel.MEDIUM_RISK
    if re.search(re.compile(r"""(\bbase\b|\ba\b).?\bhref\b.*[\/\\]{2}""", re.I), userRequest):
        totalRiskLevel = riskLevel.HIGH_RISK
    return totalRiskLevel

def iframe_check(userRequest):
    if re.search(re.compile(r"""\biframe\b""", re.I), userRequest):
        if re.search(re.compile(r"""\biframe\b.?\bsrc=\b""", re.I), userRequest):
            return riskLevel.HIGH_RISK
        return riskLevel.MEDIUM_RISK
    return riskLevel.NO_RISK



