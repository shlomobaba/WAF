import re
import riskLevel

def xml_detector(userRequest):
    if(re.search(re.compile(r""".*<?xml version=".*".*""",re.I),userRequest)):
        return True
    return False

def system_entity_detector(userRequest):
    if(re.search(re.compile(r""".*<!ENTITY .* SYSTEM.*""",re.I),userRequest)):
        return riskLevel.NO_RISK
    return riskLevel.LOW_RISK

def wesite_detector(userRequest):
    if(re.search(re.compile(r""".*SYSTEM.*http.*://.*""",re.I),userRequest)):
        return riskLevel.LOW_RISK
    return riskLevel.HIGH_RISK

def dos_detector(userRequest):
    number_of_occurrences = len(re.findall(""".*<!ENTITY.*>.*""", userRequest))
    if(number_of_occurrences > 7):
        return riskLevel.CRITICAL_RISK
    return riskLevel.NO_RISK
