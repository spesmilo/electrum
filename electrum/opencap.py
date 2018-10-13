import re

def validateUsername(username):
    username = username.lower()
    return username, bool(re.match(r"^[a-z0-9._-]{1,25}$", username))


def validateDomain(domain):
    return bool(re.match(r"^[a-z0-9.\-]+\.[a-z]{2,4}$", domain))


def validateAlias(alias):
    parts = alias.split("$")
    if len(parts) != 2:
        return "", ""

    username = parts[0]
    domain = parts[1]

    username, valid = validateUsername(username)
    if not valid:
        return "", ""

    if not validateDomain(domain):
        return "", ""

    return username, domain