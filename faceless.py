#!/usr/bin/python3
import argparse
import os
import random
import re
import string
import sys
from shutil import copyfile

import in_place

IEX = "iex"
EXI = "exi"


def default_exclude():
    return {
        "nipper_studio_vulnaudit": r"VULNAUDIT\.[A-Z]*",
        "nipper_studio_logging": r"LOGGING\.[A-Z]*",
        "nipper_studio_configuration": r"CONFIGURATION\.[A-Z]*",
        "nipper_studio_config": r"CONFIG\.[A-Z]*",
        "nipper_studio_security": r"SECURITY\.[A-Z]*",
        "nipper_studio_ssh": r"SSH\.[A-Z]*",
        "nipper_studio_web": r"WEB\.[A-Z]*",
        "nipper_studio_appendix": r"APPENDIX\.[A-Z]*",
        "nipper_studio_timezone": r"TIMEZONE\.[A-Z]*",
        "nipper_studio_ntp": r"NTP\.CL[A-Z]*",
        "nipper_studio_address": r"ADDRESSES\.IP[A-Z]*",
        "nipper_studio_snmp": r"SNMP\.TR[A-Z]*",
        "nipper_studio_filter": r"FILTER\.[A-Z]*",
        "nipper_studio_authentication": r"AUTHENTICATION\.[A-Z]*",
        "nipper_studio_administration": r"ADMINISTRATION\.[A-Z]*",
        "nipper_studio_scope": r"SCOPE\.[A-Z]*",
        "nipper_studio_vuln": r"VULN\.[A-Z]*",
        "nipper_studio_banner": r"BANNER\.[A-Z]*",
        "nipper_studio_reportfiltering": r"REPORTFILTERING[A-Z]*",
        "nipper_studio_remoteaccess": r"REMOTEACCESS\.[A-Z]*",
        "nipper_studio_idsips": r"IDSIPS\.[A-Z]*",
        "nipper_studio_time": r"TIME\.[A-Z]*",
        "nipper_studio_natpat": r"NATPAT\.[A-Z]*",
    }


def random_ip():
    return f"10.{'.'.join(str(random.randint(0, 255)) for _ in range(3))}"


def random_varstring():
    length = random.randrange(8, 16)
    letters = string.ascii_lowercase
    return f"{''.join(random.choice(letters) for i in range(length))}"


def random_varstrings(number=1):
    try:
        assert int(number) in range(10)
    except:
        number = 1
    length = random.randrange(8, 16)
    letters = string.ascii_lowercase
    return [random_varstring() for i in range(number)]


def random_domain():
    letters = string.ascii_lowercase
    return f"{random_varstring()}.example.com"


def random_url():
    return f"https://{random_domain()}/{random_varstring()}"


def random_mail():
    return f"{random_varstring()[:6]}{random_varstring()[:6]}@example.com"


def random_path(platform):
    backslash = "\\"
    if platform == "win":
        return f"C:{backslash}{backslash.join(random_varstrings(3))}{backslash}test.txt"
    else:
        return f"/var/tmp/{'/'.join(random_varstrings(3))}/test.txt"


def trash():
    return {"dangling_xml": r"\<\/.*\>[\)|\.|\,|\;]*$"}


def getGlobalSeparator():
    return "::::"


def static_regexes(full=False):
    start = r""
    end = r""
    if full:
        start = r"^"
        end = r"$"
    return {
            "URL": start + r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+" + end,
            "EMAIL": start + r"[a-zA-Z0-9+_\-\.]+@[0-9a-zA-Z][.-0-9a-zA-Z]*.[a-zA-Z]+" + end,
            "DOMAIN": start + r"(?!:\/\/)([a-zA-Z0-9-_]+\.)*[a-zA-Z0-9][a-zA-Z0-9-_]+\.[a-zA-Z]{2,11}?[a-zA-Z]?" + end,
            "IP": start + r"(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])" + end,
            "WINPATH": start + r"([a-zA-Z]:)*\\[\\\S|*\S]?[^\/|\|\<|\>|\?|\:|\*|\"|\:]{4,}" + end
            }


def reset_filters():
    filters = {
        "include": {
            "DOMAIN": [],
            "URL": [],
            "EMAIL": [],
            "IP": [],
            "WINPATH": []
        },
        "exclude": {
            "DOMAIN": [],
            "URL": [],
            "EMAIL": [],
            "IP": [],
            "WINPATH": []
        },
        "opmode": {
            "DOMAIN": EXI,
            "URL": EXI,
            "EMAIL": EXI,
            "IP": EXI,
            "WINPATH": EXI
        },

    }
    return filters


def setopmode(filterstring):
    if not filterstring:
        return EXI
    if filterstring.startswith("++"):
        return IEX
    return EXI


def init_filters(command):
    _filters = reset_filters()
    order_checked = False
    if not command:
        return _filters
    for _check in command.split("§§"):
        if _check.find("::") >= 0:
            key, raw_filter = _check.split("::")
            if key.upper() not in list(static_regexes().keys()) + ["*"]:
                continue
            filters = raw_filter.split("..")
            _filters["opmode"][key.upper()] = setopmode(raw_filter)
            for f in filters:
                if f.startswith("--"):
                    _filters["exclude"][key.upper()].append(f[2:])
                elif f.startswith("++"):
                    _filters["include"][key.upper()].append(f[2:])
                else:
                    _filters["exclude"][key.upper()].append(f)
        else:
            if _check.startswith("--"):
                mode = "exclude"
                shift = 2
            elif _check.startswith("++"):
                mode = "include"
                shift = 2
            else:
                mode = "include"
                shift = 0
            for k in static_regexes().keys():
                _filters["opmode"][k] = setopmode(_check)
                _filters[mode][k].append(_check)

    return _filters


def deanonymize(file_path, mapping_path):
    return anonymize(file_path, mapping_path, True)


def anonymize(file_path, mapping_path, reverse=False):
    _map = []
    separator = getGlobalSeparator()
    with open(mapping_path, "r") as mapping:
        for line in mapping:
            pair = {"original": line.split(separator)[0].strip(), "new": line.split(separator)[1].strip()}
            _map.append(pair)

    with in_place.InPlace(file_path) as handle:
        for line in handle:
            new_line = line
            for elem in _map:
                _search, _replace = (elem["original"], elem["new"]) if not reverse else (elem["new"], elem["original"])
                if _search in line:
                    new_line = line.replace(_search, _replace)
                    break
            handle.write(new_line)


def is_included(line, filters, pattern_name):
    for f in filters["include"][pattern_name]:
        if re.search(f, line):
            return True
    return False


def is_excluded(line, filters, pattern_name):
    for f in filters["exclude"][pattern_name]:
        if re.search(f, line):
            return True
    return False  # or filters["opmode"][pattern_name] == EXI


def is_filtered(line, filters, pattern_name):
    checked = False
    filtered = False
    pattern_name = pattern_name.upper()
    if not isinstance(filters, dict):
        return True
    if not pattern_name in filters["opmode"].keys():
        return True
    if filters["opmode"][pattern_name] == IEX:
        if is_included(line, filters, pattern_name):
            return not is_excluded(line, filters, pattern_name)
        else:
            return False
    else:
        if is_included(line, filters, pattern_name):
            return True
        return not is_excluded(line, filters, pattern_name)


def search(pattern_name, pattern, line, line_number, unique, seen, filters):
    filters = init_filters(filters)
    line = line.strip()
    mo = re.search(pattern, line)
    if mo:
        result = mo.group()
        if not is_filtered(result, filters, pattern_name):
            return
        for regex in default_exclude().values():
            if re.search(regex, result):
                return
        for regex in trash().values():
            result = re.sub(regex, "", result)
        if unique:
            if result in seen:
                return
            else:
                print("[*][%s][%s] %s" % (pattern_name, line_number, result))
                seen.append(result)
        else:
            print("[*][%s][%s] %s" % (pattern_name, line_number, result))


def check(file_path, regex=None, unique=False, filters=None):
    seen = []
    with open(file_path, "r", errors="ignore") as handle:
        for line_number, line in enumerate(handle):
            if regex == "." or (not regex.upper() in static_regexes().keys()) and len(regex.split("::")) < 2:
                for pattern_name, pattern in static_regexes().items():
                    search(pattern_name, pattern, line, line_number, unique, seen, filters)
            elif len(regex.split("::")) >= 2:
                for k in regex.split("::"):
                    if k.upper() in static_regexes().keys():
                        search(k.upper(), static_regexes()[k.upper()], line, line_number, unique, seen, filters)
            else:
                search(regex.upper(), static_regexes()[regex.upper()], line, line_number, unique, seen, filters)
    return seen


def generate(mapping_file, seen):
    separator = getGlobalSeparator()
    with open(mapping_file, "w+") as mappings:
        counter = 0
        for line in seen:
            line = line.strip()
            m = ""
            if re.search(static_regexes(full=True)["IP"], line):
                m = f"{line}{separator}{random_ip()}\n"
            elif re.search(static_regexes(full=True)["DOMAIN"], line):
                m = f"{line}{separator}{random_domain()}\n"
            elif re.search(static_regexes(full=True)["URL"], line):
                m = f"{line}{separator}{random_url()}\n"
            elif re.search(static_regexes(full=True)["EMAIL"], line):
                m = f"{line}{separator}{random_mail()}\n"
            elif re.search(static_regexes(full=True)["WINPATH"], line):
                m = f"{line}{separator}{random_path('win')}\n"
            mappings.write(m)


def validate_file(filename):
    return os.path.exists(filename)


def check_version():
    if sys.version_info.major < 3:
        print("\n[!] Python2 is not supported. Aborting.\n")
        sys.exit(1)
    return True


def main():
    check_version()
    parser = argparse.ArgumentParser(description='Faceless: A script to anonymize/de-anonymize data')

    parser.add_argument(
        '-c', '--check', required=False, type=str, default=None, help='Check common regex')
    parser.add_argument(
        '-u', '--unique', required=False, action="store_true", default=False, help='Print just first occurrence')
    parser.add_argument(
        '-g', '--generate', required=False, action="store_true", default=False,
        help='Attempt to automatically generate a mapping')
    parser.add_argument(
        '-m', '--mapping', required=False, type=str, default=None, help='Mapping File')
    parser.add_argument(
        '-d', '--debug', required=False, action="store_true", help='Enable debug output')
    parser.add_argument(
        '-i', '--file', required=True, type=str, default=None, help='File to anonymize')
    parser.add_argument(
        '-f', '--filters', required=False, type=str, default=None, help='Filter set in string form')
    parser.add_argument(
        '-r', '--restore', required=False, action='store_true', help='Apply a reverse mapping')

    args = parser.parse_args()

    if args.check and args.mapping:
        print("[-] Check and Mapping are mutually exclusive")
        sys.exit(1)
    if not args.check and args.generate:
        print("[-] Generate must be used in combination with Check")
        sys.exit(1)
    if not validate_file(args.file):
        print("[-] Invalid input")
        sys.exit(1)

    if (not args.check and not args.generate) and (not args.mapping or not validate_file(args.mapping)):
        print("[-] Invalid input or mapping file")
        sys.exit(1)
    elif args.check and not args.generate:
        check(args.file, args.check, args.unique, args.filters)
        sys.exit(0)
    elif args.check and args.generate:
        mapping_file = f"{args.file}.mappings.txt"
        seen = check(args.file, args.check, True, args.filters)
        generate(mapping_file, seen)
        sys.exit(0)
    else:
        if args.restore:
            working_file = f"{args.file}.restored.tmp"
            copyfile(args.file, working_file)
            deanonymize(working_file, args.mapping)
        else:
            working_file = f"{args.file}.tmp"
            copyfile(args.file, working_file)
            anonymize(working_file, args.mapping)


if __name__ == '__main__':
    main()
