#!/usr/bin/python3
"""
    Copyright (c) 2023 Penterep Security s.r.o.

    ptsamesite - Same site scripting detection tool

    ptsamesite is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    ptsamesite is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with ptsamesite.  If not, see <https://www.gnu.org/licenses/>.
"""

import argparse
import sys; sys.path.append(__file__.rsplit("/", 1)[0])

from _version import __version__
from ptlibs import ptmisclib, ptjsonlib, ptprinthelper
from ptlibs.threads import ptthreads, printlock

import dns.resolver
import tldextract


class PtSamesite:
    def __init__(self, args):
        self.ptjsonlib          = ptjsonlib.PtJsonLib()
        self.ptthreads          = ptthreads.PtThreads()
        self.use_json           = args.json
        self.vulnerable         = args.vulnerable
        self.subdomains         = args.subdomains
        self.result_list        = []

        try:
            self.domain_list = ptmisclib.read_file(args.file) if args.file else args.domain
            self._domain_list_len = len(self.domain_list)
        except FileNotFoundError:
            self.ptjsonlib.end_error("File not found", self.use_json)

        if len(self.domain_list) > 1 and self.use_json:
            self.ptjsonlib.end_error("Cannot test more than 1 domain while --json parameter is present", self.use_json)

    def run(self, args) -> None:
        """Main method"""
        ptprinthelper.ptprint("Vulnerable domains:", "TITLE", not self.use_json and self.vulnerable)

        self.ptthreads.threads(self.domain_list, self._test_domain, args.threads)
        self.ptjsonlib.set_status("ok")
        ptprinthelper.ptprint(self.ptjsonlib.get_result_json(), "", self.use_json)

    def _test_domain(self, domain_list: list):
        printlock_ = printlock.PrintLock()
        subdomains = self._prepare_subdomains_for_test(domain_list)
        for subdomain in subdomains:
            self.result_list.append(self._test_subdomain(subdomain, printlock_))
        printlock_.lock_print_output(end="")

    def _test_subdomain(self, subdomain, printlock_):
        printlock_.add_string_to_output( ptprinthelper.out_ifnot(f"Testing {subdomain}", "TITLE", self.use_json, colortext=True), not self.vulnerable)
        data = {"domain": subdomain, "status": "null", "vulnerable": "null", "ip": "null"}
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            ip = resolver.resolve(subdomain, "A", lifetime=5)[0].to_text()
            if ip == "127.0.0.1":
                printlock_.add_string_to_output( ptprinthelper.out_ifnot(f"Vulnerable to same site scripting", "VULN", self.use_json), not self.vulnerable)
                printlock_.add_string_to_output( ptprinthelper.out_if(subdomain, "", self.vulnerable), self.vulnerable)
                self.ptjsonlib.add_vulnerability("PTWVSSS", note=subdomain)
                data.update({"vulnerable": True, "ip": ip, "domain": subdomain, "status": "ok"})
            else:
                printlock_.add_string_to_output( ptprinthelper.out_ifnot(f"Not vulnerable to same site scripting", "NOTVULN", self.use_json), not self.vulnerable)
                data.update({"vulnerable": False, "ip": ip, "domain": subdomain, "status": "ok"})
        except dns.exception.DNSException:
            printlock_.add_string_to_output( ptprinthelper.out_ifnot(f"{str(sys.exc_info()[1]).split(':')[0]}", "INFO", self.use_json), not self.vulnerable)
            data.update({"vulnerable": False, "domain": subdomain, "status": "ok"})
        return data

    def _prepare_subdomains_for_test(self, domain):
        ext = tldextract.extract(domain)
        subdomains = []
        while domain.startswith("."):
            domain = domain[1:]
        if self.subdomains and ext.subdomain:
            parsed_domain = ext.subdomain.split(".")
            if parsed_domain[0] == "localhost":
                parsed_domain.pop(0)
            for tested_subdomain_no in range(len(parsed_domain)):
                subdomains.append("localhost." + ".".join(parsed_domain[tested_subdomain_no:]) + "." + ext.domain + "." + ext.suffix)
            subdomains.append("localhost." + ext.domain + "." + ext.suffix)
        else:
            if not domain.startswith("localhost"):
                domain = "localhost." + domain
            subdomains.append(domain)
        return subdomains


def get_help():
    return [
        {"description": ["Same site scripting detection tool"]},
        {"usage": ["ptsamesite <options>"]},
        {"usage_example": ["ptsamesite -d example.com", "ptsamesite -d example.com example2.com", "ptsamesite -d subdomain1.subdomain2.example.com -s", "ptsamesite -f domain_list.txt", "ptsamesite -f domains_list.txt -s -V -t 100"]},
        {"options": [
            ["-d",  "--domain",           "<domain>",   "Test domain"],
            ["-f",  "--file",             "<file>",     "Test domains from file"],
            ["-s",  "--subdomains",       "",           "Test all subdomains of given domain (default False)"],
            ["-t",  "--threads",          "<threads>",  "Set number of threads (default 20)"],
            ["-V",  "--vulnerable",       "",           "Show only vulnerable domains"],
            ["-v",  "--version",          "",           "Show script version and exit"],
            ["-h",  "--help",             "",           "Show this help message and exit"],
            ["-j",  "--json",             "",           "Output in JSON format"],
        ]}
    ]


def parse_args():
    parser = argparse.ArgumentParser(add_help=False, usage=f"{SCRIPTNAME} <options>")
    exclusive_group = parser.add_mutually_exclusive_group(required=True)
    exclusive_group.add_argument("-d", "--domain", type=str, nargs="+")
    exclusive_group.add_argument("-f", "--file",   type=str)
    parser.add_argument("-t", "--threads",         type=int, default=20)
    parser.add_argument("-s", "--subdomains",      action="store_true")
    parser.add_argument("-V", "--vulnerable",      action="store_true")
    parser.add_argument("-j", "--json",            action="store_true")
    parser.add_argument("-v", "--version",         action="version", version=f"{SCRIPTNAME} {__version__}")

    if len(sys.argv) == 1 or "-h" in sys.argv or "--help" in sys.argv:
        ptprinthelper.help_print(get_help(), SCRIPTNAME, __version__)
        sys.exit(0)

    args = parser.parse_args()
    ptprinthelper.print_banner(SCRIPTNAME, __version__, args.json, space=0)
    return args


def main():
    global SCRIPTNAME
    SCRIPTNAME = "ptsamesite"
    args = parse_args()
    script = PtSamesite(args)
    script.run(args)


if __name__ == "__main__":
    main()
