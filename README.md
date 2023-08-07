[![penterepTools](https://www.penterep.com/external/penterepToolsLogo.png)](https://www.penterep.com/)


# PTSAMESITE

> Same site scripting detection tool

ptsamesite is a tool that tests domains for same site scripting vulnerability. <br />
ptsamesite utilizes threading for fast parallel domain testing.


## Installation

```
pip install ptsamesite
```

## Add to PATH
If you cannot invoke the script in your terminal, its probably because its not in your PATH. Fix it by running commands below.

> Add to PATH for Bash
```bash
echo "export PATH=\"`python3 -m site --user-base`/bin:\$PATH\"" >> ~/.bashrc
source ~/.bashrc
```

> Add to PATH for ZSH
```bash
echo "export PATH=\"`python3 -m site --user-base`/bin:\$PATH\"" >> ~/.zshhrc
source ~/.zshhrc
```

## Usage examples
```
ptsamesite -d example.com                               # Test domain
ptsamesite -d example.com example2.com                  # Test two domains
ptsamesite -d subdomain1.subdomain2.example.com -s      # Test domain along with all subdomains
ptsamesite -f domain_list.txt                           # Test domains from a file
ptsamesite -f domains_list.txt -s -t 100 -V             # Test domains from a file with all present subdomains, set threads count to 100 and print only vulnerable domains
```

## Options
```
-d  --domain      <domain>   Test domain
-f  --file        <file>     Test domains from file
-s  --subdomains             Test all subdomains of given domain (default False)
-t  --threads     <threads>  Set number of threads (default 20)
-V  --vulnerable             Show only vulnerable domains
-v  --version                Show script version and exit
-h  --help                   Show this help message and exit
-j  --json                   Output in JSON format
```


## Dependencies
```
dnspython
tldextract
ptlibs
```

## Version History
```
1.0.0
    - Code improvements
    - Updated for ptlibs 1.0.0
0.0.1 - 0.0.5
    - Alpha releases
```

## License

Copyright (c) 2023 Penterep Security s.r.o.

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

## Warning

You are only allowed to run the tool against the websites which
you have been given permission to pentest. We do not accept any
responsibility for any damage/harm that this application causes to your
computer, or your network. Penterep is not responsible for any illegal
or malicious use of this code. Be Ethical!