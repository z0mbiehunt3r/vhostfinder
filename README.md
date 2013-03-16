vhostfinder
===========

Enumerates virtual hosts against several IP addresses through "Host" HTTP header. <br>
It will save a CSV file with answers info and will write HTML answer code per IP address and vhost.

Requisites
-----
You will need argparse (<http://code.google.com/p/argparse/>), requests (https://pypi.python.org/pypi/requests) and iptools (https://pypi.python.org/pypi/iptools/).
<br><br>Can be installed with pip:
```
# pip install argparse requests iptools
```

Usage
-----
```
$ ./main.py -d wikipedia.org -i netranges.txt -o ./output_reports/wikipedia --vhosts wordlists/vhosts_small.txt -v -c
```

Example
-----
![](http://img839.imageshack.us/img839/9996/vhostfinder.png)

CSV Output
-----
![](http://img59.imageshack.us/img59/3371/vhostfindercsvp.png)
