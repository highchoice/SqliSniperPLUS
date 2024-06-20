<p align="center">
<a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/license-MIT-_red.svg"></a>
</p>

<p align="center">
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
</p>

**Based on** <a href="https://github.com/danialhalo/SqliSniper">SqliSniper</a> •  <br> 
**SqliSniperPLUS** is a robust Python tool designed to detect time-based blind SQL injections in HTTP request headers and GET parameters. It enhances the security assessment process by rapidly scanning and identifying potential vulnerabilities using multi-threaded, ensuring speed and efficiency. Unlike other scanners, SqliSniperPLUS is designed to eliminates false positives through and send alerts upon detection, with the built-in Discord notification functionality.

## Key Features
- **Time-Based Blind SQL Injection Detection:** Pinpoints potential SQL injection vulnerabilities in HTTP headers.
- **Multi-Threaded Scanning:** Offers faster scanning capabilities through concurrent processing.
- **Discord Notifications:** Sends alerts via Discord webhook for detected vulnerabilities.
- **False Positive Checks:** Implements response time analysis to differentiate between true positives and false alarms.
- **Custom Payload and Headers Support:** Allows users to define custom payloads and headers for targeted scanning.


## Installation
```
git clone https://github.com/highchoice/SqliSniperPLUS.git
cd SqliSniperPLUS
chmod +x SqliSniperPlus.py
pip3 install -r requirements.txt
```
# Usage

This will display help for the tool. Here are all the options it supports.
```
ubuntu:~/SqliSniperPLUS$ ./SqliSniperPlus.py -h

usage: SqliSniperPlus.py [-h] [-u URL] [-r URLS_FILE] [-p] [--proxy PROXY] [--payload PAYLOAD] [--single-payload SINGLE_PAYLOAD] [--discord DISCORD] [--headers HEADERS]
                     [--threads THREADS] [--getparams]

Detect SQL injection by sending malicious queries

options:
  -h, --help            show this help message and exit
  -u URL, --url URL     Single URL for the target
  -r URLS_FILE, --urls_file URLS_FILE
                        File containing a list of URLs
  -p, --pipeline        Read from pipeline
  --proxy PROXY         Proxy for intercepting requests (e.g., http://127.0.0.1:8080)
  --payload PAYLOAD     File containing malicious payloads (default is payloads.txt)
  --single-payload SINGLE_PAYLOAD
                        Single payload for testing
  --discord DISCORD     Discord Webhook URL
  --headers HEADERS     File containing headers (default is headers.txt)
  --threads THREADS     Number of threads
  --getparams           Test only GET parameters for SQL injection | without this switch just Headers will be tested!
```

# Running SqliSniperPLUS
### Single Url Scan - Headers only
The url can be provided with `-u flag` for single site scan
```
./SqliSniperPlus.py -u http://example.com
```
### Single Url Scan GET params only
The url can be provided with `-u flag` for single site scan with `--getparams` to scan onyla GET parameters
```
./SqliSniperPlus.py -u http://example.com/param1=xxx&param2=123 --getparams
```
### File Input
The `-r flag` allows SqliSniperPlUS to read a file containing multiple URLs for simultaneous scanning.
```
./SqliSniperPlus.py -r url.txt
```
### piping URLs
The SqliSniperPlUS can also worked with the pipeline input with `-p flag`
```
cat url.txt | ./SqliSniperPlus.py -p
```
The pipeline feature facilitates seamless integration with other tools. For instance, you can utilize tools like subfinder and httpx, and then pipe their output to SqliSniperPlUS for mass scanning.
```
subfinder -silent -d google.com | sort -u | httpx -silent | ./SqliSniperPlus.py -p
```
### Scanning with custom payloads  
By default the SqliSniperPlUS use the payloads.txt file. However `--payload flag` can be used for providing custom payloads file.
```
./SqliSniperPlus.py -u http://example.com --payload mssql_payloads.txt
```
While using the custom payloads file, ensure that you substitute the sleep time with `%__TIME_OUT__%`. SqliSniperPlUS dynamically adjusts the sleep time iteratively to mitigate potential false positives.
The payloads file should look like this.
```
ubuntu:~/SqliSniperPLUS$ cat payloads.txt 
0\"XOR(if(now()=sysdate(),sleep(%__TIME_OUT__%),0))XOR\"Z
"0"XOR(if(now()=sysdate()%2Csleep(%__TIME_OUT__%)%2C0))XOR"Z"
0'XOR(if(now()=sysdate(),sleep(%__TIME_OUT__%),0))XOR'Z
```
### Scanning with Single Payloads
If you want to only test with the single payload `--single-payload flag` can be used. Make sure to replace the sleep time with `%__TIME_OUT__%`
```
./SqliSniperPlus.py -r url.txt --single-payload "0'XOR(if(now()=sysdate(),sleep(%__TIME_OUT__%),0))XOR'Z"
```
### Scanning Custom Header 
Headers are saved in the file headers.txt for scanning custom header save the custom HTTP Request Header in headers.txt file. 
```
ubuntu:~/SqliSniperPLUS$ cat headers.txt 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
X-Forwarded-For: 127.0.0.1
```
### Scanning GET Parameters 
GET parameters are parsed from URL and tested one by one 
```
ubuntu:~/SqliSniperPLUS$ ./SqliSniperPlus.py -r url.txt --getparams
```
### Scanning GET Parameters with papline 
Automate testing list of urls with other tools 
```
ubuntu:~/SqliSniperPLUS$ cat url.txt | katana -f qurl -silent | sort -u | python3 sqlisniperNEWv4.py -p --proxy http://10.10.16.1:9090 --threads 50 --getparams
```
### Sending Discord Alert Notifications
SqliSniperPlUS also offers Discord alert notifications, enhancing its functionality by providing real-time alerts through Discord webhooks. This feature proves invaluable during large-scale scans, allowing prompt notifications upon detection.
```
./SqliSniperPlus.py -r url.txt --discord <web_hookurl>
```
### Multi-Threading 
Threads can be defined with `--threads flag`
```
 ./SqliSniperPlus.py -r url.txt --threads 10
```
**Note:** It is crucial to consider that **employing a higher number of threads might lead to potential false positives or overlooking valid issues**. Due to the nature of time-based SQL injection it is recommended to use lower thread for more accurate detection.

---

<table>
<tr>
<td>

## Legal Disclaimer

Usage of this tool for attacking targets without prior mutual consent is strictly prohibited. It is the end user's responsibility to obey all applicable local, state, and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program..

</td>
</tr>
</table>

---

# Contributing
Contributions to SqliSniperPlUS are always welcome. Whether it's feature enhancements, bug fixes, or documentation improvements, every bit of help is appreciated.


