# OWASP Top 10 - A Primer
This document explores the 10 vulnerability classes discussed in [OWASP Top 10 - 2017](https://www.owasp.org/images/7/72/OWASP_Top_10-2017_%28en%29.pdf.pdf).

## Vulnerabilities
---
### A1:2017 - Injections
#### Definition / Description
 A web application is vulnerable to injection attacks if user-supplied data is not properly validated, filtered, or sanitized before being processed by the interpreter. Injection vulnerabilities can be exploited to reveal sensitive information, execute commands on host systems, and exfiltrate or destroy data. Within the category of injection attacks are two main classes: code and command injections. Code injection attacks are limited in what they can do based on the language they are written in; command injection utilizes existing code to execute commands, usually within the context of a shell. Injection vulnerabilities are very common, they are easy to exploit and can have a severe impact, however, they are also easy to detect.

 What makes injection attacks so prevalent compared to the other attacks named in the OWASP Top 10 is that they are quite varied in their implementation. Code injections are not limited to a single programming language,
 nor are they confined to a specific web framework. They can utilize PHP, Javascript, SQL, HTML, or any other language that a web application relies on to function. Similarly, command injections leverage operating system
 commands to operate maliciously by extending the functionality of the target application. 

#### How it Works
While there are many types of code injection attacks, cross-site scripting (XSS) and SQL injection are two of the most common and both present an extremely high risk to the confidentiality, integrity, and availability to business data. No matter the code injection type, they all work in relatively the same way. User-supplied data is first input into a web application which is then processed by the interpreter. Whether it is a file upload field, a comment box, or an open url query parameter, the supplied untrusted data is formatted in a particular way so as to achieve a specific result desired by an attacker.  

For example, SQL injection can give unauthorized access to information stored in a backend database, whereas XSS can allow an attacker to send malicious code to end users which can grant an attacker access to cookies, session tokens, or other sensitive information.

An attacker has plenty of manual and automated methods to identify and exploit injection vulnerabilities. Manual methods of identifying injection vulnerabilities range from checking urls for open query parameters to testing various syntax-breaking code expressions and looking for potentially helpful error statements. Automated tools--such as sqlmap and Burp Suite--can help identify code injection vulnerabilities within web applications by scanning and mapping web applications, identifying known points of vulnerability, and running code against them.

#### Scenario
SQL injection UNION attacks are possible when an application is already vulnerable to SQL injections. A UNION attack allows one or more SELECT queries to be appended to an original query thereby returning data from other tables within a database. Two requirements must be met to successfully execute a SQL UNION injection:
- The individual queries must return the same number of columns from the table.
- The data types in each column must be compatible between the individual queries.

*SQL Injection UNION attack example:*

```URL Encoded UNION query: <http://ptl-f99df351-3bdd4c8f.libcurl.so/cat.php?id=1%20UNION%20SELECT%201,concat(login,%27:%27,password),3,4%20FROM%20users>
Decoded UNION query: http://ptl-f99df351-3bdd4c8f.libcurl.so/cat.php?id=1 UNION SELECT 1,concat(login,':',password),3,4 FROM users
```

Because a UNION injection attack requires individual queries to return the same number of columns from a table, a string concatenation can be performed to bypass column-number-matching issues. In the example above, the text to the left of the UNION keyword is a url query parameter where the SQL command is set to "id". Columns 3 and 4 from the users table is set to match column 1, where the second matching pair is a concatenation of "login" and "password" separated by a colon. To comply with the first requirement of SQL injection UNION attacks, a string concatenation is required to ensure that the individual queries return the same number of columns. This allows for multiple values to be retrieved within a single column.

#### Mitigation  
Two ways of mitigating injection attack vulnerabilities:
1. Whitelist approaches to allowing user-input data is an easier way to prevent code injections
2. Encoding user-supplied data can prevent XSS and accounts for the wide variety of programming languages that can be used to execute an injection attack.

**Command Injection**    
Command injection attacks are possible when an application passes unsafe user-supplied data to a system shell. It is often the case that a code injection attack can also permit a command injection attack.

Example: The following PHP code is susceptible to a command injection attack because the user-supplied argument 'filename' is called by the function 'system' which is intended to only delete files. By escaping the command using a semicolon, other OS commands can be inserted.

```
<?php
print("Please specify the name of the file to delete");
print("<p>");
$file=$_GET['filename'];
system("rm $file");
?>
```

Here is the same PHP file modified with a command injection:

```
http://127.0.0.1/delete.php?filename=bob.txt;ls
```

The filename 'bob.txt' is selected to be removed, but the inclusion of the semicolon ends that command and begins a second one, in this case 'ls'.

---
### A2:2017 - Broken Authentication
#### Definition / Description
Broken authentication refers to authentication and session management implementation flaws that allow attackers to assume other users' identities. The security risks associated with this are largely dependent on the type of web application that is accessed: severe, if an assumed account has administration-level access to a database with sensitive data; less severe, if the assumed account is an everyday user's social media account (or similar) where identity theft then becomes the issue. 

It is very common for username and password combinations to be reused across multiple platforms which means a breach of a user's account on one platform can potentially be extended to access accounts on others. This was the case in the Sony (2011), Yahoo (2012), and Dropbox (2012) breaches where it was discovered that two-thirds of the compromised user login credentials were reused on other systems.

#### How it Works
User authentication typically requires a matching username and password pair, with more robust systems also implementing some form of multi-factor authentication. Well-developed authentication and session management schemes will implement complex password requirements, limited credential entry attempts, password databases that encrypt or hash entries, user sessions that are encrypted from beginning to end, and other OWASP-defined security policies and mechanisms. Web applications that don't implement limited login attempts are vulnerable to brute force attacks; if the same systems also do not require the use of complex passwords, a brute force attack would become even more effective.

#### Scenario
Using the Damn Vulnerable Web Application (DVWA) as the testing space and BurpSuite as the tool, I demonstrate how a simple brute force attack can exploit a broken authentication vulnerability.

---
##### Raw Request 

```
GET /dvwa/vulnerabilities/brute/?username=test&password=test&Login=Login HTTP1.1
Host: localhost
User-Agent: Mozilla/5.0 (x11; Ubuntu; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Referer: http://localhost/dvwa/vulnerabilities/brute/?username=test&password=test&Login=Login
Cookie: security=low; PHPSESSID=ai0d0pdqhd8ni12nvjfm08vc4p
Upgrade-Insecure-Requests: 1
```

##### Intruder Request 

```
GET /dvwa/vulnerabilities/brute/?username=admin&password=password&Login=Login HTTP1.1
Host: localhost
User-Agent: Mozilla/5.0 (x11; Ubuntu; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Referer: http://localhost/dvwa/vulnerabilities/brute/?username=test&password=test&Login=Login
Cookie: security=low; PHPSESSID=ai0d0pdqhd8ni12nvjfm08vc4p
Upgrade-Insecure-Requests: 1
```

##### Valid Response(s)

```
HTTP/1.1 200 OK
Date: Wed, 07 Aug 2019 10:45:45 GMT
Server: Apache/2.4.29 (Ubuntu)
Expires: Tue, 23 Jun 2009 12:00:00 GMT
Cache-Control: no-cache, must-revalidate
Pragma: no-cache
Vary: Accept-Encoding
Content-Length: 4419
Connection: close
Content-Type: text/html;charset=utf-8
```

#### Mitigation
Here are two ways to prevent a brute force attack:
 1. Limiting the number of login attempts before the account is locked (or implementing an ever-increasing time delay for each successive login attempt).    
 2. Implementing multi-factor authentication to ensure that a password-username pair, on its own, is insufficient to authenticate a user onto a system.
 
---
### A3:2017 - Sensitive Data Exposure
#### Definition / Description
Most web applications store user data that is considered sensitive and personally identifiable. For example, web applications related to banking, health, and e-commerce might store user credit cards, login credentials, physical and mailing addresses, social security numbers and more. The unauthorized disclosure of this information could enable malicious activities like identity theft, financial fraud, and extortion. Sensitive data exposure (SDE) exists on the OWASP Top 10 because of its widespread impact on businesses and consumers and the relative ease of its exploitability. Whereas most of the other OWASP Top 10 define more narrow security vulnerabilities, sensitive data exposure refers to the broader impact of those attacks. For example, injection attacks (e.g., SQL injection), broken access controls (e.g., local file inclusion), and broken authentication (e.g., credential stuffing) can all result in the exposure of sensitive data either directly (e.g., a database dump as a result of well-crafted SQL queries) or by enabling subsequent attacks through the initial exposed data (i.e., pivoting within exposed networks or accessing a user's email account using stolen credentials).

Sensitive data needs to be properly secured throughout all phases of its digital journey: from the initial user-supplied input within the web application, to its transit over the wire and finally through to its final resting place on the backend database. By implementing proper security controls like HTTPS and encrypting all user data using strong cryptographic algorithms, the risk of sensitive data exposure can be mitigated. 

#### How it Works
Local File Inclusion (LFI) is an example of a sensitive data exposure vulnerability because it can allow an attacker to output the contents of a file stored locally on a web application's server. This vulnerability exists when a web page receives the path to a file--as input from the user--which is not properly sanitized. So, for example, if in the URL of a webpage the query parameter "?page=" exists, an attacker can modify the request to perform a directory traversal using "../" instead of the developer's intended "file.php." 

#### Scenario
I demonstrate how an LFI vulnerability can be exploited using the DVWA.

On the low security setting, the requested file1.php page generates the following URL:

```
localhost/dvwa/vulnerabilities/fi/?page=file1.php
```

Because no input validation filters are applied, the "?page=" query parameter can easily be modified to output the contents of the target fi.php file:

```
localhost/dvwa/vulnerabilities/fi/?page=../../hackable/flags/fi.php
```

On the medium security setting, the backend filter strips user input of the following character sets: "../", "..\", "http://", "https://". This is an example of a blacklist-based security mechanism that can easily be bypassed. If a user-input validation filter strips known bad query parameters, such as the "../" directory traversal, a request can be crafted to bypass the filter mechanism by splitting the desired query parameter value into two. When the known-bad string is removed by the filter, the desired split string remains, concatenates, then yields the desired payload.

Because "../" is filtered out, try "..././". The filter will match the ".[../]./" known-bad string, remove it from the query, and the surrounding characters "../" will concatenate thus yielding the desired payload. Here is the modified URL query parameter that successfully bypasses the medium security setting filter:

```
localhost/dvwa/vulnerabilities/fi/?page=..././..././hackable/flags/fi.php
```

#### Mitigation
- To defend against LFI attacks, a web application developer should filter user-supplied inputs to only allow the parameterization of specified files on the web server. A blacklist approach is ineffective in mitigating LFI attacks because they can easily be circumvented by a carefully crafted URL query parameter. A blacklist policy might be implemented using a string-replacement function that either replaces or strips user input of the specified terms, expressions, or characters. Therefore, a whitelist policy, where only the file(s) specified by the developer are allowed, is the recommended approach.
---
### A4:2017 - XML External Entities (XXE)
#### Definition / Description
XML External Entity vulnerabilities are a type of injection attack when exploited by a malicious user. It essentially allows untrusted data to be processed by an XML parser and can result in the loss of confidentiality and availability with respect to the CIA triad.

#### How it Works
Web developers use XML, or e**X**tensible **M**arkup **L**anguage, as a way to exchange data between potentially incompatible systems. Because the data is sent and received as plaintext, XML is used as a software- and hardware-neutral way for sharing and storing data that eliminates the programmatic need to first convert it. The way that XML organizes data is by creating units called entities, which can be defined as either internal or external.     
-An internal entity is similar to a JSON key-value syntax, or even a bash alias, where an entity is defined by the syntactic structure <!ENTITY entityname "replacement text">. The text defined in the "replacement text" section will replace the "entityname" whenever it is invoked; before an entity can be called for replacement it must first be defined within the XML document. The replacement text can either be a single character, a string, or even entire documents.     
-An external entity contains a value inside or outside the XML document, and takes the form <!ENTITY entityname SYSTEM "system identifier">. The entityname is, once again, an arbitrary name defined by the developer that is invoked in order to call the information contained within the "system identifier." The system identifer is usually a URI, the contents of which will replace the entityname wherever it is called. The ability for external elements to be called and processed by an XML parser is what enables XXE attacks.  

**Note:** The following syntax is required to call an entity: <&entityname;>.

Another important component of XML is the Document Type Definition (DTD), or DOCTYPE, which is an optional file that defines the structure, elements, and attributes of an XML document. This file can also define entities within itself, which has been used to launch XML bombs such as the so-called "Billion Laughs" attack (sample below). 

#### Scenario
##### Payload 1: Accessing System Files

```xml
<?xml version="1.0" encoding="ISO-8859-1"?> <!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file:///etc/passwd" >]> <foo>&xxe;</foo>
```
 
The output of this command will be the contents of the system's /etc/passwd file. The entity name is xxe, and the system identifier is "file:///etc/passwd."
 
 ##### Payload 2: Accessing a Private Network
 
```xml
<!ENTITY xxe SYSTEM "https://192.168.1.1/private" >]>
```

This attack attempts to access the server's private network.

##### Payload 3: Denial of Service

```xml
<!ENTITY xxe SYSTEM "file:///dev/random" >]>
```

This command attempts to execute a denial of service attack (DOS) because it forces the XML parser to try and retrieve the contents of the system file /dev/random (which is Linux's pseudo-random number generator) and substitute it for the entityname "xxe".

 ##### Payload 4: Denial of Service: The Billion Laughs Attack
 
```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
  <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
  <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
  <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
  <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<lolz>&lol9;</lolz>
```

This attack attempts to exhaust the system's resources by forcing the XML parser to expand each nested entity. This small file ~1kb, actually contains one-billion lol's when fully expanded.

#### Mitigation
One of the most effective ways to mitigate XXE attacks is to disable external entities completely. OWASP provides helpful documentation for disabling DTDs for many of the most popular parsers [OWASP's XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html).

---
### A5:2017 - Broken Access Control
#### Definition / Description
Broken access control (BAC) differs from broken authentication in that access controls determine which users are given permission to read or write a given set of data; authentication is the process by which a user's identity is validated. With respect to the CIA (confidentiality, integrity, and availability) triad, broken access control is primarily concerned with the preservation of confidentiality and secondarily concerned with integrity: if a generic user, authenticated or otherwise, has administrative-level access, data can be exfiltrated, deleted, or modified.

BAC vulnerabilities are relatively common and easy to exploit because automated detection mechanisms are ineffective in identifying them; OWASP recommends that manual tests be run against web applications in order to best identify BAC vulnerabilities.

#### How it Works
Local file inclusion, discussed previously in section **A3-Sensitive Data Exposure**, is a great example of a broken access control vulnerability. Within a secure web application, the only local files able to be requested by a generic user are those specifically defined by the developer within a whitelist. If a url query parameter is unrestricted, as was demonstrated by the DVWA low-security setting in A3, a user would be allowed to modify the query to request access to any file on the local system. In this way, confidentiality is breached because an unauthenticated and unauthorized user would have access to sensitive data.

#### Scenario
Suppose you log into an application as the user `jane`, and get redirected to: `https://example.site/userProfile.php?user=jane`.

Suppose Jane is able to see Bob's profile by navigating to: `https://example.site/userProfile.php?user=bob`
- This is called Insecure Direct Object Reference (IDOR) or parameter-based access control. This vulnerability exists when a web application retrieves content based on untrusted user-supplied input, which can allow an attacker to modify the URL parameter without being properly authenticated. 
---
### A6:2017 - Security Misconfiguration
#### Definition / Description
Security misconfigurations is a broad category of vulnerabilities that generally relate to unpatched systems, out-of-date software, the non-removal of default accounts and administrative credentials, and overly-verbose error messages. The exploitation of these vulnerabilities can give an attacker access to a user account with high privileges or it can help facilitate an attacker in identifying ways to penetrate a system. Security misconfigurations are extremely common, easy to exploit, easy to detect, and they can have a moderate to severe impact on a business depending on the type of service they provide. 

#### How it Works
An example of a security misconfiguration is if the PHP runtime options "allow_url_include" and "allow_url_fopen" are enabled on a web server. This vulnerability would allow a remote file inclusion attack to be executed by permitting the upload of files to a web application's backend server via a user-supplied URL. While benign use cases for this configuration exist, an attacker can exploit this vulnerability by uploading a malicious PHP script, for example a webshell, which can then freely carry out shell commands. The initial upload can take place either by modifying the URL query parameter to link to a file hosted on an external site, or an upload field will be available within the app itself in order to inject a malicious script onto the system. The resulting upload destination path can be logically followed by inspecting the page's source elements and inserting that path into the URL.

##### Sample PHP Webshell Script:
If a web application had "allow_url_include" and "allow_url_fopen" options enabled, this script could be uploaded to the server in order to open an interactive webshell.

```
<?php
$command = $_GET['cmd'];
echo system($command);
?>
```

The $_GET['cmd']; part of the script receives the value of the query parameter in the URL; in this case, 'cmd' is the query parameter and any desired system commands would be set equal to it. By intercepting an HTTP request to the uploaded file's path on the web server (using a tool like Burp Suite), a command injection attack can be performed through a crafted URL. As an example, the request line for a modified HTTP request header that seeks to dump the contents of a web server's /etc/passwd file would look something like this:
```
GET /hackable/webshell.php?cmd=cat%20/etc/passwd
```

The path to the uploaded malicious file would be then followed by the desired system command, in this case 'cat /etc/passwd'. Because the request is being made in the URL, all system commands would have to be properly URL encoded (Burp Suite can automatically encode payloads for URL insertion).

#### Scenario
To help mitigate remote file inclusion attacks like the above webshell, it is considered best practice to keep "allow_url_include" and "allow_url_fopen" disabled within the `php.ini` configuration file.

```php
allow_url_fopen=Off
allow_url_include=Off
```

---
### A7:2017 - Cross-Site Scripting (XSS)
#### Definition / Description

Cross-site scripting is a vulnerability that allows an attacker to compromise the interactions that users have with a web application. There are three main types of cross-site scripting (XSS) attacks: reflected, DOM, and persistent. Reflected XSS attacks get echoed to the webpage based on malicious user input; persistent XSS attacks, considered the most dangerous, get stored on the web application's database and is included in the server's HTTP response for other users' HTTP requests; DOM-based XSS exploits the client-side script via manipulation of the document object model (DOM). 
 
#### How it Works
Reflected XSS gets echoed to a web page when an application receives an HTTP request and includes the untrusted attacker-supplied data. A reflected XSS injection in the URL query parameter will execute the arbitrary script in a user's browser if they visit that particular webpage. The consequence of a successful reflected XSS injection is that an attacker can steal the identity of a user, view and modify any data at the user's privilege level, or steal the user's sensitive data.

#### Scenario
I use DVWA to demonstrate a reflected XSS injection in conjunction with BurpSuite to capture and modify the HTTP request. The HTTP request is captured by the proxy, then forwarded on to Burp Intruder where the position and payload are set, and then the modified HTTP request with the XSS injection is forwarded on to execute the attack.

```
GET /dvwa/vulnerabilities/xss_r/?name=%3Cscript%3Ealert%28%22test%22%29%3C%2Fscript%3E HTTP1.1
Host: localhost
User-Agent: Mozilla/5.0 (x11; Ubuntu; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Referer: http://localhost/dvwa/vulnerabilities/brute/?username=test&password=test&Login=Login
Cookie: security=low; PHPSESSID=4ok2c5opnf27mndsfpqkpuh72
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0

```
---
### A8:2017 - Insecure Deserialization
#### Definition / Description
Serialization is the process of converting an object into a format which allows it to be saved to a disk, sent across a network, or sent through streams. The format that an object is serialized into can either be binary or structured text, such as JSON, YAML, or XML (discussed earlier in A4-XML External Entities). Deserialization is, of course, the reverse process where structured or binary text is converted into an object. Web applications perform serialization and deserialization, more generally referred to as data parsing, on a regular basis as part of their normal functionality. This data conversion process can be exploited by an attacker to carry out denial of service attacks (DOS), execute remote code injection, and bypass application authentication processes.

Trusted (de)serialization is when data is processed and retrieved from known-good sources, such as those with authenticated cryptographic signatures. To mitigate attacks that exploit insecure deserialization, OWASP recommends that native (de)serialization formats be avoided and that untrusted user-supplied data be rejected entirely or sanitized for safe (de)serialization.

#### How it Works / Scenario
A remote code execution (RCE) attack can be acheived by exploiting insecure deserialization through modifying HTTP requests and injecting a malicious payload.

---
### A9:2017 - Using Components with Known Vulnerabilities
#### Definition / Description
Today's web applications utilize many different components in order to provide content and functionality to their user-base. Developers and security personnel need to have a comprehensive understanding of all of the components that touch their service, including both the front and back ends. Knowledge of an entire application's architecture is the first step towards ensuring that all peripheral components have their current software updates and vulnerability patches installed.

Using components with known vulnerabilities is a widespread problem, but fortunately it is relatively easy to detect and even easier to patch. However, despite the relative ease of patching outdated or vulnerable systems, many of the infamous cyberattacks that have made the news over the past few years relied on users not updating their devices. The WannaCry ransomware attack in 2017 exploited the EternalBlue vulnerability and was able to propagate so effectively due to the large number of systems that went unpatched; systems that applied Microsoft's security patches, which were released two months prior to the WannaCry attack, avoided becoming infected.

#### How it Works: The Supply Chain 
Related to using components with known vulnerabilities is sourcing materials from vulnerable supply chains. As a best practice, the National Institute of Standards and Technology (NIST) recommends that businesses make concerted efforts to secure their supply chains. This entails identifying and assessing suppliers, performing routine audits of suppliers and their products, and developing trusted relationships with known-good vendors, among many others. The rather famous supply chain attack against the US-based company's Supermicro hardware in 2018 highlights the serious security implications of supply chain attacks. Because software, firmware, and hardware distributed directly by vendors is asusmed to be safe, they are often highly desirable targets for attacks and compromises. 

---
### A10:2017 - Insufficient Logging & Monitoring
#### Definition / Description
Sufficient logging and monitoring are two foundational components for protecting a network. Proper logging provides an analyst or auditor sufficient information to mitigate, assess, and analyze attacks. The next crucial step is to ensure that those logs are actively monitored. A robust logging and alert system has little value if real-time alerts are not being acted upon. A related issue is if network log files are only stored locally as they could be susceptible to deletion or modification by an attacker. A second logging-related issue is sensitivity: logging and alert systems should be fine-tuned to minimize false positives and negatives, but they should be sensitive enough to detect any potentially malicious behavior. Quality alert mechanisms are essential for mitigating alert fatigue, which desensitizes analysts who ignore critical alerts due to an excessive number of false positives. A third focus should be placed on quality record keeping. If a breach does occur, sufficient log files should be preserved for forensic analysis. This is especially important in criminal cases where a business is required to produce forensic evidence for legal review.

*Note:* A sometimes overlooked area of logging and monitoring is in a business's physical security. Access logs, security camera footage, and visitor logs should also be maintained with the same care and duration as network traffic logs.

#### How it Works / Scenario
The first two steps in hacking a network are footprinting and scanning. Footprinting is the reconnaissance phase of an attack where a malicious user will work to identify key information about a business, such as its network topography, organizational data, operating systems, etc. Scanning is the more intrusive step where an attacker will actively engage and probe a target network. In this second phase an attacker will seek to identify things like open ports, operating systems, services or processes running, the presence of firewalls, addresses of routers or other devices, and existing known vulnerabilities.

##### A network intrusion detection system that is properly configured should be able to log an attackers activity and, if the attacker is sloppy or overly aggressive, it should flag their behavior as malicious and would send an alert to network administrators. A poorly configured logging and monitoring might miss these red flags which could permit an attacker to breach a company network without being noticed. Similarly, a well-configured network monitoring system that is itself not monitored could also enable an attacker to work freely within or around a system.
---
### Sources    
-OWASP.org    
-Acunetix.com    
-Portswigger.net    
-"The Web Application Hacker's Handbook, Second Edition", by Dafydd Stuttard and Marcus Pinto    
