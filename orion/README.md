# Orion

This machine primarily focuses on exploiting CVEs. Running an Nmap scan, we find a web application running.

![Nmap scan](img/image.png)

![Web application homepage](img/image-1.png)

We didn't find any subdomains.

![Subdomain enumeration](img/image-3.png)

However, there is an admin page.

![Path enumeration](img/image-2.png)


![Admin login page](img/image-4.png)

After researching this CMS, we find the following CVE:

https://nvd.nist.gov/vuln/detail/CVE-2025-32432


There is a Metasploit module available for this CVE, which we can use to exploit the vulnerability.

![Metasploit module configuration](img/image-5.png)

![Finding credentials](img/image-6.png)

We find the MySQL credentials in the `.env` file. We can connect using the password `SuperSecureCraft123Pass!`:

```bash
mysql -D orion -u root -p
```

```sql
select * from users;
```

After retrieving the `users` table, we get the password hash for adam, who is a user on this machine.

| email | password |
|----------|----------|
| adam@orion.htb | $2y$13$e9zuohgFZzGtbQalcn9Mz.5PJbjxobO0GMbXo8NHp3P/B42LUg0lS |

We can crack this hash using `john`:

![Cracking hash with John the Ripper](img/image-7.png)

We can log in as `adam:darkangel` via SSH and inspect the local ports in use. Interestingly, there is a telnet service running, which I will tunnel to my host to test more easily.

![SSH connection and local ports check](img/image-8.png)

![Tunneling the telnet service](img/image-9.png)

After searching for the service name, we find a related CVE:

https://github.com/SystemVll/CVE-2026-24061

After downloading and executing the script, we become root and obtain the flag.

![Root flag](img/image-10.png)