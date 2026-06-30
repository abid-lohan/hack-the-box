# Cap

Port enumeration reveals an FTP service and a web application.

![Nmap scan](img/image-3.png)

Checking the website, we notice an IDOR vulnerability on `/data/<id>`. Our current ID, 1, has no useful packets. However, ID 0 contains packets, and we can download the PCAP file:

![Vulnerable endpoint](img/image.png)

![Downloading the PCAP file for /data/0](img/image-1.png)

Analyzing the file in `Wireshark`, we find the FTP credentials:

![Credentials found in Wireshark](img/image-2.png)

We confirm the credentials and retrieve the first flag from the FTP server:

![Retrieving the flag via FTP](img/image-4.png)

The same credentials work for SSH, so we log in using them.

The privilege escalation path, as the box's title suggests, involves capabilities. We can list files with configured capabilities by running `getcap -r / 2>/dev/null`:

![Capabilities exploitation](img/image-5.png)

Since `python3.8` has the `cap_setuid` capability, we can exploit it to spawn a shell with root privileges and obtain the final flag.