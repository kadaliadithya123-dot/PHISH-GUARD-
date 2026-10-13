# PHISH GUARD - Feature Engineering & Cybersecurity Rationale

This document provides a comprehensive technical breakdown of the **30 lexical, structural, statistical, and security features** engineered in `feature_extractor.py`.

---

## Technical Feature Matrix

| # | Feature Key | Type | Description | Cybersecurity Rationale |
|---|---|---|---|---|
| **1** | `url_length` | Float | Total character length of URL | Phishing URLs are frequently elongated to obfuscate the real target or accommodate token tracking. |
| **2** | `domain_length` | Float | Total length of netloc/hostname | Long domain names often conceal brand names or multiple subdomains. |
| **3** | `path_length` | Float | Length of URL path component | Deep hierarchical paths are often used in credential-harvesting kits. |
| **4** | `count_dots` | Float | Number of `.` characters in URL | Excessive dots signify multiple subdomains used for domain spoofing. |
| **5** | `count_hyphens` | Float | Number of `-` characters | Attackers frequently hyphenate brand names (e.g., `paypal-security-update.com`). |
| **6** | `count_digits` | Float | Count of numeric characters in URL | High digit counts correlate with session hashes, IP addresses, or algorithmically generated patterns. |
| **7** | `count_subdomains` | Float | Subdomain depth | Attackers nest subdomains (e.g. `login.paypal.com.attacker.org`) to mislead mobile address bars. |
| **8** | `has_https` | Binary (0/1) | Uses HTTPS protocol | Legitimate websites overwhelmingly use HTTPS. |
| **9** | `has_http` | Binary (0/1) | Uses unencrypted HTTP | Credential forms over plain HTTP are high-risk indicators. |
| **10** | `has_ip_address` | Binary (0/1) | Hostname is an IPv4 or IPv6 address | Legitimate public companies almost never present raw IP addresses to consumers. |
| **11** | `count_at` | Float | Count of `@` symbols in URL | The `@` symbol causes browsers to ignore all preceding characters for routing, misleading users. |
| **12** | `count_percent` | Float | Count of `%` (URL encoded) symbols | Attackers encode characters to bypass simple pattern matching firewalls. |
| **13** | `count_underscore` | Float | Count of `_` characters | Uncommon in legitimate domain names; prevalent in script parameters. |
| **14** | `count_equal` | Float | Count of `=` symbols | Indicates query parameters carrying encoded user targets. |
| **15** | `count_question` | Float | Count of `?` symbols | Query string delimiter; multiple `?` indicate malformed or deceptive URLs. |
| **16** | `count_ampersand` | Float | Count of `&` symbols | Parameter chaining frequency. |
| **17** | `has_double_slash_path` | Binary (0/1) | Presence of `//` inside path | Used in open redirect exploits or to trick users into believing a different domain is active. |
| **18** | `num_parameters` | Float | Number of distinct query params | Deep parameter payloads are typical in phishing landing pages. |
| **19** | `url_entropy` | Float | Shannon entropy of URL string | High entropy indicates randomly generated hashes or obfuscation. |
| **20** | `domain_entropy` | Float | Shannon entropy of domain name | High domain entropy detects Domain Generation Algorithms (DGA) used by botnets. |
| **21** | `suspicious_keywords_count`| Float | Frequency of auth keywords | Keywords like `login`, `verify`, `banking`, `wallet`, `recover` indicate credential theft. |
| **22** | `brand_impersonation` | Binary (0/1) | Targeted brand found outside root domain | Flags presence of brands (`paypal`, `chase`, `google`) in subdomains or paths of untrusted hosts. |
| **23** | `is_shortened_url` | Binary (0/1) | Matches known URL shorteners | Shorteners (`bit.ly`, `tinyurl`) hide the final destination and lack transparency. |
| **24** | `has_punycode` | Binary (0/1) | Domain starts with `xn--` | IDN Homograph attack vector using Cyrillic or Greek characters to spoof Latin domains. |
| **25** | `has_homoglyphs` | Binary (0/1) | Character substitutions (`g00gle`, `paypa1`)| Detects leetspeak substitutions commonly used in typosquatting. |
| **26** | `tld_risk_score` | Binary (0/1) | Domain uses high-abuse TLD | TLDs like `.xyz`, `.top`, `.tk`, `.buzz`, `.club` have statistically higher abuse rates. |
| **27** | `digit_to_letter_ratio` | Float | Ratio of digits to alphabetic chars | Phishing URLs have a significantly higher ratio of numbers to letters. |
| **28** | `has_port` | Binary (0/1) | Non-standard port specified | Legitimate consumer services rarely use explicit ports (e.g. `:8080`, `:8888`). |
| **29** | `consecutive_hyphens` | Binary (0/1) | Presence of `--` in domain | Common in fake or spoofed domain registrations. |
| **30** | `tld_in_subdomain` | Binary (0/1) | Common TLD found in subdomain | Deceptive structure (e.g. `paypal.com.attacker.org`) tricking users into trusting the prefix. |

---

## Mathematical Formulation of Key Metrics

### Shannon Entropy Calculation
$$H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$
Where:
* $X$ is the URL or domain string.
* $P(x_i)$ is the empirical probability of character $x_i$ occurring in the string.
* High entropy ($H > 4.2$) indicates algorithmic randomness typical of DGAs.

### Digit-to-Letter Ratio
$$\text{Ratio} = \frac{\sum \text{digits}}{\max(1, \sum \text{alphabetic characters})}$$
A ratio $> 0.4$ strongly correlates with disposable infrastructure and malicious redirect chains.
