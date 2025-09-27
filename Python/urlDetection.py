import re
from urllib.parse import urlparse
from main import CleanText
def extract_urls_from_text(text: str):
    # matches http://, https://, or www.something
    url_pattern = r'(https?://[^\s]+|www\.[^\s]+)'
    urls = re.findall(url_pattern, text)
    return urls

def check_domain_mismatch(email_msg):
    riskScore = 0
    mismatches = [] # store (claimed_domain, actual_domain)
    clean_text, urls = CleanText(email_msg)

    for url in urls:
        parsed_url = urlparse(url)
        actual_domain = parsed_url.netloc.lstrip("www.")

        # look for a claimed domain in the text near the URL
        claimed_domain = ""
        idx = clean_text.find(url)
        if idx != -1:
            snippet = clean_text[max(0, idx-50):idx]
            words = snippet.split()
            for w in reversed(words):
                if "." in w:
                    claimed_domain = w.lstrip("www.")
                    break

        if claimed_domain and claimed_domain.lower() != actual_domain.lower():
            riskScore += 15
            mismatches.append((claimed_domain, actual_domain))

    for claimed, actual in mismatches:
        print(f"Mismatch: Claimed '{claimed}' but actually goes to '{actual}'")
    return riskScore

#get domain from URL
def get_domain(urls):
    domains = []
    for url in urls:
        netloc = urlparse(url).netloc
        if netloc.startswith("www."):
            netloc = netloc[4:]  # remove www.
        domains.append(netloc.lower())
    return domains

# check if URL contains an IP address
ipadd_pattern = r'^((([0-9a-fA-F]{1,4}:){7}([0-9a-fA-F]{1,4}|:))|(([0-9a-fA-F]{1,4}:){6}(:[0-9a-fA-F]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9a-fA-F]{1,4}:){5}(((:[0-9a-fA-F]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9a-fA-F]{1,4}:){4}(((:[0-9a-fA-F]{1,4}){1,3})|((:[0-9a-fA-F]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9a-fA-F]{1,4}:){3}(((:[0-9a-fA-F]{1,4}){1,4})|((:[0-9a-fA-F]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9a-fA-F]{1,4}:){2}(((:[0-9a-fA-F]{1,4}){1,5})|((:[0-9a-fA-F]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9a-fA-F]{1,4}:)(((:[0-9a-fA-F]{1,4}){1,6})|((:[0-9a-fA-F]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9a-fA-F]{1,4}){1,7})|((:[0-9a-fA-F]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?$'

def url_contains_ip(urls):
    riskScore = 0
    domains = get_domain(urls)
    for domain in domains:
        if re.search(ipadd_pattern, domain):
            riskScore += 40
    return riskScore

def lexical_features(urls): 
    riskScore = 0
    domains = get_domain(urls)

    for i in range(len(urls)):
        url = urls[i].strip(' "\'<>')
        domain = domains[i]

        if len(url) > 75: 
            riskScore += 2
        if "@" in url: 
            riskScore += 1
        if "-" in domain: 
            riskScore += 1
        if domain.count('.') > 3: 
            riskScore += 1
    return riskScore
        
def scanURLs(urls,email_msg):
    if not urls:
        print("No URLs found.")
        return 0
    riskScore = url_contains_ip(urls) + lexical_features(urls) + check_domain_mismatch(email_msg)
    print("URL Risk Score:", riskScore)                             
    print("URLs scanned:", urls)
    return riskScore