import re
import whois
import tldextract
from datetime import datetime
from urllib.parse import urlparse
from ParseEmail import SetBodyCleanText

def extract_urls_from_text(text: str):
    # matches http://, https://, or www.something
    url_pattern = r'(https?://[^\s]+|www\.[^\s]+)'
    urls = re.findall(url_pattern, text)
    return urls

def check_domain_mismatch(email_msg):
    """
    Checks for mismatches between the claimed domain (in URL) and actual domain.
    Returns:
        mismatches: list of tuples (claimed_domain, actual_domain)
        actual_domains: list of all actual domains found
        riskScore: total risk score from domain mismatches
    """
    riskScore = 0
    mismatches = []
    actual_domains = []

    clean_text = SetBodyCleanText(email_msg)
    urls = extract_urls_from_text(clean_text)
    # Ensure clean_text is a string if it comes as a list
    if isinstance(clean_text, list):
        clean_text = " ".join(clean_text)

    for url in urls:
        url = url.strip(' "\'<>')  # clean up any surrounding characters

        # Extract actual domain using tldextract
        ext = tldextract.extract(url)
        actual_domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
        actual_domain = actual_domain.lower()
        if not actual_domain:
            continue
        actual_domains.append(actual_domain)

        # Extract claimed domain from URL itself
        parsed = urlparse(url)
        claimed_domain = parsed.netloc.lower().lstrip("www.")

        # If claimed domain differs from actual domain, add risk
        if claimed_domain and claimed_domain != actual_domain:
            riskScore += 15
            mismatches.append((claimed_domain, actual_domain))

    # Debug print
    for claimed, actual in mismatches:
        print(f"Mismatch: Claimed '{claimed}' but actually goes to '{actual}'")

    return mismatches, actual_domains, riskScore

def get_domain_age(domains):
    riskScore = 0
    try:
        for domain in domains:
            w = whois.whois(domain)
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            if creation_date:
                age_year = (datetime.now() - creation_date).days / 365
                if age_year < 1:
                    riskScore = 20
                    return riskScore
    except Exception as e:
        print(f"WHOIS lookup failed for {domain}: {e}")
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

def load_blacklist():
    file_path="/Domains/sampleBlacklistedDomains.txt"
    try:
        with open(file_path, "r") as f:
            # convert all to lowercase and ignore empty lines
            return {line.strip().lower() for line in f if line.strip()}
    except FileNotFoundError:
        print("File not found.")
        return set()

def check_blacklist(domains):
    riskScore = 0
    matches = []
    blacklist = load_blacklist()

    for domain in domains:
        if domain.lower() in blacklist:
            riskScore += 15  
            matches.append(domain)

    if matches:
        print(f"Blacklisted domains detected in URL: {matches}")
    return riskScore, matches


def scanURLs(urls,email_msg):
    if not urls:
            print("No URLs found.")
            return 0
    domains = get_domain(urls)
    mismatches, actual_domains, domain_mismatch_score = check_domain_mismatch(email_msg)
    blacklist = load_blacklist()
    blacklist_score, blacklisted_domains = check_blacklist(domains)
    total_risk = 0
    total_risk += url_contains_ip(urls) + lexical_features(urls) + domain_mismatch_score + get_domain_age(actual_domains) + blacklist_score
    print("URL Risk Score:", total_risk)
    print("URLs scanned:", urls)
    return total_risk

