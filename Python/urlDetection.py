import re
import whois
import tldextract
from datetime import datetime
from urllib.parse import urlparse
from ParseEmail import SetBodyCleanText

def ExtractURLsFromText(text: str):
    # matches http://, https://, or www.something
    urlPattern = r'(https?://[^\s]+|www\.[^\s]+)'
    urls = re.findall(urlPattern, text)
    return urls

def CheckDomainMismatch(email_msg):
    """
    Checks for mismatches between the claimed domain (in URL) and actual domain.
    Returns:
        mismatches: list of tuples (claimedDomain, actualDomains)
        actualDomains: list of all actual domains found
        riskScore: total risk score from domain mismatches
    """
    riskScore = 0
    mismatches = []
    actualDomains = []

    cleanText = SetBodyCleanText(email_msg)
    urls = ExtractURLsFromText(cleanText)
    # Ensure cleanText is a string if it comes as a list
    if isinstance(cleanText, list):
        cleanText = " ".join(cleanText)

    for url in urls:
        url = url.strip(' "\'<>')  # clean up any surrounding characters

        # Extract actual domain using tldextract
        ext = tldextract.extract(url)
        actualDomain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
        actualDomain = actualDomain.lower()
        if not actualDomains:
            continue
        actualDomains.append(actualDomain)

        # Extract claimed domain from URL itself
        parsed = urlparse(url)
        claimedDomain = parsed.netloc.lower().lstrip("www.")

        # If claimed domain differs from actual domain, add risk
        if claimedDomain and claimedDomain != actualDomains:
            riskScore += 15
            mismatches.append((claimedDomain, actualDomains))

    # Debug print
    for claimed, actual in mismatches:
        print(f"Mismatch: Claimed '{claimed}' but actually goes to '{actual}'")

    return mismatches, actualDomains, riskScore

def GetDomainAge(domains):
    riskScore = 0
    try:
        for domain in domains:
            w = whois.whois(domain)
            creationDate = w.creationDate
            if isinstance(creationDate, list):
                creationDate = creationDate[0]
            if creationDate:
                ageYear = (datetime.now() - creationDate).days / 365
                if ageYear < 1 and ageYear == 0:
                    riskScore = 20
                    return riskScore
    except Exception as e:
        print(f"WHOIS lookup failed for {domain}: {e}")
    return riskScore

#get domain from URL
def GetDomain(urls):
    domains = []
    for url in urls:
        netloc = urlparse(url).netloc
        if netloc.startswith("www."):
            netloc = netloc[4:]  # remove www.
        domains.append(netloc.lower())
    return domains

# check if URL contains an IP address
ipaddPattern = r'^((([0-9a-fA-F]{1,4}:){7}([0-9a-fA-F]{1,4}|:))|(([0-9a-fA-F]{1,4}:){6}(:[0-9a-fA-F]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9a-fA-F]{1,4}:){5}(((:[0-9a-fA-F]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9a-fA-F]{1,4}:){4}(((:[0-9a-fA-F]{1,4}){1,3})|((:[0-9a-fA-F]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9a-fA-F]{1,4}:){3}(((:[0-9a-fA-F]{1,4}){1,4})|((:[0-9a-fA-F]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9a-fA-F]{1,4}:){2}(((:[0-9a-fA-F]{1,4}){1,5})|((:[0-9a-fA-F]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9a-fA-F]{1,4}:)(((:[0-9a-fA-F]{1,4}){1,6})|((:[0-9a-fA-F]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9a-fA-F]{1,4}){1,7})|((:[0-9a-fA-F]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?$'

def URLContainsIP(urls):
    riskScore = 0
    domains = GetDomain(urls)
    for domain in domains:
        if re.search(ipaddPattern, domain):
            riskScore += 40
    return riskScore

def LexicalFeatures(urls): 
    riskScore = 0
    domains = GetDomain(urls)

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

def LoadBlacklist():
    file_path="Domains/sampleBlacklistedDomains.txt"
    try:
        with open(file_path, "r") as f:
            # convert all to lowercase and ignore empty lines
            return {line.strip().lower() for line in f if line.strip()}
    except FileNotFoundError:
        print("File not found.")
        return set()

def CheckBlacklist(domains):
    riskScore = 0
    matches = []
    blacklist = LoadBlacklist()

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
    domains = GetDomain(urls)
    mismatches, actualDomains, domainMismatchScore = CheckDomainMismatch(email_msg)
    blacklist = LoadBlacklist()
    blacklistScore, blacklistedDomains = CheckBlacklist(domains)
    totalRisk = 0
    totalRisk += URLContainsIP(urls) + LexicalFeatures(urls) + domainMismatchScore + GetDomainAge(actualDomains) + blacklistScore
    print("URL Risk Score:", totalRisk)
    print("URLs scanned:", urls)
    return totalRisk