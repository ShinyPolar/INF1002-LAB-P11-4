r'''
This module provides a suite of functions for detecting suspicious URLs within
email content, a critical component of phishing detection systems. It analyzes
URLs for various characteristics commonly associated with malicious links.

The primary functionalities include:
- Extracting all URLs from the email body using regular expressions.
- Checking for domain mismatches, where the displayed link text differs from
  the actual destination domain (a strong phishing indicator).
- Performing WHOIS lookups to determine the age of a domain, flagging newly
  registered domains as high-risk.
- Detecting URLs that use an IP address instead of a domain name.
- Analyzing lexical features of URLs, such as excessive length, the presence
  of special characters like '@', hyphens in the domain, and an unusual
  number of subdomains.
- Aggregating the results of these checks into a single, cumulative risk score.

It leverages external libraries like `whois` for domain age checks and
'tldextract' for accurate domain parsing, alongside standard libraries like
're' and 'urllib'.
'''

import re
import whois
import tldextract
from datetime import datetime
from urllib.parse import urlparse
from ParseEmail import SetBodyCleanText

# Find all URLs in the text
def ExtractURLsFromText(text: str):
    """
    Extracts all URLs from a given string of text.

    This function uses a regular expression to find all substrings that match
    common URL patterns (starting with http://, https://, or www.).

    Args:
        text (str): The text to search for URLs.

    Returns:
        list: A list of URL strings found in the text.
    """
    # Matches http://, https://, or www.something
    urlPattern = r'(https?://[^\s]+|www\.[^\s]+)'
    urls = re.findall(urlPattern, text)
    return urls

def CheckDomainMismatch(email_msg):
    """
    Checks for mismatches between the displayed URL domain and the actual domain.

    It parses the email body, extracts all URLs, and compares the domain
    visible in the URL's netloc with the true registered domain extracted by
    tldextract. Mismatches are a strong indicator of phishing.

    Args:
        email_msg: The email message object to be analyzed.

    Returns:
        tuple: A tuple containing:
            - mismatches (list): A list of (claimedDomain, actualDomain) tuples.
            - actualDomains (list): A list of all actual domains found.
            - riskScore (int): The risk score contribution from domain mismatches.
    """
    riskScore = 0
    count = 0
    mismatches = []
    actualDomains = []

    cleanText = SetBodyCleanText(email_msg)
    # Ensure cleanText is a string if it comes as a list
    if isinstance(cleanText, list):
        cleanText = " ".join(cleanText)

    urls = ExtractURLsFromText(cleanText)

    for url in urls:
        url = url.strip(' "\'<>')  # clean up any surrounding characters

        # Extract actual domain using tldextract
        ext = tldextract.extract(url)
        actualDomain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
        actualDomain = actualDomain.lower()
        actualDomains.append(actualDomain)

        # Extract claimed domain from URL itself
        parsed = urlparse(url)
        claimedDomain = parsed.netloc.lower().lstrip("www.")

        # If claimed domain differs from actual domain, add risk
        if claimedDomain and claimedDomain != actualDomain:
            count+=1
            mismatches.append((claimedDomain, actualDomain))
    
    if count>=1:
        riskScore+=10

    # Debug print
    for claimed, actual in mismatches:
        print(f"Mismatch: Claimed '{claimed}' but actually goes to '{actual}'")

    return mismatches, actualDomains, riskScore

# Uses the whois module to find out how long ago the domain was registered
def GetDomainAge(domains):
    """
    Calculates a risk score based on the age of the domains.

    It performs a WHOIS lookup for each domain and assigns a risk score if
    any domain was registered less than one year ago, as newly created
    domains are often used for phishing.

    Args:
        domains (list): A list of domain strings to check.

    Returns:
        int: A risk score of 10 if a new domain is found, otherwise 0.
    """
    riskScore = 0
    try:
        for domain in domains:
            w = whois.whois(domain)
            creationDate = w.creationDate
            if isinstance(creationDate, list):
                creationDate = creationDate[0]
            if creationDate:
                ageYear = (datetime.now() - creationDate).days / 365
                if ageYear < 1:
                    riskScore = 10
                    return riskScore
    except Exception as e:
        print(f"WHOIS lookup failed for {domain}: {e}")
        riskScore = 10
    return riskScore

# Get domain from URL, removing www.
def GetDomain(urls):
    """
    Extracts the network location (domain) from a list of URLs.

    It parses each URL to get its netloc and removes the 'www.' prefix
    if present.

    Args:
        urls (list): A list of URL strings.

    Returns:
        list: A list of cleaned domain strings.
    """
    domains = []
    for url in urls:
        netloc = urlparse(url).netloc
        if netloc.startswith("www."):
            netloc = netloc[4:]  # remove www.
        domains.append(netloc.lower())
    return domains

# Check if URL contains an IP address
def URLContainsIP(urls): 
    """
    Checks if any URL in a list uses an IP address instead of a domain name.

    URLs containing IP addresses are suspicious and often used to bypass
    domain-based filters.

    Args:
        urls (list): A list of URL strings to check.

    Returns:
        int: A risk score of 10 if an IP address is found in any URL, otherwise 0.
    """
    ipaddPattern = r'((^\s*((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))\s*$)|(^\s*((([0-9a-fA-F]{1,4}:){7}([0-9a-fA-F]{1,4}|:))|(([0-9a-fA-F]{1,4}:){6}(:[0-9a-fA-F]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9a-fA-F]{1,4}:){5}(((:[0-9a-fA-F]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9a-fA-F]{1,4}:){4}(((:[0-9a-fA-F]{1,4}){1,3})|((:[0-9a-fA-F]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9a-fA-F]{1,4}:){3}(((:[0-9a-fA-F]{1,4}){1,4})|((:[0-9a-fA-F]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9a-fA-F]{1,4}:){2}(((:[0-9a-fA-F]{1,4}){1,5})|((:[0-9a-fA-F]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9a-fA-F]{1,4}:)(((:[0-9a-fA-F]{1,4}){1,6})|((:[0-9a-fA-F]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9a-fA-F]{1,4}){1,7})|((:[0-9a-fA-F]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$))'
    riskScore = 0
    count = 0
    domains = GetDomain(urls)
    for domain in domains:
        if re.search(ipaddPattern, domain):
            count+=1
    if count>=1:
        riskScore+=10
    return riskScore

# Checks the structure of the URL for suspicious traits
def LexicalFeatures(urls): 
    """
    Analyzes URLs for suspicious lexical features.

    This function checks for several common phishing URL traits:
    - Excessive length (> 75 characters).
    - Presence of the '@' symbol.
    - Use of hyphens in the domain name.
    - Excessive number of subdomains (more than 3 dots).

    Args:
        urls (list): A list of URL strings to analyze.

    Returns:
        int: A risk score of 10 if any suspicious feature is found, otherwise 0.
    """
    riskScore = 0
    count = 0
    domains = GetDomain(urls)

    for i in range(len(urls)):
        url = urls[i].strip(' "\'<>')
        domain = domains[i]

        if len(url) > 75: 
            count+=1
        if "@" in url: 
            count+=1
        if "-" in domain: 
            count+=1
        if domain.count('.') > 3: 
            count+=1
    if count>=1:
        riskScore+=10
    return riskScore

# Scan URLs and calculate risk score
def ScanURLs(urls,email_msg):
    """
    Orchestrates all URL-based security checks and calculates a total risk score.

    This function serves as the main entry point for URL analysis. It calls
    other functions to check for domain mismatches, IP addresses in URLs,
    suspicious lexical features, and new domain registrations.

    Args:
        urls (list): The list of URLs extracted from the email.
        email_msg: The original email message object, needed for mismatch checks.

    Returns:
        int: The total aggregated risk score from all URL checks.
    """
    if not urls:
            print("No URLs found.")
            return 0
    mismatches, actualDomains, domainMismatchScore = CheckDomainMismatch(email_msg)
    totalRisk = 0
    totalRisk += URLContainsIP(urls) + LexicalFeatures(urls) + domainMismatchScore + GetDomainAge(actualDomains)
    print("URL Risk Score:", totalRisk)
    print("URLs scanned:", urls)
    return totalRisk