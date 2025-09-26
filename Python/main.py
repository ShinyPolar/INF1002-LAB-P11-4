from email import message_from_file
import mailbox
from html.parser import HTMLParser
from email.header import decode_header
import re
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from email.utils import parseaddr
import ScanEmail
import mailbox

#for .eml files parsing
from email import policy
from email.parser import BytesParser

#for handling multiple datasets in a directory
import os

import DomainChecks as dc #this is for whitelist check and edit distance check

class HTMLStripper(HTMLParser):
    def __init__(self):
        super().__init__()
        self.data = []
    def handle_data(self, d):
        self.data.append(d)
    def get_data(self):
        return ''.join(self.data)

def strip_html(html):
    s = HTMLStripper()
    s.feed(html)
    return s.get_data()

def detect_email_filetype(filepath: str) -> str:
    """
    Detect whether a file is in mbox or eml format.
    Returns: "mbox", "eml", or "unknown"
    """
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if line:  # skip blank lines
                first_line = line
                break
        else:
            return "unknown"  # empty file

    if first_line.startswith("From "):  # mbox separator line
        return "mbox"

    eml_headers = ("Return-Path:", "From:", "To:", "Subject:", "Date:")
    if any(first_line.startswith(h) for h in eml_headers):
        return "eml"

    return "unknown"

def ParseMBox(path: str):
    '''Parse the mbox file and return a list of email messages
    '''
    mbox = mailbox.mbox(path)
    phishing_mailList = [message for message in mbox] 
    #turn it into a list cause idk what format mbox is in
    return phishing_mailList

def ParseSingleMbox(path: str):
    '''Parse a single mbox file and return the email message
    '''
    mbox = mailbox.mbox(path)
    return mbox[0] #return the first email in the mbox file

def ParseSingleEML(path: str):
    """
    Parse a single .eml file and return an EmailMessage object.
    """
    with open(path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)
    return msg

def ParseEmail(path: str):
    '''Parse a single email file and return the email message
    '''
    with open(path, "r") as f:
        email = message_from_file(f)
    return email
    

def PrintMultiPartMBox(mbox: mailbox.mboxMessage):
    '''Print the parts of a multipart mbox file
    '''
    for part in mbox.get_payload():
        print(part)
        print("NEXT NEXT NEXT NEXT\n")

def CleanText(msg: mailbox.mboxMessage):
    '''Extract texts from an email message, handling both plain text and HTML parts,
    then subsequently set it as the new payload of the email message.'''
    plainText = htmlText = ""
    urls = []
    if msg.is_multipart():
        for part in msg.get_payload():
            if part.get_content_type() == "text/plain":
                plainText = part.get_payload(decode=True).decode(part.get_content_charset() or "utf-8", errors="replace")
            elif part.get_content_type() == "text/html":
                html = part.get_payload(decode=True).decode(part.get_content_charset() or "utf-8", errors="replace")
                htmlText = strip_html(html)

                urls.extend(extract_urls_from_text(html))
    else:
        content_type = msg.get_content_type()
        payload = msg.get_payload(decode=True).decode(msg.get_content_charset() or "utf-8", errors="replace")
        if content_type == "text/plain":
            plainText = payload
        elif content_type == "text/html":
            htmlText = strip_html(payload)
            urls.extend(extract_urls_from_text(htmlText))
    plainText += htmlText
    cleanText = plainText.replace("\n", "").replace("\t", "")

    urls.extend(extract_urls_from_text(cleanText))
    print(cleanText)
    msg.set_payload(cleanText)
    return cleanText, urls

def extract_urls_from_text(text: str):
    # matches http://, https://, or www.something
    url_pattern = r'(https?://[^\s]+|www\.[^\s]+)'
    urls = re.findall(url_pattern, text)
    return urls

def get_html_content(email):
    html_content = ""
    if email.is_multipart():
        for part in email.get_payload():
            if part.get_content_type() == "text/html":
                html_content = part.get_payload(decode=True).decode(part.get_content_charset() or "utf-8", errors="replace")
    else:
        if email.get_content_type() == "text/html":
            html_content = email.get_payload(decode=True).decode(email.get_content_charset() or "utf-8", errors="replace")
    return html_content

def check_domain_mismatch(email):
    global riskScore
    html_content = get_html_content(email)
    if not html_content:
        return
    soup = BeautifulSoup(html_content, "html.parser")
    for a in soup.find_all('a', href=True):
        actual_url = a['href'].strip()
        claimed_text = a.get_text().strip()
        # Parse claimed domain if it looks like a domain
        claimed_domain = urlparse("http://" + claimed_text).netloc.lstrip("www.") if "." in claimed_text else actual_url
        actual_domain = urlparse(actual_url).netloc.lstrip("www.")
        if claimed_domain.lower() != actual_domain.lower():
            riskScore += 15

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
    global riskScore
    domains = get_domain(urls)
    for domain in domains:
        if re.search(ipadd_pattern, domain):
            riskScore += 40

def lexical_features(urls): 
    global riskScore 
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
        
def scanURLs(urls):
    if not urls:
        return
    url_contains_ip(urls)                               # IP address check
    lexical_features(urls)                              # length > 75, "@", "-", "." checks
    print("URLs scanned:", urls)

if __name__=='__main__':
    #wordDict = {} #initialize empty dictionary
    #CheckWords(ParseMBox("../phishing_dataset/phishing0.mbox"), wordDict)
    #CheckWords(ParseMBox("../phishing_dataset/phishing1.mbox"), wordDict)
    #CheckWords(ParseMBox("../phishing_dataset/phishing2.mbox"), wordDict)
    #wordDict = SortDict(wordDict)
    #WriteToFile(wordDict)
    #everything above is for word frequency analysis, not yet finished
    #=========================================================================


    riskScore = 0
    
    #suspiciouswords = []                                #initialize empty list
    ScanEmail.SetSuspiciousWords("sampleWordList.txt")            #set the suspicious words from the file
    

    """  #to loop our email detection checklist through all files in a directory
    #WARNING!!!
    #Output might be messy as we have yet to sort out the print statements

    directory = "D:\JK\SIT ICT (IS)\Y1 Trimester 1\INF1002\Python Grp Proj\easy_ham\easy_ham"
    
    for f in os.listdir(directory):
        filepath = os.path.join(directory, f)
        print(filepath) 

        <move rest of the code below here. replace variable file with filepath>
        """

    
    file = "sampleEmail3.txt"
    filetype = detect_email_filetype(file) #checks if email is .mbox or .eml
    print(filetype)
    if filetype == "mbox":
        emailToScan = ParseSingleMbox(file)   #parse the sampleEmail to readable status for mbox files
        #PrintMultiPartMBox(emailToScan)
    elif filetype == "eml":
        emailToScan = ParseSingleEML(file)    #parse the sampleEmail to readable status for eml files
    

    #initialize whitelisted domains
    WhitelistedDomains = dc.LoadWhitelistedDomains("sampleWhitelistedDomains.txt")
    


    cleanText, urls = CleanText(emailToScan)      #cleans the text of the email & remove the html if neccesary

    sender = dc.GetSender(emailToScan) #gets sender email address from the "from" header in the email
    riskScore=dc.CheckWhitelistedDomain(sender,riskScore,WhitelistedDomains) #checks if the sender's domain is whitelisted and add to risk score if not
    print(riskScore)
    if riskScore > 0:#if email fails whitelist check
        riskScore=dc.check_sender_levenshtein(sender,WhitelistedDomains,riskScore) #edit distance check 
        print(riskScore)

    riskScore += ScanEmail.ScanEmail(emailToScan, urls)                        #scan the email for suspicious words
    check_domain_mismatch(emailToScan)    
    print(riskScore)