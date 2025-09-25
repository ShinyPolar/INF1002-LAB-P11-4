from email import message_from_file
import mailbox
from html.parser import HTMLParser
from email.header import decode_header
import re
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from email.utils import parseaddr

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

def ParseEmail(path: str):
    '''Parse a single email file and return the email message
    '''
    with open(path, "r") as f:
        email = message_from_file(f)
    return email

def CheckWhitelistedDomain(email):
    '''
    Check if the sender's email domain is in the whitelist.
    - If whitelisted: return the same riskScore.
    - If not whitelisted: add a penalty to the riskScore.
    
    Args:
        email: parsed email object (dict-like with "From" header).
    '''

    global riskScore
    penalty = 20

    #gets sender email address via the from header,
    sender = email.get("From")
    # print(f'Sender: {sender}')

    #if no sender from header, flag as suspicious and add penalty to risk score
    if not sender:
        print(f'\nSuspicious email detected. No sender found')
        riskScore+=penalty
        return

    #splits the from header into display name + email address
    dispName, addr = parseaddr(sender)
    # print(f'Display Name:{dispName}, Domain: {addr}')

    #if "@" not in addr, flag as suspicious and add penalty to risk score
    if "@" not in addr:
        print(f'\nSuspicious email detected. Sender email address ({addr}) does not contain @')
        riskScore+=penalty
        return

    #splits the email address into username and domain name, converts the domain name to lowercase and assign domain name to variable
    domain = addr.split("@")[-1].lower() 
    # print(WhitelistedDomains)
    
    #checks if domain name is in whitelist
    if domain not in [d.lower() for d in WhitelistedDomains]:
        print(f'\nSuspicious email detected. Sender email address ({addr}) is not whitelisted')
        riskScore+=penalty
        return
    else:
        #Does not add to risk score if sender email address is whitelisted
        print(f'\nSender email address ({addr}) is whitelisted')
    

def CheckWords(mailList: list, wordDict: dict):
    '''
    Check the words in the subject of the email in the list\n
    If the word is already in the dictionary, it increments the count by 1\n
    If the word is not in the dictionary, it adds the word to the dictionary with a count of 1
    '''
    for i in range(len(mailList)):
        #print(phishing_mailList[i]["subject"])
        for word in str(mailList[i]["subject"]).split(" "):
            if word in wordDict:
                wordDict[word] += 1
            else:
                wordDict.update({word:1})
    

def SortDict(wordDict: dict) -> dict:
    '''Sorts and returns the dictionary by amount in descending order
    '''
    sortedDict = dict(sorted(wordDict.items(), key=lambda item: item[1], reverse=True))
    return sortedDict

def WriteToFile(wordDict: dict):
    '''Write the dictionary to a file
    '''
    f = open("wordCount.txt", "w")
    for key, value in wordDict.items():
        try: #there was an encoding error here once
            f.write(f"{key}: {value}\n")
        except:
            continue
    f.close()

def ScanEmail(email: mailbox.mboxMessage, urls: list=[]):
    '''Scan the email for suspicious words if there are suspicious words found it would check if it is the first 100 words of the email body.
    Decode the subject line of the email.
    '''
    #Decodes the subject line. If it does not need to be decoded it will still pass
    #risck score for subject and position based on the word doc
    subject = email['subject']
    subject = decode_header(subject)
    subject = ''.join(part.decode(charset or 'utf-8') if isinstance(part, bytes) else part for part, charset in subject)
    subject = subject.lower()
#    print(subject)
    global riskScore

    print(f"\n\nIn subject line:")
    for i in suspiciouswords:
        if i in subject:
            print(f"Found suspicious word '{i}' in subject line.")
            riskScore += 15

    print(f"\n\nIn email body:")
    
    for word in suspiciouswords:
        if word in email.get_payload():
            #potentially faster if using dictionary/list maybe?

            print(f"Found suspicious word '{word}' in email.")
            # say out the word found
            
            riskScore += 1
            #place holder until we decide how riskScoring will work

            first_100_words = email.get_payload().split() 
            first_100_words = first_100_words[:100]

            for position in first_100_words:
                if word == position:
                    print(f"'{word}' is in the first 100 words of the email.\n")
                    riskScore += 10
    pass
    scanURLs(urls)


def SetSuspiciousWords(path: str):
    '''Set the list of suspicious words
    '''
    global suspiciouswords
    file = open(path, "r")
    suspiciouswords = file.read().splitlines()
    file.close()
    pass

def LoadWhitelistedDomains(filename: str) -> list:
    '''
    Reads a text file containing whitelisted domains (one per line)
    and stores them in the global WhitelistedDomains list.

    Args:
        filename: path to the text file

    Returns:
        The updated WhitelistedDomains list
    '''
    global WhitelistedDomains
    WhitelistedDomains.clear()  # reset before loading

    try:
        with open(filename, "r") as f:
            for line in f:
                domain = line.strip().lower()
                if domain and not domain.startswith("#"):  # skip blanks & comments
                    WhitelistedDomains.append(domain)
    except FileNotFoundError:
        print(f"Whitelist file '{filename}' not found.")
    except Exception as e:
        print(f"Error reading whitelist file: {e}")

    # print(WhitelistedDomains)
    return WhitelistedDomains

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
    
    suspiciouswords = []                                #initialize empty list
    SetSuspiciousWords("sampleWordList.txt")            #set the suspicious words from the file
    emailToScan = ParseSingleMbox("sampleEmail1.txt")   #parse the sampleEmail to readable status
    
    #PrintMultiPartMBox(emailToScan)

    #initialize whitelisted domains
    WhitelistedDomains = []
    LoadWhitelistedDomains("sampleWhitelistedDomains.txt")
    


    cleanText, urls = CleanText(emailToScan)            #cleans the text of the email & remove the html if neccesary
    CheckWhitelistedDomain(emailToScan)                 #checks if the sender's domain is whitelisted
    # print(riskScore)
    ScanEmail(emailToScan, urls)                        #scan the email for suspicious words
    check_domain_mismatch(emailToScan)    
    print(riskScore)
