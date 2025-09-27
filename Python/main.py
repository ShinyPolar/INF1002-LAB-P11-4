from email import message_from_file
import mailbox
from html.parser import HTMLParser
from email.header import decode_header
from email.utils import parseaddr
#====INSTALL THE MODULES IN requirements.txt FIRST BEFORE RUNNING====
#====Alternatively, you can run the following command in your terminal:====
#pip install -r requirements.txt


#for .eml files parsing
from email import policy
from email.parser import BytesParser

#for handling multiple datasets in a directory
import os

#for whitelist check and edit distance check
import DomainChecks as dc
import urlDetection as ud
import ScanEmail as se

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

                urls.extend(ud.extract_urls_from_text(html))
    else:
        content_type = msg.get_content_type()
        payload = msg.get_payload(decode=True).decode(msg.get_content_charset() or "utf-8", errors="replace")
        if content_type == "text/plain":
            plainText = payload
        elif content_type == "text/html":
            htmlText = strip_html(payload)
            urls.extend(ud.extract_urls_from_text(htmlText))
    plainText += htmlText
    cleanText = plainText.replace("\n", "").replace("\t", "")

    urls.extend(ud.extract_urls_from_text(cleanText))
    print(cleanText)
    msg.set_payload(cleanText)
    return cleanText, urls

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
    se.SetSuspiciousWords("sampleWordList.txt")            #set the suspicious words from the file
    

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
    riskScore = dc.CheckWhitelistedDomain(sender,riskScore,WhitelistedDomains) #checks if the sender's domain is whitelisted and add to risk score if not
    print(riskScore)
    if riskScore > 0:#if email fails whitelist check
        riskScore = dc.check_sender_levenshtein(sender,WhitelistedDomains,riskScore) #edit distance check 
        print(riskScore)

    riskScore += se.ScanEmail(emailToScan, urls)                        #scan the email for suspicious words
    riskScore += ud.scanURLs(urls, email_msg=emailToScan)                               #scan the URLs in the email for suspicious features
    print(f'Total Risk Score: {riskScore}')