r'''
Parsing Email Module


'''
import mailbox
from email import message_from_file


#for .eml files parsing
from email import policy
from email.parser import BytesParser
from html.parser import HTMLParser

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

    eml_headers = ("Return-Path:", "From:", "To:", "Subject:", "Date:", "Forwarded:", "Replied:", "Received:", "Delivered-To:")
    if any(first_line.startswith(h) for h in eml_headers):
        return "eml"

    return "unknown"

def ParseMBox(path: str):
    '''Parse the mbox file and return a list of email messages
    '''
    mbox = mailbox.mbox(path)
    phishing_mailList = [message for message in mbox] 
    # for message in mbox:
    #     #Cleans payload text beforehand 
    #     SetBodyCleanText(message)
    #     phishing_mailList.append(message)

    #Returns the mbox in a list of mbox.Message
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

def TryDecode(decodeText:str, charset):
    r"""Tries to decode payload of mbox.
    Returns the string if it is able to decode, otherwise decode it in utf-8
    """
    returnString = ""
    try:
        returnString = decodeText.decode(charset or "utf-8", errors="replace")
    except:
        returnString = decodeText.decode("utf-8", errors="replace")
    return returnString


def SetBodyCleanText(msg: mailbox.mboxMessage)->str:
    '''Extract texts from an email message, handling both plain text and HTML parts,
    then subsequently set it as the new payload of the email message.'''
    plainText = htmlText = ""
    #urls = []
    for part in msg.walk():
        content_type = part.get_content_type()
        content_charset = part.get_content_charset()

        if content_type == "text/plain":
            plainText = TryDecode(part.get_payload(decode=True), content_charset)
        if content_type == "text/html":
            htmlText = TryDecode(part.get_payload(decode=True), content_charset)
            htmlText = strip_html(htmlText)
            #urls.extend(ud.extract_urls_from_text(html))
    
    plainText += htmlText
    cleanText = ' '.join(plainText.split())  # replace all whitespace sequences with single space
    #cleanText = cleanText.replace(". ", ".\n")  # put sentences on separate lines
    #urls.extend(ud.extract_urls_from_text(cleanText))
    #print(cleanText)
    msg.set_payload(cleanText)
    return cleanText

def GetPlainText(msg: mailbox.mboxMessage)->mailbox.mboxMessage:
    plainText = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                plainText = TryDecode(part.get_payload(decode=True), part.get_content_charset())
    else:
        plainText = msg.get_payload()
    return plainText