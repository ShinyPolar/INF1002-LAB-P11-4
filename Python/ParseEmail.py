r'''
Parsing Email Module


'''
import mailbox
from email import message_from_file
from email.message import EmailMessage
from email.utils import parseaddr

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


def SetBodyCleanText(msg: EmailMessage)->str:
    '''Extract texts from an email message, handling both plain text and HTML parts,
    then subsequently set it as the new payload of the email message.'''
    plainText = htmlText = ""
    for part in msg.walk():
        content_type = part.get_content_type()
        content_charset = part.get_content_charset()

        if content_type == "text/plain":
            plainText = TryDecode(part.get_payload(decode=True), content_charset)
        if content_type == "text/html":
            htmlText = TryDecode(part.get_payload(decode=True), content_charset)
            htmlText = strip_html(htmlText)
            # urls.extend(ud.extract_urls_from_text(htmlText))
    
    plainText += htmlText
    cleanText = ' '.join(plainText.split())  # replace all whitespace sequences with single space
    #cleanText = cleanText.replace(". ", ".\n")  # put sentences on separate lines
    #print(cleanText)
    msg.set_payload(cleanText)
    return cleanText

def GetPlainText(msg: EmailMessage)->str:
    plainText = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                plainText = TryDecode(part.get_payload(decode=True), part.get_content_charset())
    elif msg.get_content_type() == "text/plain":
        plainText = msg.get_payload()
    else:
        plainText = ""
    return plainText

def GetHTMLText(msg: EmailMessage)->str:
    htmlText = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/html":
                htmlText = TryDecode(part.get_payload(decode=True), part.get_content_charset())
    elif msg.get_content_type() == "text/html":
        htmlText = msg.get_payload()
    else:
        htmlText = ""
    return htmlText

def GetCleanHTMLText(msg: EmailMessage)->str:
    cleanHTMLText = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/html":
                cleanHTMLText = TryDecode(part.get_payload(decode=True), part.get_content_charset())
                cleanHTMLText = strip_html(cleanHTMLText)
    elif msg.get_content_type() == "text/html":
        cleanHTMLText = msg.get_payload()
        cleanHTMLText = strip_html(cleanHTMLText)
    else:
        cleanHTMLText = ""
    return cleanHTMLText

    return
def GetSender(email)->str:
    '''
    Extract Sender from the email.
    
    Args:
        email: parsed email object (dict-like with "From" header).

    Returns:
        Email address of sender
    '''
    #gets sender information via the from header, this consists of sender display name + email address
    sender = email.get("From") or email.get("from")

    #splits the from header into sender display name [index 0] + email address [index 1], and assigns email address to addr
    addr = parseaddr(sender)[1]
    return addr

def GetRecepient(msg: EmailMessage)->str:
    '''
    Gets recepient from email
    '''
    sender = msg.get("To") or msg.get("to")

    return sender