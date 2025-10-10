r'''
This module provides a comprehensive toolkit for parsing email files,
including both `.mbox` and `.eml` formats. It is designed to extract key
information from raw email data, such as headers (sender, recipient),
and body content (plain text and HTML).

The module includes functionalities to:
- Automatically detect the email file format (mbox or eml).
- Parse entire mbox archives or single email files.
- Extract and decode text content, with robust handling for various character sets.
- Sanitize HTML content by stripping out tags, converting it to plain text.
- Provide easy access to specific parts of an email, like the sender's address,
  plain text body, or HTML body.

It leverages standard Python libraries like `mailbox`, `email`, and `html.parser`
to provide a reliable and structured way to process email messages for analysis.
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
    """
    A simple HTML parser class to strip HTML tags from a string.

    This class inherits from 'html.parser.HTMLParser' and overrides the
    'handle_data' method to collect all character data encountered, effectively
    ignoring all HTML tags.
    """
    def __init__(self):
        """Initializes the parser and a list to store data."""
        super().__init__()
        self.data = []
    def handle_data(self, d):
        """
        Collects character data from the HTML.

        Args:
            d (str): A chunk of character data.
        """
        self.data.append(d)
    def get_data(self):
        """
        Returns all collected character data as a single string.

        Returns:
            str: The concatenated, tag-free text.
        """
        return ''.join(self.data)

def strip_html(html):
    """
    Removes HTML tags from a given string of HTML.

    Args:
        html (str): The HTML string to be stripped.

    Returns:
        str: The plain text content from the HTML.
    """
    s = HTMLStripper()
    s.feed(html)
    return s.get_data()

def detect_email_filetype(filepath: str) -> str:
    """
    Determine whether an email file is in mbox or eml format.

    This function inspects the first non-blank line of the file to infer
    its format:
      - If the line begins with "From ", it is treated as an mbox file.
      - If the line begins with a standard email header (e.g., "From:", "To:", "Subject:",
        "Date:", "Forwarded:", "Replied:", "Received:", "Delivered-To:"),
        it is treated as an eml file.
      - Otherwise, the format is considered unknown.

    Args:
        filepath (str): Path to the email file to be checked.

    Returns:
        str: One of:
            - "mbox" if the file appears to be in mbox format.
            - "eml" if the file appears to be in eml format.
            - "unknown" if the format cannot be determined (e.g., empty file or unrecognized header).
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
    """
    Parses an mbox file and returns a list of email message objects.

    Args:
        path (str): The file path to the mbox archive.

    Returns:
        list: A list of 'mailbox.mboxMessage' objects, where each object
              represents an email in the archive.
    """
    mbox = mailbox.mbox(path)
    phishing_mailList = [message for message in mbox] 
    # for message in mbox:
    #     #Cleans payload text beforehand 
    #     SetBodyCleanText(message)
    #     phishing_mailList.append(message)

    #Returns the mbox in a list of mbox.Message
    return phishing_mailList

def ParseSingleMbox(path: str):
    """
    Parses an mbox file and returns only the first email message.

    This is useful for mbox files that are known to contain only one email.

    Args:
        path (str): The file path to the mbox file.

    Returns:
        mailbox.mboxMessage: The first email message object found in the mbox file.
    """
    mbox = mailbox.mbox(path)
    return mbox[0] #return the first email in the mbox file

def ParseSingleEML(path: str):
    """
    This function reads the raw contents of an email file in RFC 822 format
    and parses it into a structured 'EmailMessage' object using the
    'email.parser.BytesParser' with the default policy.

    Args:
        path (str): The filesystem path to the '.eml' file to be parsed.

    Returns:
        EmailMessage: A parsed email message object containing headers,
        body, and attachments (if any).
    """
    with open(path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)
    return msg

def TryDecode(decodeText:str, charset):
    """
    Attempts to decode a byte string using a specified charset, with a fallback to UTF-8.

    This function is designed to handle potential decoding errors gracefully by
    first trying the provided charset and then falling back to 'utf-8' if the
    initial attempt fails.

    Args:
        decodeText (bytes): The byte string to decode.
        charset (str): The character set to try first (e.g., 'iso-8859-1').

    Returns:
        str: The decoded string.
    """
    returnString = ""
    try:
        returnString = decodeText.decode(charset or "utf-8", errors="replace")
    except:
        returnString = decodeText.decode("utf-8", errors="replace")
    return returnString


def SetBodyCleanText(msg: EmailMessage)->str:
    """
    Extracts, cleans, and sets the plain text body of an email message.

    This function walks through all parts of an email message, extracts both
    'text/plain' and 'text/html' content, strips HTML tags from the latter,
    combines them, and then replaces the message's payload with this unified,
    clean text.

    Args:
        msg (EmailMessage): The email message object to process.

    Returns:
        str: The cleaned and combined plain text content.
    """
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
    """
    Extracts the plain text content from an email message.

    It walks through the message parts and returns the content of the first
    part with a 'text/plain' content type.

    Args:
        msg (EmailMessage): The email message object.

    Returns:
        str: The plain text content, or an empty string if not found.
    """
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
    """
    Extracts the raw HTML content from an email message.

    It walks through the message parts and returns the content of the first
    part with a 'text/html' content type.

    Args:
        msg (EmailMessage): The email message object.

    Returns:
        str: The raw HTML content, or an empty string if not found.
    """
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
    """
    Extracts and strips the HTML content from an email message.

    It finds the 'text/html' part of the message, decodes it, and removes
    all HTML tags, returning the resulting plain text.

    Args:
        msg (EmailMessage): The email message object.

    Returns:
        str: The cleaned (tag-stripped) text from the HTML part, or an
             empty string if no HTML part is found.
    """
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
    """
    Extract Sender from the email.
    
    Args:
        email (EmailMessage): parsed email object (dict-like with "From" header).

    Returns:
        Email address of sender(string)
    """
    #gets sender information via the from header, this consists of sender display name + email address
    sender = email.get("From") or email.get("from")

    #splits the from header into sender display name [index 0] + email address [index 1], and assigns email address to addr
    addr = parseaddr(sender)[1]
    return addr

def GetRecepient(email: EmailMessage)->str:
    """
    Extracts the recipient's address from the 'To' header of an email message.

    Args:
        msg (EmailMessage): The parsed email message object.

    Returns:
        str: The content of the 'To' header, which may include the
             recipient's name and email address.
    """
    recepient = email.get("To") or email.get("to")

    return recepient