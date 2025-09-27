import mailbox
from html.parser import HTMLParser
#====INSTALL THE MODULES IN requirements.txt FIRST BEFORE RUNNING====
#====Alternatively, you can run the following command in your terminal:====
#pip install -r requirements.txt



#for handling multiple datasets in a directory
import os

#for Module imports
import DomainChecks as dc
import urlDetection as ud
import ScanEmail as se
import ParseEmail as pe

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
    cleanText = ' '.join(plainText.split())  # replace all whitespace sequences with single space
    cleanText = cleanText.replace(". ", ".\n")  # put sentences on separate lines
    urls.extend(ud.extract_urls_from_text(cleanText))
    print(cleanText)
    msg.set_payload(cleanText)
    return cleanText, urls



if __name__=='__main__':


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
    filetype = pe.detect_email_filetype(file) #checks if email is .mbox or .eml
    print(filetype)
    if filetype == "mbox":
        emailToScan = pe.ParseSingleMbox(file)   #parse the sampleEmail to readable status for mbox files
        #PrintMultiPartMBox(emailToScan)
    elif filetype == "eml":
        emailToScan = pe.ParseSingleEML(file)    #parse the sampleEmail to readable status for eml files

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