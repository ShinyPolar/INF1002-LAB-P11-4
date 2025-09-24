from email import message_from_file
import mailbox
from html.parser import HTMLParser
from email.header import decode_header
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

def ScanEmail(email: mailbox.mboxMessage):
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
    #if msg.is_multipart():
    for part in msg.get_payload():
        if part.get_content_type() == "text/plain":
            plainText = part.get_payload(decode=True).decode(part.get_content_charset() or "utf-8", errors="replace")
        elif part.get_content_type() == "text/html":
            html = part.get_payload(decode=True).decode(part.get_content_charset() or "utf-8", errors="replace")
            htmlText = strip_html(html)
    plainText += htmlText
    cleanText = plainText.replace("\n", "").replace("\t", "")
    print(cleanText)
    msg.set_payload(cleanText)

    pass
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
    


    CleanText(emailToScan)                              #cleans the text of the email & remove the html if neccesary
    CheckWhitelistedDomain(emailToScan)                 #checks if the sender's domain is whitelisted
    # print(riskScore)
    ScanEmail(emailToScan)                              #scan the email for suspicious words
    print(riskScore)

    
