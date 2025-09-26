from html.parser import HTMLParser
from email.header import decode_header
from email import message_from_file
import mailbox
import DomainChecks as dc
import ParseEmail as pe
    

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
    
    emailToScan = pe.ParseSingleMbox("sampleEmail2.txt")   #parse the sampleEmail to readable status
    #PrintMultiPartMBox(emailToScan)

    #initialize whitelisted domains
    WhitelistedDomains = dc.LoadWhitelistedDomains("sampleWhitelistedDomains.txt")
    
    #cleans the text of the email & remove the html if neccesary
    pe.CleanText(emailToScan)                             
    #print(emailToScan)

    #gets the senders email address from the "from" header in the email
    sender = dc.GetSender(emailToScan)
    #print(f'sender is:{sender}')

    #checks if the sender's domain is whitelisted
    dc.CheckWhitelistedDomain(sender,riskScore,WhitelistedDomains)                 
    #print(riskScore)
    ScanEmail(emailToScan)                              #scan the email for suspicious words
    print(riskScore)

    
