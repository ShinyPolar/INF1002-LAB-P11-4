r'''
Scanning Email module
will be the place where it scans the email for suspicious words
and returns a risk score based on the findings

'''

import mailbox
from email.header import decode_header



suspiciouswords = [] 
riskScoreSubject = riskScoreBody = 0

def ScanEmail(email: mailbox.mboxMessage, urls: list=[])->int:
    '''Scan the email for suspicious words if there are suspicious words found it would check if it is the first 100 words of the email body.
    Decode the subject line of the email.
    '''
    

    ScanSubject(email)
    ScanBody(email)

    return riskScoreSubject + riskScoreBody
    #scanURLs(urls)

def ScanSubject(email: mailbox.mboxMessage):
    '''Scan the subject of the email for suspicious words, 
    adding to the risk score when necessary
    '''
    #Decodes the subject line. If it does not need to be decoded it will still pass
    #risk score for subject and position based on the word doc
    subject = email['subject']
    subject = decode_header(subject)
    subject = ''.join(part.decode(charset or 'utf-8') if isinstance(part, bytes) else part for part, charset in subject)
    subject = subject.lower()
    print(subject)

    global riskScoreSubject

    print(f"\n\nIn subject line:")
    for i in suspiciouswords:
        if i in subject:
            print(f"Found suspicious word '{i}' in subject line.")
            riskScoreSubject += 15
    pass

def ScanBody(email: mailbox.mboxMessage):
    '''Scan the body of the email for suspicious words, 
    adding to the risk score when necessary
    '''


    global riskScoreBody
    print(f"\n\nIn email body:")
    foundWords = []
    foundWords100 = []
    
    for word in suspiciouswords:
        if word in email.get_payload():
            foundWords.append(word)
            #potentially faster if using dictionary/list maybe?

            riskScoreBody += 1
            #place holder until we decide how riskScoring will work

            first_100_words = email.get_payload().split()
            first_100_words = first_100_words[:100]

            for position in first_100_words:
                if word == position:
                    foundWords100.append(word)
                    riskScoreBody += 10

    #Printing the results
    print(f"Found suspicious words in email body:")
    for i in range(len(foundWords)):
        if i < len(foundWords)-1:
            print(f"'{foundWords[i]}', ", end="")
        else:
            print(f"'{foundWords[i]}'", end="\n\n")
    
    print(f"Found in the first 100 words:")
    for i in range(len(foundWords100)):
        if i < len(foundWords100)-1:
            print(f"'{foundWords100[i]}', ", end="")
        else:
            print(f"'{foundWords100[i]}'", end="\n\n")
    pass

def SetSuspiciousWords(path: str):
    '''Set the list of suspicious words
    '''
    global suspiciouswords
    file = open(path, "r")
    suspiciouswords = file.read().splitlines()
    file.close()
    pass

