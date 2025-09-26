r'''
Scanning email module

'''

import mailbox
from email.header import decode_header
import os


def ScanEmail(email: mailbox.mboxMessage, urls: list=[])->int:
    '''Scan the email for suspicious words if there are suspicious words found it would check if it is the first 100 words of the email body.
    Decode the subject line of the email.
    '''
    #Decodes the subject line. If it does not need to be decoded it will still pass
    #risk score for subject and position based on the word doc
    subject = email['subject']
    subject = decode_header(subject)
    subject = ''.join(part.decode(charset or 'utf-8') if isinstance(part, bytes) else part for part, charset in subject)
    subject = subject.lower()
    #print(subject)
    riskScore = 0

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
    return riskScore
    #scanURLs(urls)


def SetSuspiciousWords(path: str):
    '''Set the list of suspicious words
    '''
    global suspiciouswords
    file = open(path, "r")
    suspiciouswords = file.read().splitlines()
    file.close()
    pass

suspiciouswords = [] 

if __name__=='__main__':
    riskScore = 0
    #print(os.getcwd())
                                   #initialize empty list
    SetSuspiciousWords("sampleWordList.txt")            #set the suspicious words from the file
    