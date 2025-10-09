r'''
Scanning Email module
will be the place where it scans the email for suspicious words
and returns a risk score based on the findings

'''

import mailbox
import os
from email.header import decode_header
import ParseEmail as pe



suspiciousWords = {}
riskScoreSubject = float(0.0)
riskScoreBody = float(0.0)
def ScanEmail(email: mailbox.mboxMessage, urls: list=[])->int:
    '''Scan the email for suspicious words if there are suspicious words found it would check if it is the first 30 words of the email body.
    Decode the subject line of the email.
    '''
    #Reinitialize the risk scores for subject and body
    global riskScoreSubject, riskScoreBody
    riskScoreSubject = riskScoreBody = 0

    ScanSubject(email)
    ScanBody(email)
    print(f"risk: {riskScoreSubject}, risk: {riskScoreBody}")

    #Clamp values
    riskScore = int(riskScoreSubject+riskScoreBody)
    riskScore = max(0, min(riskScore, 30))
    return riskScore
    #scanURLs(urls)

def ScanSubject(email: mailbox.mboxMessage):
    '''Scan the subject of the email for suspicious words, 
    adding to the risk score when necessary
    '''
    #Decodes the subject line. If it does not need to be decoded it will still pass
    #risk score for subject and position based on the word doc
    subject = email['subject']

    # Theres a problem here for dataset no.159 from hard_ham where TypeError: expected string or bytes-like object, got 'NoneType'
    subject = decode_header(subject)
    
    # Theres a problem here for dataset no.2132 from easy_ham where the encoding is unknown-8(or smthg liddat)
    subject = ''.join(part.decode(charset or 'utf-8') if isinstance(part, bytes) else part for part, charset in subject)
    #subject = subject.lower()
    print(subject)

    global riskScoreSubject

    print(f"\n\nIn subject line:")
    for word, weightage in suspiciousWords.items():
        if word == subject:
            print(f"Found suspicious word '{word}' in subject line.")
            riskScoreSubject += 3 * weightage
    pass

def ScanBody(email: mailbox.mboxMessage):
    '''Scan the body of the email for suspicious words, 
    adding to the risk score when necessary
    '''


    global riskScoreBody
    foundWords = []
    foundWords30 = []
    textToScan = pe.GetPlainText(email)
    if not textToScan:
        textToScan = pe.GetCleanHTMLText(email) 
    textToScanList = textToScan.split()
    for word, weightage in suspiciousWords.items():
        if word in textToScanList:
            foundWords.append(word)
            #potentially faster if using dictionary/list maybe?

            riskScoreBody += 1 * weightage
            #place holder until we decide how riskScoring will work

            #first30Words = textToScan.split()
            first30Words = textToScanList[:30]

            for position in first30Words:
                if word == position:
                    foundWords30.append(word)
                    riskScoreBody += 3 * weightage


    
    #Printing the results
    print(f"\n\nIn email body:")
    print(f"Found suspicious words:")
    for i in range(len(foundWords)):
        if i < len(foundWords)-1:
            print(f"'{foundWords[i]}', ", end="")
        else:
            print(f"'{foundWords[i]}'", end="\n\n")

    #If no suspicious words were found in the first 30 words, we can skip this section
    if not foundWords30:
        return
    print(f"Found in the first 30 words:")
    for i in range(len(foundWords30)):
        if i < len(foundWords30)-1:
            print(f"'{foundWords30[i]}', ", end="")
        else:
            print(f"'{foundWords30[i]}'", end="\n\n")
    return

def SetSuspiciousWords(file: str):
    '''Set the dictionary of suspicious words
    '''
    global suspiciousWords
    filepath = os.path.join("Lists", file)
    with open(filepath, "r", encoding="latin-1") as textfile:
        for line in textfile:
            word, weightage = line.split(": ")
            word = word.strip()
            weightage = float(weightage.strip())
            suspiciousWords[word] = weightage
        textfile.close()
    pass

