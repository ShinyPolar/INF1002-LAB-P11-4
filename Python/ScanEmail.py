r'''
Scanning Email module
will be the place where it scans the email for suspicious words
and returns a risk score based on the findings

Key functionalities include:
- Setting the suspicious words with weightage from a text file
- Scanning the subject line for suspicious words
- Scanning the body of the email for suspicious words
'''

import os
from email.header import decode_header
import ParseEmail as pe
from email.message import EmailMessage



suspiciousWords = {}
riskScoreSubject = float(0.0)
riskScoreBody = float(0.0)
def ScanEmail(email: EmailMessage)->int:
    '''Scan the email for suspicious words if there are suspicious words found it would check if it is the first 30 words of the email body.
    Decode the subject line of the email.

    Args:
        email: Email in the format EmailMessage to scan

    Returns:
        The risk score of the email based on the findings
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

def ScanSubject(email: EmailMessage):
    '''Scan the subject of the email for suspicious words, 
    adding to the risk score when necessary
    
    Args:
        email: Email in the format EmailMessage to scan

    '''
    #Decodes the subject line. If it does not need to be decoded it will still pass
    subject = email['subject']

    subject = decode_header(subject)
    
    subject = ''.join(part.decode(charset or 'utf-8') if isinstance(part, bytes) else part for part, charset in subject)
    print(subject)

    #Risk score for subject and position based on the wordWeightage.txt
    #Loops through the words in WordWeightage.txt, 
    # if word is found will be added to risk score
    global riskScoreSubject

    print(f"\n\nIn subject line:")
    for word, weightage in suspiciousWords.items():
        if word == subject:
            print(f"Found suspicious word '{word}' in subject line.")
            riskScoreSubject += 10 * weightage
    pass

def ScanBody(email: EmailMessage):
    '''Scan the body of the email for suspicious words, 
    adding to the risk score when necessary

    Args:
        email: Email in the format EmailMessage to scan

    '''


    global riskScoreBody
    foundWords = []
    foundWords30 = []

    #Get the plain text of the email, if it is not available get the clean HTML text
    textToScan = pe.GetPlainText(email)
    if not textToScan:
        textToScan = pe.GetCleanHTMLText(email) 
    textToScanList = textToScan.split()

    #Risk score for body and position based on the wordWeightage.txt
    for word, weightage in suspiciousWords.items():
        if word in textToScanList:
            foundWords.append(word) #If word is found would be added to foundWords list

            #add to risk score
            riskScoreBody += 5 * weightage

            #check if it is in the first 30 words, then add to risk score again
            first30Words = textToScanList[:30]
            for position in first30Words:
                if word == position:
                    foundWords30.append(word)
                    riskScoreBody += 5 * weightage


    
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
    '''Sets the dictionary of suspicious words with weightage
    
    Args:
        email: Email in the format EmailMessage to scan

    '''
    global suspiciousWords
    filepath = os.path.join("Lists", file)
    with open(filepath, "r") as textfile:
        for line in textfile:
            # Splits the line into word and weightage through a common delimiter ": "
            word, weightage = line.split(": ")
            word = word.strip()
            weightage = float(weightage.strip())
            suspiciousWords[word] = weightage
        textfile.close()
    pass

