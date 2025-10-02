r'''



'''
import mailbox
from collections import Counter
#import numpy as np
import ParseEmail as pe
import os
import re
from email.message import EmailMessage


def CheckWords(mailList: list, wordDict: dict):
    '''
    Check the words in the subject of the email in the list\n
    If the word is already in the dictionary, it increments the count by 1\n
    If the word is not in the dictionary, it adds the word to the dictionary with a count of 1
    '''
    '''for i in range(len(mailList)):
        #print(phishing_mailList[i]["subject"])
        subjectString = str(mailList[i]["subject"])
        #subjectString = ' '.join(subjectString.split())
        for word in subjectString.split():
            if word in wordDict:
                wordDict[word] += 1
            else:
                wordDict.update({word:1})'''
    
    '''
    Check the words in the body of the email in the list\n
    If the word is already in the dictionary, it increments the count by 1\n
    If the word is not in the dictionary, it adds the word to the dictionary with a count of 1
    '''
    for message in mailList:
        payload = message.get_payload(decode=True)
        if payload:
            try:
                body = payload.decode(errors="ignore")
            except:
                body = str(payload)
            for word in body.split():
                word = word.strip().lower()
                if word in wordDict:
                    wordDict[word] += 1
                else:
                    wordDict[word] = 1


def ParseEML(mail: EmailMessage):  
    '''
    extract the plain text of the eml body       
    '''
    body = ""
    if mail.is_multipart():
        for part in mail.walk():
            content_type = part.get_content_type()
            content_disposition = part.get_content_disposition()

            if content_type == "text/plain" and content_disposition != "attachment":
                try:
                    body = part.get_payload(decode=True).decode(part.get_content_charset('utf-8'))
                except:
                    continue    
                break
    else:
        try:
            body = mail.get_payload(decode=True).decode(mail.get_content_charset('utf-8'))
        except:
            body = ""
    return body


def CheckWordsEML(mail: EmailMessage, wordDict: dict):
    '''
    checks the words in the eml body and subject\n
    if in the dictionary, it would increase the count\n
    If its not in the body, it then adds the word into the dictionary with a count of 1
    '''
    bodyMessage = ParseEML(mail) # extracts the date, from, message-ID and body of email
    if bodyMessage:
        body = bodyMessage if isinstance(bodyMessage, str) else str(bodyMessage) # checks if the mail is a string if not will change into a string variable
        for word in body.split():
            word =re.sub(r"(^\W+|\W+$)", "", word).lower() # removes any special characters after and before the word
            if word in wordDict:
                wordDict[word] += 1
            else:
                wordDict[word] = 1
    
 
    subject = mail['subject'] 
    for i in subject.split():
        clean = re.sub(r"(^\W+|\W+$)", "", i).lower()  # removes any special characters after and before the word
        if clean:
            if clean in wordDict:
                wordDict[clean] += 1

            else:
                wordDict[clean] = 1
    

def SortDict(wordDict: dict) -> dict:
    '''Sorts and returns the dictionary by amount in descending order
    '''
    sortedDict = dict(sorted(wordDict.items(), key=lambda item: item[1], reverse=True))
    return sortedDict


def WriteToFile(wordDict: dict, name):
    '''Write the dictionary to a file
    '''
    f = open(name, "w")
    for key, value in wordDict.items():
        try: #there was an encoding error here once
            key = key.strip()
            f.write(f"{key}: {value}\n")
        except:
            continue
    f.close()

def ParseMBox(path: str):
    '''Parse the mbox file and return a list of email messages
    '''
    mbox = mailbox.mbox(path)
    phishing_mailList = [message for message in mbox] 
    #turn it into a list cause idk what format mbox is in

    print(len(phishing_mailList))
    return phishing_mailList

#===========TEST STUFF===============

# compute document frequencies (in how many emails the word appears)
def doc_freq(docs):
    df = Counter()
    for d in docs:
        df.update(set(d))  # set -> document freq
    return df


def CompileWordList(hamS, phishingS):
    """Will add the 2 .txt together for a compiled listing

    """

    hamWords = ConvertFileToDictionary(hamS)
    phishWords = ConvertFileToDictionary(phishingS)

    compiledWords = hamWords.copy()
    for word, count in phishWords.items():
        if word in compiledWords:
            compiledWords[word] += count
        else:
            compiledWords[word] = count

    WriteToFile(compiledWords, "compiledWordList.txt")

    pass

def ConvertFileToDictionary(string)-> dict:
    wordDict = {}
    file = open(string, 'r')
    for line in file:
        word, count = line.split(": ")
        word = word.strip()
        count = int(count.strip())
        wordDict[word] = count

    file.close()
    return wordDict

if __name__=='__main__':
    wordDict = {} #initialize empty dictionary
    #CheckWords(ParseMBox("../phishing_dataset/phishing0.mbox"), wordDict)
    #CheckWords(ParseMBox("../phishing_dataset/phishing1.mbox"), wordDict)
    '''
    CheckWords(ParseMBox("../phishing_dataset/phishing3.mbox"), wordDict)
    wordDict = SortDict(wordDict)
    WriteToFile(wordDict, "wordCount.txt")
    '''
    CompileWordList("wordCountEasyHam.txt", "wordCount.txt")

    '''
    for f in os.listdir("../INF1002-LAB-P11-4/easy_ham/easy_ham/"):
        f = str(f)
        CheckWordsEML(pe.ParseSingleEML(os.path.join("../INF1002-LAB-P11-4/easy_ham/easy_ham/", f)), wordDict)
    
    wordDict = SortDict(wordDict)
    WriteToFile(wordDict, "wordCountEasyHam.txt") 
    
    '''

#    print(type(ParseMBox("../INF1002-LAB-P11-4/phishing_dataset/phishing0.mbox")))
#    email = list(pe.ParseSingleEML("../INF1002-LAB-P11-4/easy_ham/easy_ham/0001.ea7e79d3153e7469e7a9c3e0af6a357e"))
    pass
