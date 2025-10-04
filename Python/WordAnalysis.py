r'''



'''
import mailbox
from collections import Counter
#import numpy as np
import ParseEmail as pe
import os
import re
from email.message import EmailMessage
from email.header import decode_header
import math


def CheckWords(mailList: list, wordDict: dict):
    '''
    Check the words in the subject of the email in the list\n
    If the word is already in the dictionary, it increments the count by 1\n
    If the word is not in the dictionary, it adds the word to the dictionary with a count of 1
    '''
    for email in mailList:
        subjectString = str(email["subject"])
        #subjectString = decode_header(subjectString)
        if subjectString is None:
            continue
        wordDict = CheckString(subjectString, wordDict)
    
    '''
    Check the words in the body of the email in the list
    If the word is already in the dictionary, it increments the count by 1
    If the word is not in the dictionary, it adds the word to the dictionary with a count of 1
    '''
    count = 0
    for email in mailList:
        count += 1
        bodyString = pe.SetBodyCleanText(email)
        wordDict = CheckString(bodyString, wordDict)

    return count

def CheckString(string: str, wordDict: dict):
    for word in string.split():
            if word in wordDict:
                wordDict[word] += 1
            else:
                wordDict[word] = 1
    return wordDict


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


#===========TEST STUFF===============

#STEP 1: COUNT HOW MANY TIMES WORD APPEAR IN EMAIL

# compute document frequencies (in how many emails the word appears)
def email_freq(emailList):
    emailFrequency = Counter()
    for email in emailList:
        wordList = email.get_payload().split(" ")
        emailFrequency.update(set(wordList))  # set -> document freq
    return emailFrequency



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
    wordDict = ConvertFileToDictionary("compiledWordList.txt")

    phishingList = pe.ParseMBox("../phishing_dataset/phishing3.mbox")
    totalPhishingEmail = 0
    totalPhishingEmail = CheckWords(phishingList, wordDict)

    # wordDict = SortDict(wordDict)
    # WriteToFile(wordDict, "wordCount.txt")
    #print(email_freq(mboxDataset))
    
    #CompileWordList("wordCountEasyHam.txt", "wordCount.txt")
    #mbox = pe.ParseSingleMbox("sampleEmail1.txt")
    #text = pe.SetBodyCleanText(mbox)


    hamList = []
    directory = "..\easy_ham\easy_ham"
    totalHamEmail = 0
    for f in os.listdir(directory):
        file = os.path.join(directory, f)

        emailToScan = pe.ParseSingleEML(file)    #parse the sampleEmail to readable status for eml files
        pe.SetBodyCleanText(emailToScan)
        hamList.append(emailToScan)
        totalHamEmail += 1

    phishingWordFreq = email_freq(phishingList)
    hamWordFreq = email_freq(hamList)

    print("doing rate calculations now uwu")
    #Calculate email rates
    phishingRate = {}
    hamRate = {}
    for word in wordDict:
        phishingRate[word] = (phishingWordFreq[word] + 1) / (totalPhishingEmail + 2)
        hamRate[word] = (hamWordFreq[word] + 1) / (totalHamEmail + 2)


    #print("bank:", phishingRate["bank"], hamRate["bank"], phishingRate["bank"] / hamRate["bank"])
    # print("total ham email:", totalHamEmail)
    # print("total phishing email:", totalPhishingEmail)
    score = {}
    for word in wordDict:
        weight = float(0.0)
        weight = phishingRate[word] / hamRate[word]
        score[word] = round(math.log10(weight),3)
    WriteToFile(score, "wordWeightage.txt")



    # for f in os.listdir("../INF1002-LAB-P11-4/easy_ham/easy_ham/"):
    #     f = str(f)
    #     CheckWordsEML(pe.ParseSingleEML(oprint()s.path.join("../INF1002-LAB-P11-4/easy_ham/easy_ham/", f)), wordDict)
    
    # wordDict = SortDict(wordDict)
    # WriteToFile(wordDict, "wordCountEasyHam.txt") 
    
    

#    print(type(ParseMBox("../INF1002-LAB-P11-4/phishing_dataset/phishing0.mbox")))
#    email = list(pe.ParseSingleEML("../INF1002-LAB-P11-4/easy_ham/easy_ham/0001.ea7e79d3153e7469e7a9c3e0af6a357e"))
    pass
