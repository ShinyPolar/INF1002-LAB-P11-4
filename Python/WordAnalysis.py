r'''
Module for calculating word weightage for suspicious word list
Uses Log Odds smoothign for its weight.


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
    for email in mailList:
        bodyString = email.get_payload()
        wordDict = CheckString(bodyString, wordDict)


def CheckWordsEML(mail: EmailMessage, wordDict: dict):
    '''
    checks the words in the eml body and subject\n
    if in the dictionary, it would increase the count\n
    If its not in the body, it then adds the word into the dictionary with a count of 1
    subject = mail['subject'] 
    for i in subject.split():
        clean = re.sub(r"(^\W+|\W+$)", "", i).lower()  # removes any special characters after and before the word
        if clean:
            if clean in wordDict:
                wordDict[clean] += 1

            else:
                wordDict[clean] = 1
    '''
    bodyMessage = mail # extracts the date, from, message-ID and body of email
    if bodyMessage:
        body = bodyMessage if isinstance(bodyMessage, str) else str(bodyMessage) # checks if the mail is a string if not will change into a string variable
        CheckString(body, wordDict)


def CheckString(string: str, wordDict: dict):
    
    for word in string.split():
            if not IsValidWord(word):
                continue
            if not word.isalnum():
                continue
            if word in wordDict:
                wordDict[word] += 1
            else:
                wordDict[word] = 1
    return wordDict


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

#  document frequencies (in how many emails the word appears)
def EmailFreq(emailList):
    

    emailFrequency = Counter()
    for email in emailList:
        wordList = email.get_payload().split(" ")
        emailFrequency.update(set(wordList))  # set -> document freq
    return emailFrequency

def LogOddsSmoothing():
    '''Calculate
    '''


    wordDict = {} #initialize empty dictionary
    wordDict = ConvertFileToDictionary("compiledWordList.txt")
    wordDict = CheckStopwords(wordDict, "stopWords.txt")
    wordDict = {w: c for w, c in wordDict.items() if IsValidWord(w)}

    phishingList = pe.ParseMBox("../phishing_dataset/phishing3.mbox")
    totalPhishingEmail = 0
    totalPhishingEmail = len(phishingList)

    for email in phishingList:
        pe.SetBodyCleanText(email)

    hamList = []
    directory = "..\easy_ham\easy_ham"
    totalHamEmail = 0
    for f in os.listdir(directory):
        file = os.path.join(directory, f)

        emailToScan = pe.ParseSingleEML(file)    #parse the sampleEmail to readable status for eml files
        pe.SetBodyCleanText(emailToScan)
        hamList.append(emailToScan)
        totalHamEmail += 1

    phishingWordFreq = EmailFreq(phishingList)
    hamWordFreq = EmailFreq(hamList)

    #Calculate email rates
    phishingRate = {}
    hamRate = {}
    score = {}
    for word in wordDict:
        phishingRate[word] = (phishingWordFreq[word] + 1) / (totalPhishingEmail + 2)
        hamRate[word] = (hamWordFreq[word] + 1) / (totalHamEmail + 2)
        weight = phishingRate[word] / hamRate[word]
        finalWeight = round(math.log10(weight) , 2)

        #remove words that have weightage to ham, not needed in this case
        if finalWeight < 0:
            continue
        score[word] = finalWeight


    
    WriteToFile(score, "wordWeightage.txt")
    return

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

def CheckStopwords(wordDict, path):


    f = open(path, "r")
    stopwordList = [line.strip() for line in f.readlines()]
    f.close()

    wordDictCopy = wordDict.copy()
    for word in wordDictCopy:
        if word in stopwordList:
            del wordDict[word]

    return wordDict


def IsValidWord(word)->bool:
    """Checks if it is a valid word to be compared against
    
    """
    # remove hex-like strings: 0x123abc
    if re.match(r"^0x[0-9A-Fa-f]+$", word):
        return False
    
    # remove words with digits
    if any(ch.isdigit() for ch in word):
        return False
    
    # remove very short codes (length <= 2)
    if len(word) <= 2:
        return False
    
    # removes tokens
    if word.isupper() and len(word) <= 4:
        return False

    return True

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

def GetEMLEmail(path, wordDict):
    for f in os.listdir(path):
        f = str(f)
        newpath = os.path.join(path, f)
        eml = pe.ParseSingleEML(newpath)
        clean = pe.SetBodyCleanText(eml)
        CheckWordsEML(clean, wordDict)

    return wordDict


if __name__=='__main__':
    
    wordDict = {}
    # ==========Compiling words from PhishingEmails===========
    # phishingList = pe.ParseMBox("../phishing_dataset/phishing3.mbox")
    # CheckWords(phishingList, wordDict)
    # WriteToFile(wordDict, "wordCount.txt")


    # ==========Compiling words from EasyHam============
    # wordDict = GetEMLEmail("..\easy_ham\easy_ham", wordDict)
    # WriteToFile(wordDict, "wordCountEasyHam.txt") 
    
    # ==========Compiling words from HardHam============
    # wordDict = GetEMLEmail("..\hard_ham\hard_ham", wordDict)
    # WriteToFile(wordDict, "wordCountHardHam.txt") 

    # ==========Compiling all the words=============
    # CompileWordList("wordCount.txt", "wordCountEasyHam.txt")
    # CompileWordList("compiledWordList.txt", "wordCountHardHam.txt")

    # LogOddsSmoothing()
    

#    print(type(ParseMBox("../INF1002-LAB-P11-4/phishing_dataset/phishing0.mbox")))
#    email = list(pe.ParseSingleEML("../INF1002-LAB-P11-4/easy_ham/easy_ham/0001.ea7e79d3153e7469e7a9c3e0af6a357e"))
    pass
