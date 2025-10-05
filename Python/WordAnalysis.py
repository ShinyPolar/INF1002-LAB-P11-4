r'''
Module for calculating word weightage for suspicious word list
Uses Log Odds smoothign for its weight.


'''
from collections import Counter
#import numpy as np
import ParseEmail as pe
import os
import re
from email.message import EmailMessage
import math


def CheckWords(mailList: list, wordList: list):
    r'''
    Check the words in the subject and body of all emails in the list
    Adds all unique words that are not stopwords, 
    and are valid with no special characters to the list
    '''

    #Checks the words in subject
    for email in mailList:
        subjectString = str(email["subject"])
        if subjectString is None:
            continue
        wordList = CheckString(subjectString, wordList)
    
    #Checks the words in body
    for email in mailList:
        bodyString = email.get_payload()
        wordList = CheckString(bodyString, wordList)

    #Checks for stopwords, and removes them if in list
    CheckStopwords(wordList, "Lists/stopWords.txt")


def CheckWordsEML(email: EmailMessage, wordList: list):
    r'''
    Checks the words in the eml body
    Adds all unique words that are not stopwords, 
    and are valid with no special characters to the list'''
    # subjectString = email['subject'] 
    # CheckString(subjectString, wordList)

    # Checks the words in body
    bodyMessage = email 
    if bodyMessage:
        body = bodyMessage if isinstance(bodyMessage, str) else str(bodyMessage) # checks if the mail is a string if not will change into a string variable
        CheckString(body, wordList)


def CheckString(string: str, wordList: list)-> list:
    r"""
    Checks the words in the string against the wordList
    Adds all unique words found into the wordList
    """
    for word in string.split():
            # Make sure its an actual word
            if not IsValidWord(word):
                continue
            if not word.isalpha():
                continue
            
            # Make sure its an unique word
            if word in wordList:
                continue
            else:
                wordList.append(word)

    return wordList


def WriteToFile(words, path:str):
    '''Write the dictionary/list to a file
    '''
    f = open(path, "w")

    if type(words) == list:
        for word in words:
            try: #catch any words that has weird encoding.
                word = word.strip()
                f.write(f"{word}\n")
            except:
                print("Word cannot be written out.")

    elif type(words) == dict:
        for key, value in words.items():
            try: #catch any words that has weird encoding.
                key = key.strip()
                f.write(f"{key}: {value}\n")
            except:
                print("Word cannot be written out.")

    else:
        print("Cannot write into file as format is not dict or list.")
    f.close()

def EmailFreq(emailList: list)-> Counter:
    r"""
    Computes email frequency of the words used.
    """

    emailFrequency = Counter()
    for email in emailList:
        wordList = email.get_payload().split(" ")
        emailFrequency.update(set(wordList))  # set -> document freq
    return emailFrequency



def CompileWordList(list1: list, list2: list):
    r"""Will add the 2 lists together for a compiled listing.
    Write the file out as compiledWordList.txt
    """
    wordList1 = ConvertFileToList(list1)
    wordList2 = ConvertFileToList(list2)

    compiledWords = wordList1.copy()
    for word in wordList2:
        if word in compiledWords:
            continue
        else:
            compiledWords.append(word)

    WriteToFile(compiledWords, "Lists\compiledWordList.txt")
    return

def CheckStopwords(wordList, path):
    r"""
    Checks and remove the words in the wordList against a list of Stopwords.
    Stopwords are words commonly used in the english language.
    eg. the, an, a, is, are, you, i, etc.
    """
    f = open(path, "r")
    stopwordList = [line.strip() for line in f.readlines()]
    f.close()

    wordListCopy = wordList.copy()
    for word in wordListCopy:
        if word.lower() in stopwordList:
            wordList.remove(word)

    return wordList


def IsValidWord(word: str)->bool:
    r"""
    Checks the word provided to see if it can be classified as a valid word.
    Returns true if it is.
    """
    # remove very short codes (length <= 2)
    if len(word) <= 2:
        return False
    
    # removes tokens
    if word.isupper() and len(word) <= 4:
        return False

    return True

def ConvertFileToList(path: str)-> list:
    r"""
    Converts the file provided at the path to a list.
    """

    wordList = []
    file = open(path, 'r')
    for line in file:
        # removes the character \n at the end of the line
        word = line.strip()
        wordList.append(word)
    file.close()
    return wordList

def CheckEMLEmail(path: str, wordList: list):
    r"""
    Checks the directory of eml emails provided for unique words.
    Returns the wordList after checking the EML emails.
    """
    for f in os.listdir(path):
        f = str(f)
        newpath = os.path.join(path, f)
        eml = pe.ParseSingleEML(newpath)
        clean = pe.SetBodyCleanText(eml)
        CheckWordsEML(clean, wordList)

    return wordList


def LogOddsSmoothing():
    r'''
    Calculates the weightage of all the words that appears in the emails
    using Log Odds Smoothing. Then writes it out as a file "wordWeightage.txt"
    '''

    # Get list of words from all emails
    wordList = []
    wordList = ConvertFileToList("Lists\compiledWordList.txt")

    # Get list of phishing emails
    phishingList = pe.ParseMBox("../phishing_dataset/phishing3.mbox")
    totalPhishingEmail = 0
    totalPhishingEmail = len(phishingList)

    # Get list of ham emails
    hamList = []
    directory = "..\easy_ham\easy_ham"
    totalHamEmail = 0
    for f in os.listdir(directory):
        file = os.path.join(directory, f)

        emailToScan = pe.ParseSingleEML(file)    #parse the sampleEmail to readable status for eml files
        pe.SetBodyCleanText(emailToScan)
        hamList.append(emailToScan)
        totalHamEmail += 1

    # Calculates phishing and ham frequency
    phishingWordFreq = EmailFreq(phishingList)
    hamWordFreq = EmailFreq(hamList)

    #Calculate how likely the word is in a phishing rather than ham
    phishingRate = {}
    hamRate = {}
    score = {}
    for word in wordList:
        phishingRate[word] = (phishingWordFreq[word] + 1) / (totalPhishingEmail + 2)
        hamRate[word] = (hamWordFreq[word] + 1) / (totalHamEmail + 2)
        weight = phishingRate[word] / hamRate[word]
        finalWeight = round(math.log10(weight) , 2)

        # Remove words that have weightage to ham, not needed in this case
        if finalWeight < 0:
            continue
        score[word] = finalWeight
        
    WriteToFile(score, "Lists\wordWeightage.txt")
    return


if __name__=='__main__':
    
    #wordList = []
    # ==========Compiling words from PhishingEmails===========
    # phishingList = pe.ParseMBox("../phishing_dataset/phishing3.mbox")
    # CheckWords(phishingList, wordList)
    # WriteToFile(wordList, "Lists/phishingWordList.txt")


    # ==========Compiling words from EasyHam============
    # wordList = CheckEMLEmail("..\easy_ham\easy_ham", wordList)
    # WriteToFile(wordList, "Lists/easyHamWordList.txt") 
    
    # ==========Compiling words from HardHam============
    # wordList = CheckEMLEmail("..\hard_ham\hard_ham", wordList)
    # WriteToFile(wordList, "Lists/hardHamWordList.txt") 

    # ==========Compiling all the words=============
    # CompileWordList("Lists\phishingWordList.txt", "Lists\easyHamWordList.txt")
    # CompileWordList("Lists\compiledWordList.txt", "Lists\hardHamWordList.txt")

    # LogOddsSmoothing()
    

#    print(type(ParseMBox("../INF1002-LAB-P11-4/phishing_dataset/phishing0.mbox")))
#    email = list(pe.ParseSingleEML("../INF1002-LAB-P11-4/easy_ham/easy_ham/0001.ea7e79d3153e7469e7a9c3e0af6a357e"))
    pass
