r'''



'''
import mailbox
from collections import Counter
import numpy as np
import ParseEmail as pe


def CheckWords(mailList: list, wordDict: dict):
    '''
    Check the words in the subject of the email in the list\n
    If the word is already in the dictionary, it increments the count by 1\n
    If the word is not in the dictionary, it adds the word to the dictionary with a count of 1
    '''
    for i in range(len(mailList)):
        #print(phishing_mailList[i]["subject"])
        subjectString = str(mailList[i]["subject"])
        #subjectString = ' '.join(subjectString.split())
        for word in subjectString.split():
            if word in wordDict:
                wordDict[word] += 1
            else:
                wordDict.update({word:1})



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
    pass