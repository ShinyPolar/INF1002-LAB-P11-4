import mailbox


def ParseMBox(path):
    '''Parse the mbox file and return a list of email messages
    '''
    mbox = mailbox.mbox(path)
    '''for message in mbox:
        print("Subject:", message["subject"])
        print("From:", message["from"])
        print("To:", message["to"])
        print("Date:", message["date"])
        print("Body:", message.get_payload())
        print("="*50)'''
    phishing_mailList = [message for message in mbox]
    for message in mbox:
        phishing_mailList.append(message)
    return phishing_mailList

def CheckWords(mailList, wordDict):
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
    

def SortDict(wordDict):
    '''Sort the dictionary by value in descending order
    '''
    sortedDict = dict(sorted(wordDict.items(), key=lambda item: item[1], reverse=True))
    return sortedDict

def WriteToFile(wordDict):
    f = open("wordCount.txt", "w")
    for key, value in wordDict.items():
        try:
            f.write(f"{key}: {value}\n")
        except:
            continue
    f.close()

if __name__=='__main__':
    wordDict = {}
    CheckWords(ParseMBox("../phishing_dataset/phishing0.mbox"), wordDict)
    CheckWords(ParseMBox("../phishing_dataset/phishing1.mbox"), wordDict)
    CheckWords(ParseMBox("../phishing_dataset/phishing2.mbox"), wordDict)
    #print(len(phishing_mailList)) 414
    #for i in range(len(phishing_mailList)):
        #print(phishing_mailList[i]["subject"])
    #    CheckWords(str(phishing_mailList[i]["subject"]), wordDict)
    wordDict = SortDict(wordDict)
    WriteToFile(wordDict)
    
