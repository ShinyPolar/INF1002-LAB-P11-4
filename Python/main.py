#====INSTALL THE MODULES IN requirements.txt FIRST BEFORE RUNNING====
#====Alternatively, you can run the following command in your terminal:====
#pip install -r requirements.txt

#for handling multiple datasets in a directory
import os

#for Module imports
import DomainChecks as dc
import urlDetection as ud
import ScanEmail as se
import ParseEmail as pe


def MainWorkflow(file: str, riskScore: int):
    """Main workflow for processing email files.
    Calls all the necessary functions and tabulates the riskScores
    
    """
    filetype = pe.detect_email_filetype(file) #checks if email is .mbox or .eml
    if filetype == "mbox":
        emailToScan = pe.ParseSingleMbox(file)   #parse the sampleEmail to readable status for mbox files
        #PrintMultiPartMBox(emailToScan)
    elif filetype == "eml":
        emailToScan = pe.ParseSingleEML(file)    #parse the sampleEmail to readable status for eml files
    else:
        raise ValueError("Unsupported email file type")

    #initialize whitelisted domains
    WhitelistedDomains = dc.LoadWhitelistedDomains("sampleWhitelistedDomains.txt")

    #clean the email text and extract URLs & remove the html if neccesary
    #pe.CleanText(emailToScan)

    #gets sender email address from the "from" header in the email
    sender = dc.GetSender(emailToScan)

    #checks if the sender's domain is whitelisted and add to risk score if not 
    riskScore = dc.CheckWhitelistedDomain(sender,riskScore,WhitelistedDomains)

    #if email fails whitelist check
    if riskScore > 0:
        #Edit distance check 
        riskScore = dc.check_sender_levenshtein(sender,WhitelistedDomains,riskScore) 
        #print(riskScore)

    #Scans the email for suspicious words
    urls = []
    riskScore += se.ScanEmail(emailToScan, urls)

    #Scan the URLs in the email for suspicious features
    #riskScore += ud.scanURLs(urls, email_msg=emailToScan)
    print(f'Total Risk Score: {riskScore}')

    pass

if __name__=='__main__':

    #Initialization
    se.SetSuspiciousWords("wordWeightage.txt")
    riskScore = 0


    
    #======= If remove print from every function except the final riskScore, it would be cleaner ======
    #======= If possible, make a print function for each module so that it                  ===========
    #======= would be possible to print the results of each module separately           ===============
    #======= and collate it at the end for a cleaner output                             ================

    #======= The code below is to be ran for multiple files in a directory only===========
    #directory = "..\easy_ham\easy_ham"
    # directory = "..\hard_ham\hard_ham"
    # counter = 0
    # for f in os.listdir(directory):
    #     #reset riskScore
    #     riskScore = 0
    #     file = os.path.join(directory, f)

    #     #condition here in case we want to limit the number of files processed for testing or other purposes
    #     if (counter == 5): 
    #         break
    #     counter += 1

    #     #Print out the file being checked on so that if there is an error, we know which file it is
    #     print(file)
    #     MainWorkflow(file, riskScore)
    #     print("\n\n")


    #======= The code below is to be ran for a single file only =======
    file = "sampleEmail3.txt"
    MainWorkflow(file, riskScore)

