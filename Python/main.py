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

#=======Flask===========
import flask

app = flask.Flask(__name__)

# Global variable to hold filepath
emailToScanFilePath = ""

@app.route('/')
def home():
    return flask.render_template("index.html", htmlText=app.config['HTMLTEXT'], 
                                 plainText=app.config['PLAINTEXT'],
                                 riskScore=app.config['RISKSCORE'],
                                 riskLvl=app.config['RISKLVL'],
                                 riskScoreBlacklistDomain=app.config['RISKSCOREBL'],
                                 riskScoreWhitelistDomain=app.config['RISKSCOREWD'],
                                 riskScoreDistanceCheck=app.config['RISKSCOREDC'],
                                 riskScoreKeyword=app.config['RISKSCOREKW'],
                                 riskScoreURL=app.config['RISKSCOREURL'],
                                 sender=app.config['SENDER'],
                                 recepient=app.config['RECEPIENT'])

@app.route('/upload', methods=['POST'])
def upload():
    if 'file' not in flask.request.files:
        return "No file uploaded", 400
    file = flask.request.files['file']
    if file.filename == '':
        return "No selected file", 400

    # Save temporarily if needed
    filepath = os.path.join('uploads', file.filename)
    file.save(filepath)

    global emailToScanFilePath
    emailToScanFilePath = filepath

    return f"Processing complete"

@app.route('/analyze', methods=['POST'])
def rerun():
    """Re-run MainWorkflow on the last uploaded file."""
    global emailToScanFilePath

    MainWorkflow(emailToScanFilePath, 0)
    return flask.redirect(flask.url_for('home'))

#=========Python===========
def WebUIVariables(riskScore:int, riskLvl:str, riskScoreBlacklistDomain:int
                   ,riskScoreWhitelistDomain:int,riskScoreDistanceCheck:int,riskScoreKeyword:int
                   ,riskScoreURL:int,htmltext:str,plaintext:str,sender:str,recepient:str):
    """
    Populate web UI configuration variables with risk analysis results.

    This function updates the Flask 'app.config' dictionary with values
    related to email risk scoring and message content. These values are
    then available for rendering in the web interface.

    Args:
        riskScore (int): Overall computed risk score for the email.
        riskLvl (str): Risk level classification (e.g., "Low", "Medium", "High").
        riskScoreBlacklistDomain (int): Score contribution from blacklist domain checks.
        riskScoreWhitelistDomain (int): Score contribution from whitelist domain checks.
        riskScoreDistanceCheck (int): Score contribution from domain distance/similarity checks.
        riskScoreKeyword (int): Score contribution from suspicious keyword detection.
        riskScoreURL (int): Score contribution from URL analysis.
        htmltext (str): Raw HTML body of the email.
        plaintext (str): Plain text body of the email.
        sender (str): Email address of the sender.
        recepient (str): Email address of the recipient.

    Returns:
        None: The function updates 'app.config' in place.
    """
    app.config['RISKSCORE'] = riskScore
    app.config['RISKLVL'] = riskLvl
    app.config['RISKSCOREBL'] = riskScoreBlacklistDomain
    app.config['RISKSCOREWD'] = riskScoreWhitelistDomain
    app.config['RISKSCOREDC'] = riskScoreDistanceCheck
    app.config['RISKSCOREKW'] = riskScoreKeyword
    app.config['RISKSCOREURL'] = riskScoreURL
    app.config['HTMLTEXT'] = htmltext
    app.config['PLAINTEXT'] = plaintext
    app.config['SENDER'] = sender
    app.config['RECEPIENT'] = recepient
 

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

    #Initalizes different riskScores
    riskScoreBlacklistDomain = 0
    riskScoreWhitelistDomain = riskScoreDistanceCheck = riskScoreKeyword = riskScoreURL = 0
    
    #initialize whitelisted domains
    whitelistedDomains = dc.LoadDomains("Domains/sampleWhitelistedDomains.txt")

    # Initialize blacklisted domains
    blacklistedDomains = dc.LoadDomains("Domains/sampleBlacklistedDomains.txt")

    #clean the email text and extract URLs & remove the html if neccesary
    #pe.CleanText(emailToScan)

    #gets sender email address from the "from" header in the email
    sender = pe.GetSender(emailToScan)

    #gets recepient email from the "to" header in the email
    recepient = pe.GetRecepient(emailToScan)

    #email to display on web UI
    htmltext = pe.GetHTMLText(emailToScan)
    plaintext = pe.GetPlainText(emailToScan)

    # Check the blacklist first
    riskScoreBlacklistDomain = dc.CheckBlacklistedDomain(sender, blacklistedDomains)

    if riskScoreBlacklistDomain == 185:
        # Immediate block: set total riskScore to max and skip other checks
        riskScore = riskScoreBlacklistDomain
        riskLvl = "High. Very likely to be a phishing email"
        print(f'Total Risk Score: {riskScore}')
        print(f'Risk Level:{riskLvl}')
        WebUIVariables(riskScore,riskLvl,riskScoreBlacklistDomain
                       ,riskScoreWhitelistDomain,riskScoreDistanceCheck,riskScoreKeyword
                       ,riskScoreURL,htmltext,plaintext,sender,recepient)
        return
    # Only executes for NON-BLACKLISTED domains:
    # Check if the sender's domain is whitelisted and add to risk score if not
    riskScoreWhitelistDomain = dc.CheckWhitelistedDomain(sender, riskScore, whitelistedDomains)

    #if email fails whitelist check
    if riskScoreWhitelistDomain > 0:
        #Edit distance check 
        riskScoreDistanceCheck = dc.CheckSenderLevenshtein(sender,whitelistedDomains,riskScore) 
        #print(riskScore)

    #Scans the email for suspicious words
    # urls = []
    email_text = pe.GetPlainText(emailToScan)
    urls = ud.ExtractURLsFromText(email_text)
    riskScoreKeyword = se.ScanEmail(emailToScan, urls)

    #Scan the URLs in the email for suspicious features
    riskScoreURL = ud.ScanURLs(urls, email_msg=emailToScan)
    riskScore = riskScoreDistanceCheck + riskScoreWhitelistDomain + riskScoreKeyword + riskScoreURL

    #Assign Severity
    if riskScore < 40:
        riskLvl = "Low. Unlikely to be Phising"
    elif riskScore <= 100:
        riskLvl = "Medium. Could be a Phishing email"
    else:
        riskLvl = "High. Very likely to be a phishing email"
                    
    print(f'Total Risk Score: {riskScore}')
    print(f'Risk Level:{riskLvl}')
    # For Web UI visualisation
    WebUIVariables(riskScore,riskLvl,riskScoreBlacklistDomain
                   ,riskScoreWhitelistDomain,riskScoreDistanceCheck,riskScoreKeyword
                   ,riskScoreURL,htmltext,plaintext,sender,recepient)

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
    file = "TestEmails/sampleEmail1.txt"
    MainWorkflow(file, riskScore)
    app.run(debug=True)

