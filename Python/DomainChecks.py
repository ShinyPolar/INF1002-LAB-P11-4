r'''
This module provides functions for email domain security checks.

It is designed to be used in a phishing or spam detection system to analyze
the sender's email address. The primary functions involve validating the
sender's domain against whitelists and blacklists, checking for basic email
format validity, and detecting potentially malicious, visually similar domains
(typosquatting) using the Levenshtein distance algorithm.

Key functionalities include:
- Loading whitelisted and blacklisted domains from external files.
- Checking if a sender's domain is explicitly whitelisted.
- Checking if a sender's domain is explicitly blacklisted.
- Validating the basic structure of the sender's email address.
- Calculating the Levenshtein distance to find domains that are suspiciously
  similar to whitelisted domains.
'''

from Levenshtein import distance # Using Levenshtein library

def LoadDomains(filename: str) -> list:
    '''
    Loads a list of domains from a text file.

    This function reads a text file where each line represents a domain
    to be whitelisted/blacklisted. Lines that are empty or start with '#' are ignored.
    Domains are normalized to lowercase before being added to the list.

    Args:
        filename (str): Path to the text file containing whitelisted/blacklisted domains

    Returns:
        list: A list of whitelisted/blacklisted domain strings
    '''
    domains = set()
    try:
        with open(filename, "r") as f:
            for line in f:
                domain = line.strip().lower()
                if domain and not domain.startswith("#"):  # skip blanks & comments
                    domains.add(domain)
    except FileNotFoundError:
        print(f"Whitelist file '{filename}' not found.")
    except Exception as e:
        print(f"Error reading whitelist file: {e}")

    return domains


def CheckWhitelistedDomain(emailadd,riskScore,whitelistedDomains):
    '''
    Check if the sender's email domain is in the whitelist.
    - If whitelisted: return the same riskScore.
    - If not whitelisted: add a penalty to the riskScore.
    
    Args:
        emailadd: email address
        riskScore: The current risk Score
        WhitelistedDomains: List containing Whitelisted Domain names

    Returns:
        riskScore: Adds an integer value of 20 if not whitelisted, 0 if whitelisted
    '''

    penalty = 40 #defining the penalty for failing the Domain Whitelist Check

    #splits the email address into username and domain name, converts the domain name to lowercase and assign domain name to variable
    domain = emailadd.split("@")[-1].lower() 
    
    #checks if domain name is in whitelist
    if domain not in [d.lower() for d in whitelistedDomains]:
        print(f'\nSuspicious email detected. Sender email address ({emailadd}) is not whitelisted')
        riskScore+=penalty
        return riskScore
    else:
        #Does not add to risk score if sender email address is whitelisted
        print(f'\nSender email address ({emailadd}) is whitelisted')
        return riskScore

def CheckBlacklistedDomain(emailAdd, blacklistedDomains):
    '''
    Check if the sender's email domain is in the blacklist.
    - If blacklisted: return maximum risk score indicating an immediate block.
    - If not blacklisted: return zero as no risk added by blacklist check.
    
    Args:
        emailadd: sender's email address
        BlacklistedDomains: List containing Blacklisted Domain names
    
    Returns:
        riskScore: max integer risk score (185) if domain is blacklisted/no sender
        /incomplete sender email, else 0
    '''

    maxRisk = 145  # defining the maximum risk score for a blacklisted domain, indicating a block

    #check for presence of email address and assign max risk score if email address is not found/incomplete
    if CheckSender(emailAdd) == False:
        return maxRisk
    
    # splits the email address into username and domain name, converts domain to lowercase for consistent comparison
    domain = emailAdd.split("@")[-1].lower()

    # check if the extracted domain is in the blacklist
    if domain in blacklistedDomains:
        print(f"Blocked email: sender domain '{domain}' is in blacklist.")
        return maxRisk  # immediately block by returning max risk score

    # if domain is not blacklisted, return 0 indicating no blacklist risk
    return 0

def CheckSender(emailAdd:str):
    """
    Validate the sender's email address format.

    This function checks whether a sender email address is present and
    contains the '@' symbol. If the address is missing or malformed,
    it is flagged as suspicious and the function returns False. Otherwise,
    the address is considered valid and the function returns True.

    Args:
        emailAdd (str): The sender's email address to validate.

    Returns:
        bool: 
            - False if the email address is missing or invalid.
            - True if the email address is valid.
    """
    # if no sender email address is provided or if sender email does not contain '@', mark as suspicious and block
    if not emailAdd or "@" not in emailAdd:  
        print(f"Suspicious email: invalid sender '{emailAdd}'")
        return False # immediately block by returning False
    return True


def Levenshtein(source: str, target: str) -> int:
    '''
    Compute the Levenshtein distance between two strings.
    - The distance is the minimum number of insertions, deletions, 
      or substitutions required to transform one string into the other.
    - Used for detecting visual similarity between domains in phishing detection.

    Args:
        source: The first string to compare
        target: The second string to compare

    Returns:
        distance value: integer value of 0 if identical, higher values indicate greater difference
    '''

    # Convert both strings to lowercase for case-insensitive comparison
    source = source.lower()
    target = target.lower()

    # Ensure source is the longer string (for memory efficiency)
    if len(source) < len(target): # Swap if source is shorter than target
        return Levenshtein(target, source) # Recursive call with swapped arguments

    # If target is empty, distance = remove all chars from source
    if len(target) == 0:
        return len(source) # Distance is the length of source (all deletions)

    # prev_distances[j] = distance between:
    # first i-1 chars of source  and  first j chars of target
    prevDistances = range(len(target) + 1)  # [0, 1, 2, ... len(target)]

    # Loop through each character in the source string
    for srcIndex, srcChar in enumerate(source):
        # curr_distances[j] = distance between:
        # first i chars of source  and  first j chars of target
        # Start with cost of deleting all chars up to src_index
        currDistances = [srcIndex + 1]

        # Loop through each character in the target string
        for tgtIndex, tgtChar in enumerate(target):
            # Cost of inserting target[tgt_index] into source
            insertCost = prevDistances[tgtIndex + 1] + 1

            # Cost of deleting source[src_index]
            deleteCost = currDistances[tgtIndex] + 1

            # Cost of substituting source[src_index] → target[tgt_index]
            substituteCost = prevDistances[tgtIndex] + (srcChar != tgtChar)

            # Pick the cheapest operation
            currDistances.append(min(insertCost, deleteCost, substituteCost))

        # Move to the next row
        prevDistances = currDistances

    # The last cell = distance between full source and full target
    return prevDistances[-1]

def CheckSenderLevenshtein(sender:str, whiteList:list, riskScore:int):
    '''
    Check if the sender's email domain is visually similar to any whitelisted domain.
    - If similarity is detected (edit distance ≤ threshold): add penalty to riskScore.
    - If no similarity is detected: return original riskScore unchanged.

    Args:
        sender: Sender's email address
        whiteList: List containing whitelisted domain names
        riskScore: Current accumulated risk score

    Returns:
        riskScore: integer value of 30 if sender's email domain is suspiciously similar to whitelist, else 0
    '''
    
    for w in whiteList:
        #print(f'sender:{sender},whitelisted email:{w}')
        distance = Levenshtein(sender,w) # using custom levenshtein function to compute edit distance
        
        #print(f"levenshtein distance:{distance}")
        if distance <= 2: # threshold for flagging as suspicious (allowing for minor typos)
            print(f"Sender email {sender} is similar to {w} as levenshtein distance is {distance}.") # flag as suspicious and add penalty to risk score
            riskScore += 20 # penalty for failing edit distance check
            return riskScore # return updated risk score if sender email is similar to any whitelisted domains

    print("Sender email passed edit distance check")
    return riskScore # return original risk score if sender email is not similar to any whitelisted domains
