r'''
Module to check sender email domain


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
    domains = []
    try:
        with open(filename, "r") as f:
            for line in f:
                domain = line.strip().lower()
                if domain and not domain.startswith("#"):  # skip blanks & comments
                    domains.append(domain)
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
        riskScore: Integer value of 0 if whitelisted, 20 if not
    '''

    penalty = 20 #defining the penalty for failing the Domain Whitelist Check
    
    if not emailadd: #if no sender from header, flag as suspicious and add penalty to risk score
        print(f'\nSuspicious email detected. No sender found')
        riskScore+=penalty
        return riskScore
    elif "@" not in emailadd: #if "@" not in addr, flag as suspicious and add penalty to risk score
        print(f'\nSuspicious email detected. Sender email address ({emailadd}) does not contain @')
        riskScore+=penalty
        return riskScore

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

def CheckBlacklistedDomain(emailadd, blacklistedDomains):
    '''
    Check if the sender's email domain is in the blacklist.
    - If blacklisted: return maximum risk score indicating an immediate block.
    - If not blacklisted: return zero as no risk added by blacklist check.
    
    Args:
        emailadd: sender's email address
        BlacklistedDomains: List containing Blacklisted Domain names
    
    Returns:
        riskScore: max integer risk score (185) if domain is blacklisted, else 0
    '''

    maxRisk = 185  # defining the maximum risk score for a blacklisted domain, indicating a block

    if not emailadd:  # if no sender email address is provided, mark as suspicious and block
        print(f"Suspicious email: invalid sender '{emailadd}'")
        return maxRisk # immediately block by returning max risk score

    elif "@" not in emailadd:  # if the sender email does not contain '@', mark as suspicious and block
        print(f"Suspicious email: sender email address '{emailadd}' does not contain '@'")
        return maxRisk # immediately block by returning max risk score

    # splits the email address into username and domain name, converts domain to lowercase for consistent comparison
    domain = emailadd.split("@")[-1].lower()

    # check if the extracted domain is in the blacklist
    if domain in blacklistedDomains:
        print(f"Blocked email: sender domain '{domain}' is in blacklist.")
        return maxRisk  # immediately block by returning max risk score

    # if domain is not blacklisted, return 0 indicating no blacklist risk
    return 0

# edit distance check
def levenshtein(source: str, target: str) -> int:
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
        return levenshtein(target, source) # Recursive call with swapped arguments

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

def checkSenderLevenshtein(sender:str, whiteList:list, riskScore:int):
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
        distance = levenshtein(sender,w) # using custom levenshtein function to compute edit distance
        
        #print(f"levenshtein distance:{distance}")
        if distance <= 2: # threshold for flagging as suspicious (allowing for minor typos)
            print(f"Sender email {sender} is similar to {w} as levenshtein distance is {distance}.") # flag as suspicious and add penalty to risk score
            riskScore += 30 # penalty for failing edit distance check
            return riskScore # return updated risk score if sender email is similar to any whitelisted domains

    print("Sender email passed edit distance check")
    return riskScore # return original risk score if sender email is not similar to any whitelisted domains
