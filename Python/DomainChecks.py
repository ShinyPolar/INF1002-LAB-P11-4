r'''
Module to check sender email domain


'''
from Levenshtein import distance

def LoadWhitelistedDomains(filename: str) -> list:
    '''
    Reads a text file containing whitelisted domains (one per line)
    and stores them in the global WhitelistedDomains list.

    Args:
        filename: path to the text file

    Returns:
        The updated whitelistedDomains list
    '''
    #global WhitelistedDomains
    #WhitelistedDomains.clear()  # reset before loading
    whitelistedDomains = []
    try:
        with open(filename, "r") as f:
            for line in f:
                domain = line.strip().lower()
                if domain and not domain.startswith("#"):  # skip blanks & comments
                    whitelistedDomains.append(domain)
    except FileNotFoundError:
        print(f"Whitelist file '{filename}' not found.")
    except Exception as e:
        print(f"Error reading whitelist file: {e}")

    # print(WhitelistedDomains)
    return whitelistedDomains

def LoadBlacklistedDomains(filename: str) -> list:
    '''
    Reads a text file containing blacklisted domains (one per line)
    and stores them in the global BlacklistedDomains list.

    Args:
        filename: path to the text file

    Returns:
        The updated BlacklistedDomains list
    '''
    #global BlacklistedDomains
    #BlacklistedDomains.clear()  # reset before loading
    blacklistedDomains = []
    try:
        with open(filename, "r") as f:
            for line in f:
                domain = line.strip().lower()
                if domain and not domain.startswith("#"):  # skip blanks & comments
                    blacklistedDomains.append(domain)
    except FileNotFoundError:
        print(f"Blacklist file '{filename}' not found.")
    except Exception as e:
        print(f"Error reading blacklist file: {e}")

    # print(BlacklistedDomains)
    return blacklistedDomains


def CheckWhitelistedDomain(emailadd,riskScore,whitelistedDomains):
    '''
    Check if the sender's email domain is in the whitelist.
    - If whitelisted: return the same riskScore.
    - If not whitelisted: add a penalty to the riskScore.
    
    Args:
        email: email address
        riskScore: The current risk Score
        WhitelistedDomains: List containing Whitelisted Domain names
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
        emailadd: sender email address
        BlacklistedDomains: List containing Blacklisted Domain names
    
    Returns:
        Integer risk score (max risk for blacklist hit, else 0)
    '''

    maxRisk = 185  # defining the maximum risk score for a blacklisted domain, indicating a block

    if not emailadd:  # if no sender email address is provided, mark as suspicious and block
        print(f"Suspicious email: invalid sender '{emailadd}'")
        return maxRisk

    elif "@" not in emailadd:  # if the sender email does not contain '@', mark as suspicious and block
        print(f"Suspicious email: sender email address '{emailadd}' does not contain '@'")
        return maxRisk

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
    """
    This function is to compute the Levenshtein distance between two strings.

    The distance is the minimum number of insertions, deletions, 
    or substitutions required to transform source to target.
    """

    source = source.lower()
    target = target.lower()

    # Ensure source is the longer string (for memory efficiency)
    if len(source) < len(target):
        return levenshtein(target, source)

    # If target is empty, distance = remove all chars from source
    if len(target) == 0:
        return len(source)

    # prev_distances[j] = distance between:
    # first i-1 chars of source  and  first j chars of target
    prevDistances = range(len(target) + 1)  # [0, 1, 2, ... len(target)]

    # Loop through each character in the source string
    for srcIndex, srcChar in enumerate(source):
        # curr_distances[j] = distance between:
        #   first i chars of source  and  first j chars of target
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
        prev_distances = currDistances

    # The last cell = distance between full source and full target
    return prev_distances[-1]

def checkSenderLevenshtein(sender:str, whiteList:list, riskScore:int):
    '''
    Check if the sender's email domain is visually similar to the domains in the whitelist.
    - If visually similar: add a penalty to the riskScore
    - If not visually similar: returns original riskScore.
    
    Args:
        sender: email address
        whitelist: List containing Whitelisted Domain names
        riskScore: The current risk Score
    '''
    for w in whiteList:
        #print(f'sender:{sender},whitelisted email:{w}')
        distance = levenshtein(sender,w)
        
        #print(f"levenshtein distance:{distance}")
        if distance <= 2:
            print(f"Sender email {sender} is similar to {w} as levenshtein distance is {distance}.")
            riskScore += 30
            return riskScore

    print("Sender email passed edit distance check")
    return riskScore


