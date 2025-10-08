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
        The updated WhitelistedDomains list
    '''
    #global WhitelistedDomains
    #WhitelistedDomains.clear()  # reset before loading
    WhitelistedDomains = []
    try:
        with open(filename, "r") as f:
            for line in f:
                domain = line.strip().lower()
                if domain and not domain.startswith("#"):  # skip blanks & comments
                    WhitelistedDomains.append(domain)
    except FileNotFoundError:
        print(f"Whitelist file '{filename}' not found.")
    except Exception as e:
        print(f"Error reading whitelist file: {e}")

    # print(WhitelistedDomains)
    return WhitelistedDomains

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
    BlacklistedDomains = []
    try:
        with open(filename, "r") as f:
            for line in f:
                domain = line.strip().lower()
                if domain and not domain.startswith("#"):  # skip blanks & comments
                    BlacklistedDomains.append(domain)
    except FileNotFoundError:
        print(f"Blacklist file '{filename}' not found.")
    except Exception as e:
        print(f"Error reading blacklist file: {e}")

    # print(BlacklistedDomains)
    return BlacklistedDomains


def CheckWhitelistedDomain(emailadd,riskScore,WhitelistedDomains):
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
    if domain not in [d.lower() for d in WhitelistedDomains]:
        print(f'\nSuspicious email detected. Sender email address ({emailadd}) is not whitelisted')
        riskScore+=penalty
        return riskScore
    else:
        #Does not add to risk score if sender email address is whitelisted
        print(f'\nSender email address ({emailadd}) is whitelisted')
        return riskScore

def CheckBlacklistedDomain(emailadd, BlacklistedDomains):
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

    max_risk = 185  # defining the maximum risk score for a blacklisted domain, indicating a block

    if not emailadd:  # if no sender email address is provided, mark as suspicious and block
        print(f"Suspicious email: invalid sender '{emailadd}'")
        return max_risk

    elif "@" not in emailadd:  # if the sender email does not contain '@', mark as suspicious and block
        print(f"Suspicious email: sender email address '{emailadd}' does not contain '@'")
        return max_risk

    # splits the email address into username and domain name, converts domain to lowercase for consistent comparison
    domain = emailadd.split("@")[-1].lower() 

    # check if the extracted domain is in the blacklist
    if domain in BlacklistedDomains:
        print(f"Blocked email: sender domain '{domain}' is in blacklist.")
        return max_risk  # immediately block by returning max risk score

    # if domain is not blacklisted, return 0 indicating no blacklist risk
    return 0

def CheckBlacklistThenWhitelist(emailadd, riskScore, WhitelistedDomains, BlacklistedDomains):
    '''
    Check sender's email domain against blacklist first then whitelist:
    - If domain is blacklisted: block immediately with max risk score.
    - If not blacklisted: check whitelist to allow or add penalty if untrusted.
    
    Args:
        emailadd: sender email address
        riskScore: current risk score before domain checks
        WhitelistedDomains: list of trusted domains
        BlacklistedDomains: list of malicious domains
    
    Returns:
        Updated risk score (max risk for blacklist hit, increased for not whitelisted, unchanged if whitelisted)
    '''

    # Check the blacklist first to immediately block if the sender domain is blacklisted
    blk_risk = CheckBlacklistedDomain(emailadd, BlacklistedDomains)

    # If blk_risk equals 100, it means the domain is blacklisted and we block immediately by returning max risk
    if blk_risk == 185:
        return blk_risk  # block immediately without further checks

    # If domain is not blacklisted, proceed to check if it is whitelisted
    # This will return the risk score unchanged if whitelisted, or add penalty if not
    return CheckWhitelistedDomain(emailadd, riskScore, WhitelistedDomains)

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
    prev_distances = range(len(target) + 1)  # [0, 1, 2, ... len(target)]

    # Loop through each character in the source string
    for src_index, src_char in enumerate(source):
        # curr_distances[j] = distance between:
        #   first i chars of source  and  first j chars of target
        # Start with cost of deleting all chars up to src_index
        curr_distances = [src_index + 1]

        # Loop through each character in the target string
        for tgt_index, tgt_char in enumerate(target):
            # Cost of inserting target[tgt_index] into source
            insert_cost = prev_distances[tgt_index + 1] + 1

            # Cost of deleting source[src_index]
            delete_cost = curr_distances[tgt_index] + 1

            # Cost of substituting source[src_index] → target[tgt_index]
            substitute_cost = prev_distances[tgt_index] + (src_char != tgt_char)

            # Pick the cheapest operation
            curr_distances.append(min(insert_cost, delete_cost, substitute_cost))

        # Move to the next row
        prev_distances = curr_distances

    # The last cell = distance between full source and full target
    return prev_distances[-1]

def check_sender_levenshtein(sender:str, whitelist:list, riskScore:int):
    '''
    Check if the sender's email domain is visually similar to the domains in the whitelist.
    - If visually similar: add a penalty to the riskScore
    - If not visually similar: returns original riskScore.
    
    Args:
        sender: email address
        whitelist: List containing Whitelisted Domain names
        riskScore: The current risk Score
    '''
    for w in whitelist:
        #print(f'sender:{sender},whitelisted email:{w}')
        distance = levenshtein(sender,w)
        
        #print(f"levenshtein distance:{distance}")
        if distance <= 2:
            print(f"Sender email {sender} is similar to {w} as levenshtein distance is {distance}.")
            riskScore += 30
            return riskScore

    print("Sender email passed edit distance check")
    return riskScore


if __name__=='__main__':
    # test = {
    # "From": "John","phisher@bad.com"
    # "Subject": "Urgent: Reset your password"
    # }
    # print(GetSender(test))

    print(levenshtein("g0v.sg", "gov.sg"))
