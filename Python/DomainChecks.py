r'''
This module provides functions for email domain security checks.

It is designed to be used in a phishing or spam detection system to analyze
the sender's email address. The primary functions involve validating the
sender's domain against whitelists and blacklists, checking for basic email
format validity, and detecting potentially malicious, visually similar domains
(typosquatting) using the Levenshtein distance algorithm.

Key functionalities include:
- Loading whitelisted and blacklisted domains from external files.
- Checking if a sender's domain is explicitly whitelisted/blacklisted.
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
        print(f"Whitelist file or Blacklist file '{filename}' not found.")
    except Exception as e:
        print(f"Error reading whitelist or blacklist file: {e}")

    return domains

def CheckDomain(emailAdd,domains):
    '''
    Check if the sender's email domain is in the list provided.
    - If in list: return True.
    - If not in list: return False.
    
    Args:
        emailAdd: email address
        domains: List containing Whitelisted/Blacklisted Domain names

    Returns:
        True/False (Boolean): True if found, False if not found
    '''
    #splits the email address into username and domain name, converts the domain name to lowercase and assign domain name to variable
    domain = emailAdd.split("@")[-1].lower() 
    
    #checks if domain name is not in list
    if domain not in [d.lower() for d in domains]:
        return False
    else:
        #Does not add to risk score if sender email address is in list
        return True

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
    - The distance represents the minimum number of insertions, deletions, 
      or substitutions required to transform one string into the other.
    - Used for detecting visual similarity between domains in phishing detection.

    Args:
        source: The first string to compare.
        target: The second string to compare.

    Returns:
        An integer distance (0 if identical; larger values indicate greater difference).
    '''

    # Convert both strings to lowercase for case-insensitive comparison
    source = source.lower()
    target = target.lower()

    # Ensure source is the longer string (for memory efficiency)
    if len(source) < len(target): # Swap if source is shorter than target
        return Levenshtein(target, source)

    # If target is empty, distance = remove all characters from source
    if len(target) == 0:
        return len(source) # Distance is the length of source (all deletions)

    # prev_distances[j] = distance between:
    # first i-1 characters of source and first j characters of target
    prevDistances = range(len(target) + 1)

    # Loop through each character in the source string
    for srcIndex, srcChar in enumerate(source):
        # curr_distances[j] = distance between:
        # first i characters of source and first j characters of target
        # Initialize current row with deletion cost (removing all source chars up to srcIndex)
        currDistances = [srcIndex + 1]

        # Loop through and compare against each character in the target string
        for tgtIndex, tgtChar in enumerate(target):
            # Cost of inserting target[tgtIndex] into source
            insertCost = prevDistances[tgtIndex + 1] + 1

            # Cost of deleting source[srcIndex]
            deleteCost = currDistances[tgtIndex] + 1

            # Cost of substituting source[srcIndex] → target[tgtIndex]
            substituteCost = prevDistances[tgtIndex] + (srcChar != tgtChar)

            # Choose the minimal operation cost
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
        riskScore: integer value of 20 if sender's email domain is suspiciously similar to whitelist, else 0
        riskScore: integer value of 20 if sender's email domain is suspiciously similar to whitelist, else 0
    '''
    domain = sender.split("@")[-1].lower()
    for w in whiteList:
        distance = Levenshtein(domain,w) # using custom levenshtein function to compute edit distance
        if distance <= 2: # threshold for flagging as suspicious (allowing for minor typos)
            print(f"Sender email {sender} is similar to {w} as levenshtein distance is {distance}.") # flag as suspicious and add penalty to risk score
            riskScore += 20 # penalty for failing edit distance check
            return riskScore # return updated risk score if sender email is similar to any whitelisted domains

    print("Sender email passed edit distance check")
    return riskScore # return original risk score if sender email is not similar to any whitelisted domains
