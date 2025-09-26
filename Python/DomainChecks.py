

from email.utils import parseaddr
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

def GetSender(email)->str:
    '''
    Extract Sender from the email.
    - If whitelisted: return the same riskScore.
    - If not whitelisted: add a penalty to the riskScore.
    
    Args:
        email: parsed email object (dict-like with "From" header).
    '''
    #gets sender information via the from header, this consists of sender display name + email address
    sender = email.get("From") or email.get("from")

    #splits the from header into sender display name + email address, and assigns email address to addr
    addr = parseaddr(sender)[1]

    return addr

def CheckWhitelistedDomain(email,riskScore,WhitelistedDomains):
    '''
    Check if the sender's email domain is in the whitelist.
    - If whitelisted: return the same riskScore.
    - If not whitelisted: add a penalty to the riskScore.
    
    Args:
        email: email address
        riskScore: The current risk Score
        WhitelistedDomains: List containing Whitelisted Domain names

    Returns:
        Updated RiskScore
    '''

    #global riskScore
    penalty = 20

    #gets sender email address via the from header,
    #sender = email.get("From")

    #if no sender from header, flag as suspicious and add penalty to risk score
    #if not sender:
        #print(f'\nSuspicious email detected. No sender found')
        #riskScore+=penalty
        #return

    #splits the from header into display name + email address
    #dispName, addr = parseaddr(sender)
    # print(f'Display Name:{dispName}, Domain: {addr}')

    #if "@" not in addr, flag as suspicious and add penalty to risk score
    if "@" not in email:
        print(f'\nSuspicious email detected. Sender email address ({email}) does not contain @')
        riskScore+=penalty
        return

    #splits the email address into username and domain name, converts the domain name to lowercase and assign domain name to variable
    domain = email.split("@")[-1].lower() 
    # print(WhitelistedDomains)
    
    #checks if domain name is in whitelist
    if domain not in [d.lower() for d in WhitelistedDomains]:
        print(f'\nSuspicious email detected. Sender email address ({email}) is not whitelisted')
        riskScore+=penalty
        return
    else:
        #Does not add to risk score if sender email address is whitelisted
        print(f'\nSender email address ({email}) is whitelisted')

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

#print(levenshtein("kitten", "sitting"))
if __name__=='__main__':
    test = {
    "From": "John","phisher@bad.com"
    "Subject": "Urgent: Reset your password"
    }
    print(GetSender(test))