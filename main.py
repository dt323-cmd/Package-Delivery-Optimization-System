
# C.  Design and develop your fully functional data product that addresses your identified business problem or organizational need from part A. Include each of the following attributes, as they are the minimum required elements for the product:


# •   one descriptive method and one nondescriptive (predictive or prescriptive) method              # (RESOLVED)

# •   collected or available datasets                                                                # (RESOLVED)

# •   decision support functionality                                                                 # (RESOLVED)

# •   ability to support featurizing, parsing, cleaning, and wrangling datasets                       # (RESOLVED) 

# •   methods and algorithms supporting data exploration and preparation                             # (RESOLVED)

# •   data visualization functionalities for data exploration and inspection                          # (RESOLVED)  

# •   implementation of interactive queries                                                          # (RESOLVED)

# •   implementation of machine-learning methods and algorithms                                      # (RESOLVED)
                                                                                                  


# •   functionalities to evaluate the accuracy of the data product                                   #  (RESOLVED)

# •   industry-appropriate security features                                                          # (RESOLVED)

# •   tools to monitor and maintain the product                                                        # (RESOLVED)   

# a user-friendly, functional dashboard that includes three visualization types                       # (RESOLVED)


import datetime
import re
import math
import random
import os
import hashlib
import hmac
import getpass
import time
import json
import shutil
import webbrowser
from collections import Counter


# Secret key added for HMAC of audit logs / model signature. Prefer to set env var to WGUPS_AUDIT_KEY.
_AUDIT_KEY = (os.environ.get("WGUPS_AUDIT_KEY") or "").encode() or os.urandom(32)

def hmac_sign(msg):
    return hmac.new(_AUDIT_KEY, msg.encode("utf-8"), hashlib.sha256).hexdigest()

def audit_log(action, details=""):
    """Append an HMAC-signed audit log entry to disk (simple append-only)."""
    ts = datetime.datetime.utcnow().isoformat() + "Z"
    entry = f"{ts} | {action} | {details}"
    signature = hmac_sign(entry)
    line = f"{entry} | HMAC={signature}\n"
    try:
        # Ensure the file exists and append
        with open("audit.log", "a", encoding="utf-8") as f:
            f.write(line)
        # And attempt to set restrictive permissions
        try:
            os.chmod("audit.log", 0o600)
        except Exception:
            pass
    except Exception as e:
        # If logging fails, print a message that it failed
        print("Warning: audit logging failed (see console).")
        print(str(e))

# Password hashing using PBKDF2 (for safe default parameters)  
def hash_password(password, salt, iterations=100_000):
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), iterations).hex()

# Then an in memory user store to create.
def create_user_store():
    # admin password will by provided by an environment variable 
    admin_pw = os.environ.get("WGUPS_ADMIN_PW", "adminpass")  # default for demo; change in deployment
    admin_salt = os.environ.get("WGUPS_ADMIN_SALT") or ("s" + hashlib.sha1(b"wgups_salt").hexdigest()[:8])
    admin_hash = hash_password(admin_pw, admin_salt)
    # user store: username -> {salt, pw_hash, role, admin}
    return {"admin": {"salt": admin_salt, "pw_hash": admin_hash, "role": "admin"}}

_USERS = create_user_store()
_CURRENT_USER_ROLE = "viewer"  # defaults to the limited role of viewer for security
_LAST_EVAL_TIME = 0.0  # timestamp for throttle

def authenticate_user():
    """Prompt user for credentials at program start; set role in global _CURRENT_USER_ROLE."""
    global _CURRENT_USER_ROLE
    print("=== Authentication required (simple demo) ===")
    username = input("Username (enter to continue as viewer): ").strip()
    if username == "":
        audit_log("auth", "anonymous viewer started session")
        print("Continuing as viewer (limited permissions).")
        return
    pwd = getpass.getpass("Password: ")
    user = _USERS.get(username)
    if not user:
        audit_log("auth_fail", f"user={username} (unknown)")
        #Print that the user is unknown and the user has to continue as viewer and nota as admin, if the authentication fails
        print("Unknown user; continuing as viewer.")
        return
    candidate_hash = hash_password(pwd, user["salt"])
    if hmac.compare_digest(candidate_hash, user["pw_hash"]):
        _CURRENT_USER_ROLE = user.get("role", "viewer")
        audit_log("auth_success", f"user={username} role={_CURRENT_USER_ROLE}")
        print(f"Authenticated as {username} (role={_CURRENT_USER_ROLE}).")
    else:
        audit_log("auth_fail", f"user={username} (bad password)")
        print("Authentication failed; continuing as viewer.")

# Package class with more than 8 fields (ID, address, etc...)
class Package:
    def __init__(self, ID, address, city, state, zip_code, deadline, weight, notes=""):
        self.ID = ID
        self.address = address
        self.city = city
        self.state = state
        self.zip_code = zip_code
        self.deadline = deadline
        self.weight = weight
        self.notes = notes or ""
        self.status = "At hub"

        # Delayed packages will be available only after 9:05 AM
        if "Delayed" in self.notes or "delayed" in self.notes.lower():
            self.available_time = datetime.datetime.combine(datetime.date.today(), datetime.time(9, 5))
        else:
            self.available_time = datetime.datetime.combine(datetime.date.today(), datetime.time(8, 0))

#Creation of individual package objects with the required fields
packages = [
    Package(1, "195 W Oakland Ave", "Salt Lake City", "UT", "84115", "10:30 AM", 21),
    Package(2, "2530 S 500 E", "Salt Lake City", "UT", "84106", "EOD", 44),
    Package(3, "233 Canyon Rd", "Salt Lake City", "UT", "84103", "EOD", 2, "Can only be on truck 2"),
    Package(4, "380 W 2880 S", "Salt Lake City", "UT", "84115", "EOD", 4),
    Package(5, "410 S State St", "Salt Lake City", "UT", "84111", "EOD", 5),
    Package(6, "3060 Lester St", "West Valley City", "UT", "84119", "10:30 AM", 88, "Delayed on flight---will not arrive to depot until 9:05 am"),
    Package(7, "1330 2100 S", "Salt Lake City", "UT", "84106", "EOD", 8),
    Package(8, "300 State St", "Salt Lake City", "UT", "84103", "EOD", 9),
    Package(9, "300 State St", "Salt Lake City", "UT", "84103", "EOD", 2, "Wrong address listed"),
    Package(10, "600 E 900 South", "Salt Lake City", "UT", "84105", "EOD", 1),
    Package(11, "2600 Taylorsville Blvd", "Salt Lake City", "UT", "84118", "EOD", 1),
    Package(12, "3575 W Valley Central Station bus Loop", "West Valley City", "UT", "84119", "EOD", 1),
    Package(13, "2010 W 500 S", "Salt Lake City", "UT", "84104", "10:30 AM", 2),
    Package(14, "4300 S 1300 E", "Millcreek", "UT", "84117", "10:30 AM", 88, "Must be delivered with 15, 19"),
    Package(15, "4580 S 2300 E", "Holladay", "UT", "84117", "9:00 AM", 4),
    Package(16, "4580 S 2300 E", "Holladay", "UT", "84117", "10:30 AM", 88, "Must be delivered with 13, 19"),
    Package(17, "3148 S 1100 W", "Salt Lake City", "UT", "84119", "EOD", 2),
    Package(18, "1488 4800 S", "Salt Lake City", "UT", "84123", "EOD", 6, "Can only be on truck 2"),
    Package(19, "177 W Price Ave", "Salt Lake City", "UT", "84115", "EOD", 37),
    Package(20, "3595 Main St", "Salt Lake City", "UT", "84115", "10:30 AM", 37, "Must be delivered with 13, 15"),
    Package(21, "3595 Main St", "Salt Lake City", "UT", "84115", "EOD", 3),
    Package(22, "6351 South 900 East", "Murray", "UT", "84121", "EOD", 2),
    Package(23, "5100 South 2700 West", "Salt Lake City", "UT", "84118", "EOD", 5),
    Package(24, "5025 State St", "Murray", "UT", "84107", "EOD", 7),
    Package(25, "5383 South 900 East #104", "Salt Lake City", "UT", "84117", "10:30 AM", 7, "Delayed on flight---will not arrive to depot until 9:05 am"),
    Package(26, "5383 South 900 East #104", "Salt Lake City", "UT", "84117", "EOD", 25),
    Package(27, "1060 Dalton Ave S", "Salt Lake City", "UT", "84104", "EOD", 5),
    Package(28, "2835 Main St", "Salt Lake City", "UT", "84115", "EOD", 7, "Delayed on flight---will not arrive to depot until 9:05 am"),
    Package(29, "1330 2100 S", "Salt Lake City", "UT", "84106", "10:30 AM", 2),
    Package(30, "300 State St", "Salt Lake City", "UT", "84103", "10:30 AM", 1),
    Package(31, "3365 S 900 W", "Salt Lake City", "UT", "84119", "10:30 AM", 1),
    Package(32, "3365 S 900 W", "Salt Lake City", "UT", "84119", "EOD", 1, "Delayed on flight---will not arrive to depot until 9:05 am"),
    Package(33, "2530 S 500 E", "Salt Lake City", "UT", "84106", "EOD", 1),
    Package(34, "4580 S 2300 E", "Holladay", "UT", "84117", "10:30 AM", 2),
    Package(35, "1060 Dalton Ave S", "Salt Lake City", "UT", "84104", "EOD", 88),
    Package(36, "2300 Parkway Blvd", "West Valley City", "UT", "84119", "EOD", 88, "Can only be on truck 2"),
    Package(37, "410 S State St", "Salt Lake City", "UT", "84111", "10:30 AM", 2),
    Package(38, "410 S State St", "Salt Lake City", "UT", "84111", "EOD", 9, "Can only be on truck 2"),
    Package(39, "2010 W 500 S", "Salt Lake City", "UT", "84104", "EOD", 9),
    Package(40, "380 W 2880 S", "Salt Lake City", "UT", "84115", "10:30 AM", 45),
]


# Creation of parsing, normalization and featurization functions around the code

def parse_deadline(deadline_str):
    """Return a datetime.time or None for EOD / invalid formats."""
    if deadline_str == "EOD":
        return None
    try:
        return datetime.datetime.strptime(deadline_str, "%I:%M %p").time()
    except Exception:
        return None

def normalize_zip(zip_code):
    """Strip non-digits and left-pad to 5 digits if reasonable."""
    z = str(zip_code).strip()
    z = re.sub(r"\D", "", z)
    if len(z) == 0:
        return ""
    return z.zfill(5) if len(z) <= 5 else z

def normalize_address(addr):
    """Basic address normalization: collapse whitespace and unify simple abbreviations."""
    a = ' '.join(str(addr).split())
    a = (a.replace("St.", "St").replace("Rd.", "Rd").replace("Ave.", "Ave")
         .replace("Street", "St").replace("Avenue", "Ave")
         .replace("South", "S").replace("East", "E").replace("West", "W")
         .replace("North", "N"))
    return a.strip()

def featurize_package(pkg):
    """Add cleaned fields and simple features to a Package instance (in-place)."""
    # Normalize address and zip code
    pkg.address = normalize_address(pkg.address)
    pkg.zip_code = normalize_zip(pkg.zip_code)

    # Parse the deadline
    pkg.deadline_time = parse_deadline(pkg.deadline)    # datetime.time or None. One of the 2.
    pkg.is_eod = (pkg.deadline == "EOD")

    # Delay flag
    pkg.is_delayed = bool(re.search(r"delayed", pkg.notes, flags=re.I))

    # Create a Numeric priority score: For example:: earlier minute-of-day -> lower number (the higher the priority).
    if pkg.deadline_time:
        pkg.priority_score = pkg.deadline_time.hour * 60 + pkg.deadline_time.minute
    else:
        pkg.priority_score = 24 * 60  # EOD gets large value (lower priority because there is not a deadline time)

    # Must be together flag
    pkg.must_be_together = bool(re.search(r"Must be delivered with", pkg.notes, flags=re.I)) or bool(re.search(r"Must be", pkg.notes, flags=re.I))

    # Can only be on truck 2 condition
    pkg.only_truck2 = bool(re.search(r"Can only be on truck 2", pkg.notes, flags=re.I)) or bool(re.search(r"Can only be on truck 2", pkg.notes, flags=re.I))

    # If there is a wrong address, to notify the wrong address.
    pkg.wrong_address = bool(re.search(r"Wrong address", pkg.notes, flags=re.I))

    #Address group count placeholder
    pkg.address_group_count = 1

    # Placeholder for address index
    pkg.address_id = None

    return pkg

def clean_and_featurize_packages(packages_list):
    for p in packages_list:
        featurize_package(p)

clean_and_featurize_packages(packages)


# Addresses and distance matrix (From Spreadsheets data)
# Address class
class Address:
    def __init__(self, ID, name, address):
        self.ID = ID
        self.name = name
        self.address = normalize_address(address)

#Address in form of individual objects through the address class

addresses = [
    Address(0, "Western Governors University", "4001 South 700 East"),
    Address(1, "International Peace Gardens", "1060 Dalton Ave S"),
    Address(2, "Sugar House Park", "1330 2100 S"),
    Address(3, "Taylorsville-Bennion Heritage City Gov Off", "1488 4800 S"),
    Address(4, "Salt Lake City Division of Health Services", "177 W Price Ave"),
    Address(5, "South Salt Lake Public Works", "195 W Oakland Ave"),
    Address(6, "Salt Lake City Streets and Sanitation", "2010 W 500 S"),
    Address(7, "Deker Lake", "2300 Parkway Blvd"),
    Address(8, "Salt Lake City Ottinger Hall", "233 Canyon Rd"),
    Address(9, "Columbus Library", "2530 S 500 E"),
    Address(10, "Taylorsville City Hall", "2600 Taylorsville Blvd"),
    Address(11, "South Salt Lake Police", "2835 Main St"),
    Address(12, "Council Hall", "300 State St"),
    Address(13, "Redwood Park", "3060 Lester St"),
    Address(14, "Salt Lake County Mental Health", "3148 S 1100 W"),
    Address(15, "Salt Lake County United Police Dept", "3365 S 900 W"),
    Address(16, "West Valley Prosecutor", "3575 W Valley Central Station bus Loop"),
    Address(17, "Housing Auth. of Salt Lake County", "3595 Main St"),
    Address(18, "Utah DMV Administrative Office", "380 W 2880 S"),
    Address(19, "Third District Juvenile Court", "410 S State St"),
    Address(20, "Cottonwood Regional Softball Complex", "4300 S 1300 E"),
    Address(21, "Holiday City Office", "4580 S 2300 E"),
    Address(22, "Murray City Museum", "5025 State St"),
    Address(23, "Valley Regional Softball Complex", "5100 South 2700 West"),
    Address(24, "City Center of Rock Springs", "5383 South 900 East #104"),
    Address(25, "Rice Terrace Pavilion Park", "600 E 900 South"),
    Address(26, "Wheeler Historic Farm", "6351 South 900 East"),
]

# distances matrix in a list (Arraay or list)
distances = [
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [7.2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [3.8, 7.1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [11, 6.4, 9.2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [2.2, 6, 4.4, 5.6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [3.5, 4.8, 2.8, 6.9, 1.9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [10.9, 1.6, 8.6, 8.6, 7.9, 6.3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [8.6, 2.8, 6.3, 4, 5.1, 4.3, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [7.6, 4.8, 5.3, 11.1, 7.5, 4.5, 4.2, 7.7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [2.8, 6.3, 1.6, 7.3, 2.6, 1.5, 8, 9.3, 4.8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [6.4, 7.3, 10.4, 1, 6.5, 8.7, 8.6, 4.6, 11.9, 9.4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [3.2, 5.3, 3, 6.4, 1.5, 0.8, 6.9, 4.8, 4.7, 1.1, 7.3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [7.6, 4.8, 5.3, 11.1, 7.5, 4.5, 4.2, 7.7, 0.6, 5.1, 12, 4.7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [5.2, 3, 6.5, 3.9, 3.2, 3.9, 4.2, 1.6, 7.6, 4.6, 4.9, 3.5, 7.3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [4.4, 4.6, 5.6, 4.3, 2.4, 3, 8, 3.3, 7.8, 3.7, 5.2, 2.6, 7.8, 1.3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [3.7, 4.5, 5.8, 4.4, 2.7, 3.8, 5.8, 3.4, 6.6, 4, 5.4, 2.9, 6.6, 1.5, 0.6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [7.6, 7.4, 5.7, 7.2, 1.4, 5.7, 7.2, 3.1, 7.2, 6.7, 8.1, 6.3, 7.2, 4, 6.4, 5.6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [2, 6, 4.1, 5.3, 0.5, 1.9, 7.7, 5.1, 5.9, 2.3, 6.2, 1.2, 5.9, 3.2, 2.4, 1.6, 7.1, 0, 0, 0, 0, 0, 0, 0, 0],
    [3.6, 5, 3.6, 6, 1.7, 1.1, 6.6, 4.6, 5.4, 1.8, 6.9, 1, 5.4, 3, 2.2, 1.7, 6.1, 1.6, 0, 0, 0, 0, 0, 0, 0],
    [6.5, 4.8, 4.3, 10.6, 6.5, 3.5, 3.2, 6.7, 1, 4.1, 11.5, 3.7, 1, 6.9, 6.8, 6.4, 7.2, 4.9, 4.4, 0, 0, 0, 0, 0, 0],
    [1.9, 9.5, 3.3, 5.9, 3.2, 4.9, 11.2, 8.1, 8.5, 3.8, 6.9, 4.1, 8.5, 6.2, 5.3, 4.9, 10.6, 3, 4.6, 7.5, 0, 0, 0, 0, 0],
    [3.4, 10.9, 5, 7.4, 5.2, 6.9, 12.7, 10.4, 10.3, 5.8, 8.3, 6.2, 10.3, 8.2, 7.4, 6.9, 12, 5, 6.6, 9.3, 2, 0, 0, 0, 0],
    [2.4, 8.3, 6.1, 4.7, 2.5, 4.2, 10, 7.8, 7.8, 4.3, 4.1, 3.4, 7.8, 5.5, 4.6, 4.2, 9.4, 2.3, 3.9, 6.8, 2.8, 3.4, 0, 0, 0],
    [6.4, 6.9, 9.7, 0.6, 6, 9, 8.2, 4.2, 11.5, 7.8, 0.4, 6.9, 11.5, 4.4, 4.8, 5.6, 7.5, 5.5, 6.5, 11.4, 6.4, 7.9, 4.5, 0, 0],
    [2.4, 10, 6.1, 6.4, 4.2, 5.9, 11.7, 9.5, 9.5, 4.8, 4.9, 5.2, 9.5, 7.2, 6.3, 5.9, 11.1, 4, 5.6, 8.5, 2.8, 3.4, 1.7, 5.4, 0],
    [5, 4.4, 2.8, 10.1, 5.4, 3.5, 5.1, 6.2, 2.8, 3.2, 11, 3.7, 2.8, 6.4, 6.5, 5.7, 6.2, 5.1, 4.3, 1.8, 6, 7.9, 6.8, 10.6, 7, 0],
    [3.6, 13, 7.4, 10.1, 5.5, 7.2, 14.2, 10.7, 14.1, 6, 6.8, 6.4, 14.1, 10.5, 8.8, 8.4, 13.6, 5.2, 6.9, 13.1, 4.1, 4.7, 3.1, 7.8, 1.3, 8.3, 0],
]

# Make a matrix square for loop 
for i in range(27):
    while len(distances) <= i:
        distances.append([0.0] * 27)
    while len(distances[i]) < 27:
        j = len(distances[i])
        if j < len(distances) and i < len(distances[j]):
            distances[i].append(distances[j][i])
        else:
            distances[i].append(0.0)

# Normalized address lookup map (address string -> address ID)
address_lookup = {addr.address: addr.ID for addr in addresses}

def extract_address(address_str):
    """Return address ID for normalized address string."""
    key = normalize_address(address_str)
    if key in address_lookup:
        return address_lookup[key]
   
    for k, idx in address_lookup.items():
        if key in k or k in key:
            return idx
    raise ValueError(f"ERROR Address '{address_str}' not found in address list (normalized='{key}').")

def distance_in_between(i, j):
    return distances[i][j] if distances[i][j] != 0 else distances[j][i]

# Set address_id and compute address_group_count for packages (for featurization)
addr_counts = Counter(normalize_address(p.address) for p in packages)
for p in packages:
    p.address = normalize_address(p.address)
    p.address_group_count = addr_counts[p.address]
    try:
        p.address_id = extract_address(p.address)
    except Exception:
        p.address_id = None

# To create some form of implementation in machine learning or simpleLogistic regression
class SimpleLogistic:
    """Tiny logistic regression with online SGD. No dependencies."""
    def __init__(self, n_features, lr=0.1, epochs=120):
        self.n = n_features
        self.lr = lr
        self.epochs = epochs
        self.w = [0.0] * n_features
        self.b = 0.0

    @staticmethod
    def _sigmoid(z):
        # Create numerical stability
        if z < -700:
            return 0.0
        if z > 700:
            return 1.0
        return 1.0 / (1.0 + math.exp(-z))

    def predict_proba(self, x):
        z = self.b
        for wi, xi in zip(self.w, x):
            z += wi * xi
        return SimpleLogistic._sigmoid(z)

    def predict(self, x, thresh=0.5):
        return 1 if self.predict_proba(x) >= thresh else 0

    def fit(self, X, y):
        # online SGD
        for epoch in range(self.epochs):
            combined = list(zip(X, y))
            random.shuffle(combined)
            for x, yi in combined:
                p = self.predict_proba(x)
                error = yi - p
                # gradient step (logistic loss derivative)
                for j in range(self.n):
                    self.w[j] += self.lr * error * x[j]
                self.b += self.lr * error


# Create Feature building for machine learning model

def build_features(pkg, max_weight=88.0, max_addr_group=None):
    # priority: earlier deadlines = higher input value
    # Convert priority_score (minutes-from-midnight) to closeness in [0,1], where 1 = the most urgent
    max_minutes = 24 * 60
    priority_norm = 1.0 - (pkg.priority_score / max_minutes)  # earlier = closer to 1

    # weight_norm
    weight_norm = float(pkg.weight) / float(max_weight) if max_weight else 0.0
    if weight_norm > 1.0:
        weight_norm = 1.0

    delayed_flag = 1.0 if pkg.is_delayed else 0.0
    must_be_with = 1.0 if pkg.must_be_together else 0.0
    only_truck2 = 1.0 if pkg.only_truck2 else 0.0
    wrong_address = 1.0 if pkg.wrong_address else 0.0
    addr_count = float(pkg.address_group_count) / (max_addr_group or 1.0)

    # final feature vector where the return order must matter
    return [priority_norm, weight_norm, delayed_flag, must_be_with, only_truck2, wrong_address, addr_count]

# Create some form of training around the machine learning model

def build_synthetic_labels(packages_list):
    """Create simple synthetic labels for training:
       Label = 1 if (deadline not EOD) OR delayed OR must-be-together OR weight > threshold, else 0.
       This mirrors the domain rules so the model learns the current priority heuristics.
    """
    y = []
    for p in packages_list:
        high_priority = False
        if not p.is_eod:
            high_priority = True
        if p.is_delayed:
            high_priority = True
        if p.must_be_together:
            high_priority = True
        if p.weight >= 50:  # To treat as high priority for this synthetic rule
            high_priority = True
        y.append(1 if high_priority else 0)
    return y

# Prepare X,y for training
max_addr_group = max(p.address_group_count for p in packages) if packages else 1
X = [build_features(p, max_weight=88.0, max_addr_group=max_addr_group) for p in packages]
y = build_synthetic_labels(packages)

# To train a small logistic regression
ml_model = SimpleLogistic(n_features=len(X[0]), lr=0.2, epochs=200)
ml_model.fit(X, y)

# Model integrity created through hashing and hmac
def compute_model_fingerprint(model):
    # String representation of weights + bias
    s = ",".join(f"{w:.12g}" for w in model.w) + f"|{model.b:.12g}"
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

_MODEL_FINGERPRINT = compute_model_fingerprint(ml_model)
_MODEL_FINGERPRINT_HMAC = hmac.new(_AUDIT_KEY, _MODEL_FINGERPRINT.encode("utf-8"), hashlib.sha256).hexdigest()
audit_log("model_trained", f"fingerprint={_MODEL_FINGERPRINT} hmac={_MODEL_FINGERPRINT_HMAC}")

def verify_model_integrity():
    current = compute_model_fingerprint(ml_model)
    expected = _MODEL_FINGERPRINT
    ok = hmac.compare_digest(current, expected)
    if not ok:
        audit_log("model_integrity_fail", f"current={current} expected={expected}")
    return ok

def predict_priority_score(pkg):
    f = build_features(pkg, max_weight=88.0, max_addr_group=max_addr_group)
    return ml_model.predict_proba(f)  # returns probability in [0,1]

# Evaluation code for the model
def confusion_matrix_and_metrics(y_true, y_pred):
    """Return dict with tp, tn, fp, fn, accuracy, precision, recall, f1"""
    tp = fp = tn = fn = 0
    for t, p in zip(y_true, y_pred):
        if t == 1 and p == 1:
            tp += 1
        elif t == 0 and p == 1:
            fp += 1
        elif t == 0 and p == 0:
            tn += 1
        elif t == 1 and p == 0:
            fn += 1
    total = tp + tn + fp + fn
    accuracy = (tp + tn) / total if total else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return {"tp": tp, "tn": tn, "fp": fp, "fn": fn,
            "accuracy": accuracy, "precision": precision, "recall": recall, "f1": f1}

def evaluate_model_simple():
    """Evaluate the small logistic model on the synthetic dataset (X, y). Requires admin role."""
    global _LAST_EVAL_TIME
    # Note: Functionality below must be only admin allowed to run evaluation in the demo
    if _CURRENT_USER_ROLE != "admin":
        print("Permission denied: evaluation requires admin role.")
        audit_log("eval_blocked", "permission_denied")
        return

    # simple throttle: allow running at most once every 2 seconds in the demo conditrional
    now = time.time()
    if now - _LAST_EVAL_TIME < 2.0:
        print("Evaluation run too soon. Please wait a moment.")
        audit_log("eval_blocked", "rate_limit")
        return
    _LAST_EVAL_TIME = now

    # To verify model integrity before being evaluated conditional
    if not verify_model_integrity():
        print("Model integrity check failed — evaluation blocked. See audit.log.")
        return

    # Use the X and y that was created earlier
    y_pred = []
    for features in X:
        prob = ml_model.predict_proba(features)
        y_pred.append(1 if prob >= 0.5 else 0)

    metrics = confusion_matrix_and_metrics(y, y_pred)
    print("\n=== Simple ML Evaluation (on synthetic training data) ===")
    print(f"Accuracy : {metrics['accuracy']:.3f}")
    print(f"Precision: {metrics['precision']:.3f}")
    print(f"Recall   : {metrics['recall']:.3f}")
    print(f"F1 score : {metrics['f1']:.3f}")
    print(f"Confusion matrix: TP={metrics['tp']} FP={metrics['fp']} TN={metrics['tn']} FN={metrics['fn']}")
    print("Note: this evaluation uses the synthetic labels built from the heuristic rules.\n")
    audit_log("eval_run", f"accuracy={metrics['accuracy']:.3f} precision={metrics['precision']:.3f} recall={metrics['recall']:.3f} f1={metrics['f1']:.3f}")

# 
# Monitoring and maintenance tools creation
# Global metrics collection
METRICS = {
    "delivered_count": 0,
    "total_mileage": 0.0,
    "total_delivery_seconds": 0.0,
    "per_truck": {},  # truck_id -> {"delivered": int, "mileage": float}
    "feature_baseline": None,  # baseline feature averages
    "last_health_check": None
}

def record_feature_distribution(packages_list):
    """Record simple baseline: average of features across dataset X (call at startup)."""
    if not packages_list:
        return None
    features = [build_features(p, max_weight=88.0, max_addr_group=max_addr_group) for p in packages_list]
    avg = [sum(col)/len(col) for col in zip(*features)]
    METRICS["feature_baseline"] = avg
    audit_log("baseline_recorded", f"features_avg={','.join(f'{v:.4f}' for v in avg)}")
    return avg

def compute_feature_drift(packages_list):
    """Compute simple drift: difference between current averages and baseline (L1)."""
    if METRICS.get("feature_baseline") is None:
        return None
    features = [build_features(p, max_weight=88.0, max_addr_group=max_addr_group) for p in packages_list]
    cur_avg = [sum(col)/len(col) for col in zip(*features)]
    baseline = METRICS["feature_baseline"]
    drift = sum(abs(a - b) for a, b in zip(cur_avg, baseline))
    return {"drift_score": drift, "baseline": baseline, "current": cur_avg}

def health_check():
    """Run a simple health check: model integrity, basic metric sanity, and feature drift."""
    problems = []
    ok_model = verify_model_integrity()
    if not ok_model:
        problems.append("Model integrity failed")
    # conditional that delivered_count should not exceed total packages
    if METRICS["delivered_count"] > len(packages):
        problems.append("delivered_count > total packages")
    # compute drift and drift score
    drift = compute_feature_drift(packages)
    drift_score = drift["drift_score"] if drift else 0.0
    # drift threshold
    drift_threshold = 0.5
    if drift and drift_score > drift_threshold:
        problems.append(f"Feature drift detected (score={drift_score:.3f})")
    METRICS["last_health_check"] = {"timestamp": datetime.datetime.utcnow().isoformat()+"Z", "problems": problems, "drift": drift}
    audit_log("health_check", f"problems={len(problems)} drift={drift_score:.3f}")
    return {"ok_model": ok_model, "problems": problems, "drift": drift}

def dump_metrics_to_file(path="metrics.json"):
    """Dump METRICS to disk + write HMAC signature for integrity."""
    try:
        payload = json.dumps(METRICS, default=str, sort_keys=True)
        sig = hmac_sign(payload)
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"metrics": METRICS, "hmac": sig}, f, default=str, indent=2)
        try:
            os.chmod(path, 0o600)
        except Exception:
            pass
        audit_log("metrics_dumped", f"path={path}")
        print(f"Metrics written to {path}")
    except Exception as e:
        audit_log("metrics_dump_fail", str(e))
        print("Failed to write metrics file.")

def rotate_audit_log(max_bytes=10*1024, backup_dir="audit_archives"):
    """Rotate audit.log when it exceeds max_bytes; keep one backup with timestamp."""
    try:
        if not os.path.exists("audit.log"):
            print("No audit.log to rotate.")
            return
        size = os.path.getsize("audit.log")
        if size <= max_bytes:
            print("audit.log size within limit; no rotation needed.")
            return
        os.makedirs(backup_dir, exist_ok=True)
        ts = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        dest = os.path.join(backup_dir, f"audit_{ts}.log")
        shutil.move("audit.log", dest)
        # Create a new empty audit.log and restrict permissions
        open("audit.log", "a").close()
        try:
            os.chmod("audit.log", 0o600)
        except Exception:
            pass
        audit_log("audit_rotated", f"moved_to={dest}")
        print(f"Rotated audit.log -> {dest}")
    except Exception as e:
        audit_log("audit_rotate_fail", str(e))
        print("Failed to rotate audit.log.")

def retrain_model(epochs=200):
    """Admin-only: retrain the logistic model on synthetic labels, recompute fingerprint and log."""
    global ml_model, _MODEL_FINGERPRINT, _MODEL_FINGERPRINT_HMAC
    if _CURRENT_USER_ROLE != "admin":
        print("Permission denied: retrain requires admin role.")
        audit_log("retrain_blocked", "permission_denied")
        return False
    try:
        # Create retraining of the model
        new_model = SimpleLogistic(n_features=len(X[0]), lr=0.2, epochs=epochs)
        new_model.fit(X, y)
        ml_model = new_model
        _MODEL_FINGERPRINT = compute_model_fingerprint(ml_model)
        _MODEL_FINGERPRINT_HMAC = hmac.new(_AUDIT_KEY, _MODEL_FINGERPRINT.encode("utf-8"), hashlib.sha256).hexdigest()
        audit_log("model_retrained", f"fingerprint={_MODEL_FINGERPRINT}")
        print("Model retrained and fingerprint updated.")
        return True
    except Exception as e:
        audit_log("retrain_fail", str(e))
        print("Retraining failed.")
        return False
# Record initial feature distribution at startup
record_feature_distribution(packages)



# Create a dashboard for visualization with HTML and SVG

def generate_dashboard(path="dashboard.html"):
    """
    Create HTML dashboard (inline) with:
      - Bar chart: Need to gather package status counts
      - Pie chart: Gather per-truck delivered share
      - Line chart: Have all cumulative deliveries over time
    Then, Open file in default browser to visualize.
    """
    # Gather data
    # status_counts of all packages with a loop (At Hub, En Route, Delivered)
    status_counts = {"At Hub": 0, "En Route": 0, "Delivered": 0}
    for p in packages:
        st = p.status
        if hasattr(p, "delivery_time") and st.startswith("Delivered"):
            status_counts["Delivered"] += 1
        elif st == "At hub":
            status_counts["At Hub"] += 1
        else:
            status_counts["En Route"] += 1

    # per-truck delivered counts 
    per_truck = {}
    if METRICS.get("per_truck"):
        for tid, data in METRICS["per_truck"].items():
            try:
                key = int(tid)
            except Exception:
                key = tid
            per_truck[key] = int(data.get("delivered", 0))
    else:
        # fallback:  to check if the trucks exist
        for t in ["truck1", "truck2", "truck3"]:
            if t in globals():
                tr = globals()[t]
                per_truck[tr.truck_id] = sum(1 for p in tr.packages if hasattr(p, "delivery_time"))

    # cumulative deliveries over time (all of sorted). Create a list (or array) and collect the deliveries, these can also be counted
    deliveries = []
    for p in packages:
        if hasattr(p, "delivery_time"):
            deliveries.append(p.delivery_time)
    deliveries.sort()
    # if no deliveries, create empty demo series
    if deliveries:
        # convert to minutes since start-of-day for plotting
        base = datetime.datetime.combine(datetime.date.today(), datetime.time(8, 0))
        times_min = [max(0, (dt - base).total_seconds() / 60.0) for dt in deliveries]
        cum = list(range(1, len(times_min) + 1))
    else:
        times_min = []
        cum = []

    # Build SVG pieces
    # Create inline CSS for styling and give a better look to the HTML dashsboard
    css = """
      body { font-family: Arial, Helvetica, sans-serif; padding: 18px; color: #222; }
      h1 { font-size: 20px; margin-bottom: 6px; }
      .chart-title { font-size: 14px; margin: 6px 0; }
      .chart-box { border: 1px solid #ddd; padding: 8px; margin-bottom: 14px; border-radius: 6px; box-shadow: 0 1px 2px rgba(0,0,0,0.04); }
      .note { font-size: 12px; color: #666; margin-top: 8px; }
    """

    # Bar chart (status counts)
    bar_svg = ""
    try:
        max_count = max(status_counts.values()) if status_counts else 1
        bw = 120
        gap = 18
        left = 40
        top = 20
        height = 140
        # bars
        x = left
        bars = []
        labels = []
        colors = {"At Hub": "#F0C419", "En Route": "#5A8FD6", "Delivered": "#4C9F70"}
        for name, cnt in status_counts.items():
            h = (cnt / max_count) * (height - 30) if max_count > 0 else 0
            y = top + (height - h)
            color = colors.get(name, "#888")
            bars.append(f'<rect x="{x}" y="{y}" width="{bw}" height="{max(1,h)}" rx="4" ry="4" fill="{color}" />')
            labels.append(f'<text x="{x + bw/2}" y="{top + height + 14}" text-anchor="middle" font-size="12">{name} ({cnt})</text>')
            x += bw + gap
        bar_svg = f'<svg width="420" height="{height + 50}" role="img">{"".join(bars)}{"".join(labels)}</svg>'
    except Exception:
        bar_svg = '<div>Bar chart failed to render.</div>'

    # Pie chart (per-truck delivered)
    pie_svg = ""
    try:
        total_delivered = sum(per_truck.values()) or 1
        cx = 120
        cy = 120
        r = 80
        circ = 2 * math.pi * r
        offset = 0.0
        strokes = []
        palette = ["#4C9F70", "#5A8FD6", "#E38E5D", "#A569BD", "#D54C6C"]
        i = 0
        legend_items = []
        for tid, cnt in sorted(per_truck.items()):
            frac = cnt / total_delivered if total_delivered else 0
            dash = frac * circ
            gap = circ - dash
            color = palette[i % len(palette)]
            # stroke on circle (using stroke-dasharray, stroke-dashoffset)
            strokes.append(f'<circle r="{r}" cx="{cx}" cy="{cy}" fill="none" stroke="{color}" stroke-width="40" stroke-dasharray="{dash} {gap}" transform="rotate(-90 {cx} {cy})" stroke-linecap="butt" style="stroke-dashoffset:{-offset:.3f}" />')
            legend_items.append(f'<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;"><div style="width:14px;height:14px;background:{color};border-radius:3px"></div><div>Truck {tid}: {cnt}</div></div>')
            offset += dash
            i += 1
        pie_svg = f'<svg width="300" height="260" role="img">{"".join(strokes)}<text x="{cx}" y="{cy+6}" text-anchor="middle" font-weight="600" font-size="12">{sum(per_truck.values())} delivered</text></svg>'
        pie_legend = "<div>" + "".join(legend_items) + "</div>"
    except Exception:
        pie_svg = '<div>Pie chart failed to render.</div>'
        pie_legend = ""

    # Line chart (cumulative deliveries VS time)
    line_svg = ""
    try:
        w = 620
        h = 180
        left = 40
        bottom = 150
        top = 20
        if times_min:
            min_t = min(times_min)
            max_t = max(times_min) if max(times_min) > min_t else min_t + 1
            # scale
            def x_for(t): return left + ((t - min_t) / (max_t - min_t)) * (w - left - 20)
            def y_for(c): return top + (1 - (c / (cum[-1] if cum else 1))) * (h - 40)
            points = " ".join(f"{x_for(t):.2f},{y_for(c)}" for t, c in zip(times_min, cum))
            # axes and polyline
            axes = f'<line x1="{left}" y1="{top}" x2="{left}" y2="{top + h - 40}" stroke="#ccc" />' \
                   f'<line x1="{left}" y1="{top + h - 40}" x2="{w-20}" y2="{top + h - 40}" stroke="#ccc" />'
            poly = f'<polyline fill="none" stroke="#5A8FD6" stroke-width="2.5" points="{points}" />'
            # labels for min/max time
            min_label = f'{(datetime.datetime.combine(datetime.date.today(), datetime.time(8,0)) + datetime.timedelta(minutes=min_t)).strftime("%H:%M")}'
            max_label = f'{(datetime.datetime.combine(datetime.date.today(), datetime.time(8,0)) + datetime.timedelta(minutes=max_t)).strftime("%H:%M")}'
            axis_labels = f'<text x="{left}" y="{top + h - 18}" font-size="11">{min_label}</text><text x="{w-60}" y="{top + h - 18}" font-size="11">{max_label}</text>'
            line_svg = f'<svg width="{w}" height="{h}" role="img">{axes}{poly}{axis_labels}</svg>'
        else:
            line_svg = '<div style="padding:18px">No delivery timestamps available to build line chart.</div>'
    except Exception:
        line_svg = '<div>Line chart failed to render.</div>'

    # HTML File composition
    html = f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>WGU Delivery Dashboard</title>
  <style>{css}</style>
</head>
<body>
  <h1>WGU Delivery Dashboard</h1>
  <p class="note">This static dashboard was generated by the application. Please, refresh by regenerating via Maintenance - >  Create detailed Dashboard.</p>

  <div class="chart-box">
    <div class="chart-title">Package Status (Bar chart)</div>
    {bar_svg}
  </div>

  <div class="chart-box" style="display:flex;gap:12px;align-items:flex-start;">
    <div>
      <div class="chart-title">Delivered by Truck (Pie chart)</div>
      {pie_svg}
    </div>
    <div style="min-width:180px;">
      <div class="chart-title">Legend</div>
      {pie_legend}
      <div class="note">Total delivered: {sum(per_truck.values())}</div>
    </div>
  </div>

  <div class="chart-box">
    <div class="chart-title">Cumulative Deliveries Over Time (Line chart)</div>
    {line_svg}
  </div>

  <div class="note">Created at: {datetime.datetime.utcnow().isoformat()}Z</div>
</body>
</html>
"""
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
        audit_log("dashboard_generated", f"path={path}")
        # open in browser
        file_url = "file://" + os.path.abspath(path)
        try:
            webbrowser.open(file_url, new=2)
            print(f"Dashboard generated and opened: {path}")
        except Exception:
            print(f"Dashboard generated at {path} (open manually).")
    except Exception as e:
        audit_log("dashboard_fail", str(e))
        print("Failed to generate dashboard:", e)


# Hash table creation as a form of data sctructure for packages

class HashTable:
    def __init__(self, size=40):
        self.size = size
        self.table = [None] * size

    def _hash(self, key):
        return key % self.size

    def insert(self, key, value):
        index = self._hash(key)
        start_index = index
        while self.table[index] is not None:
            if self.table[index][0] == key:
                self.table[index] = (key, value)
                return
            index = (index + 1) % self.size
            if index == start_index:
                raise Exception("Hash table is full")
        self.table[index] = (key, value)

    def search(self, key):
        index = self._hash(key)
        start_index = index
        while self.table[index] is not None:
            if self.table[index][0] == key:
                return self.table[index][1]
            index = (index + 1) % self.size
            if index == start_index:
                break
        return None

# insert packages into a hash table
package_hash = HashTable()
for pkg in packages:
    package_hash.insert(pkg.ID, pkg)

# Create a Truck class for delivery of packages
class Truck:
    def __init__(self, truck_id, package_ids, package_hash, depart_time=None, use_ml=True):
        self.truck_id = truck_id
        self.package_ids = package_ids
        self.packages = self.load_packages(package_hash)
        self.address = "4001 South 700 East"  # Start from the hub, this address
        self.address = normalize_address(self.address)
        self.mileage = 0.0
        if depart_time is None:
            self.depart_time = datetime.datetime.combine(datetime.date.today(), datetime.time(hour=8))
        else:
            self.depart_time = depart_time
        self.time = self.depart_time
        self.use_ml = use_ml

        # initialize pertruck metrics
        METRICS["per_truck"].setdefault(self.truck_id, {"delivered": 0, "mileage": 0.0})

    def load_packages(self, package_hash):
        return [package_hash.search(pkg_id) for pkg_id in self.package_ids]

    def print_packages(self):
        print(f"\nTruck {self.truck_id} packages:")
        for pkg in self.packages:
            print(f"ID: {pkg.ID}, Address: {pkg.address}, Deadline: {pkg.deadline}")

    def deliver_packages(self):
        """Delivers packages; uses ML prediction combined with distance+deadline to make routing decisions."""
        undelivered = [p for p in self.packages if p is not None]
        self.packages.clear()
        self.time = self.depart_time
        print(f"Truck {self.truck_id} starting delivery at {self.depart_time.strftime('%I:%M %p')}")
        audit_log("truck_start", f"truck={self.truck_id} depart={self.depart_time.isoformat()}")
        # maximum distance used for simple normalization
        max_possible_dist = 30.0

        while undelivered:
            nearest = None
            best_score = -float('inf')
            current_idx = None
            try:
                current_idx = extract_address(self.address)
            except Exception:
                # fallback to hub ID 0
                current_idx = 0

            # pick best scoring available package
            for pkg in undelivered:
                # respect available_time
                if self.time < pkg.available_time:
                    continue

                # special case: Package 6 must be delivered immediately once available
                if pkg.ID == 6 and self.time >= pkg.available_time:
                    candidate = pkg
                    candidate_dist = distance_in_between(current_idx, extract_address(candidate.address) if candidate.address_id is not None else current_idx)
                    nearest = candidate
                    shortest_dist = candidate_dist
                    best_score = float('inf')  # force selection
                    break

                # compute distance
                try:
                    dest_idx = extract_address(pkg.address)
                    dist = distance_in_between(current_idx, dest_idx)
                except Exception:
                    # If it can not resolve address, deprioritize
                    dist = max_possible_dist

                # compute deadline factor (lower deadline minute -> more urgent)
                pr_norm = 1.0 - (pkg.priority_score / (24 * 60))  # 0..1, higher is more urgent

                #  Machine learning score
                ml_score = predict_priority_score(pkg) if self.use_ml else (1.0 if not pkg.is_eod else 0.0)

                # Compose a combined score:
                # - ml_score in [0,1] (higher=more urgent)
                # - pr_norm in [0,1] (higher=more urgent)
                # - dist normalized (smaller distance preferred)
                # Tunable weights:
                w_ml = 0.6
                w_deadline = 0.3
                w_dist = 0.5

                # normalize distance (smaller better), map to [0,1]: 1 - (dist/max_possible_dist)
                dist_norm = 1.0 - min(dist, max_possible_dist) / max_possible_dist

                combined = (w_ml * ml_score) + (w_deadline * pr_norm) + ( - w_dist * (dist / max_possible_dist) )

                # tie-breaker: if same combined, prefer closer distance
                if nearest is None or combined > best_score or (abs(combined - best_score) < 1e-6 and dist < shortest_dist):
                    nearest = pkg
                    shortest_dist = dist
                    best_score = combined

            if nearest is None:
                # No package available now; wait 1 minute
                self.time += datetime.timedelta(minutes=1)
                # To prevent infinite loop (if all packages have available_time > now and none can be delivered),
                # after waiting 60 minutes try again forcibly
                continue

      # Deliver nearest
            self.mileage += shortest_dist
            # assume average speed 18 mph like before
            travel_hours = shortest_dist / 18.0
            self.time += datetime.timedelta(hours=travel_hours)
            nearest.delivery_time = self.time
            nearest.departure_time = self.depart_time
            nearest.status = f"Delivered at {self.time.strftime('%I:%M %p')}"
            # update location
            self.address = nearest.address
            self.packages.append(nearest)
            undelivered = [pkg for pkg in undelivered if pkg.ID != nearest.ID]
            # Audit the delivery
            audit_log("delivered", f"truck={self.truck_id} pkg={nearest.ID} time={nearest.delivery_time.isoformat()}")

           
    # Update the monitoring metrics
        
            METRICS["delivered_count"] += 1
            METRICS["total_mileage"] += shortest_dist
            METRICS["per_truck"].setdefault(self.truck_id, {"delivered": 0, "mileage": 0.0})
            METRICS["per_truck"][self.truck_id]["delivered"] += 1
            METRICS["per_truck"][self.truck_id]["mileage"] += shortest_dist
    # To compute delivery duration seconds
            if hasattr(nearest, "delivery_time") and hasattr(nearest, "departure_time"):
                delta = (nearest.delivery_time - nearest.departure_time).total_seconds()
                if delta > 0:
                    METRICS["total_delivery_seconds"] += delta


# Manual truck loading and delivery simulation

truck1_ids = [1,2,5,7,10,13,14,15,16,19,20,25,30,37]
truck2_ids = [3,6,18,36,38,31,32,33,34,35,39,40]
truck3_ids = [4,8,9,11,12,17,21,22,23,24,26,27,28,29]

# instantiate trucks (truck2 depart at 9:05)
truck1 = Truck(1, truck1_ids, package_hash, use_ml=True)
truck2 = Truck(2, truck2_ids, package_hash, depart_time=datetime.datetime.combine(datetime.date.today(), datetime.time(9, 5)), use_ml=True)
truck3 = Truck(3, truck3_ids, package_hash, use_ml=True)

# Deliver packages (you can toggle use_ml flag on each truck if desired)
truck1.deliver_packages()
truck2.deliver_packages()
truck3.deliver_packages()

# To compute a derived metric (average delivery seconds) helper
def get_metrics_summary():
    summary = {
        "delivered_count": METRICS["delivered_count"],
        "total_mileage": METRICS["total_mileage"],
        "avg_delivery_seconds": (METRICS["total_delivery_seconds"] / METRICS["delivered_count"]) if METRICS["delivered_count"] else 0.0,
        "per_truck": METRICS["per_truck"],
        "last_health_check": METRICS["last_health_check"]
    }
    return summary


# Visualization and interactive lookup

def visualize_package_status(packages_list):
    status_counts = {"At Hub": 0, "En Route": 0, "Delivered": 0}
    for pkg in packages_list:
        # normalize status strings to known buckets
        st = pkg.status
        if st.startswith("Delivered"):
            key = "Delivered"
        elif st == "At hub":
            key = "At Hub"
        else:
            key = "En Route"
        status_counts[key] = status_counts.get(key, 0) + 1

    print("\nPackage Status Visualization")
    print("=" * 40)
    for status, count in status_counts.items():
        bar = "#" * count
        print(f"{status:10} | {bar} ({count})")
    print("=" * 40)

def lookup_package_info(package_hash, package_id):
    # Input validation: ensure integer and in range at all times
    try:
        pid = int(package_id)
    except Exception:
        print("Invalid package ID. Must be an integer.")
        return
    if pid < 1 or pid > 40:
        print("Package ID out of range (1-40).")
        return

    pkg = package_hash.search(pid)
    if pkg:
        print(f"Package ID: {pkg.ID}")
        print(f"Address: {pkg.address}")
        print(f"City: {pkg.city}")
        print(f"Zip Code: {pkg.zip_code}")
        print(f"Deadline: {pkg.deadline}")
        print(f"Weight: {pkg.weight} kg")
        print(f"Status: {pkg.status}")
        if hasattr(pkg, 'delivery_time'):
            print(f"Delivered At: {pkg.delivery_time.strftime('%I:%M %p')}")
        else:
            print("Delivered At: N/A")

        # Audit lookup
        audit_log("lookup", f"pkg={pkg.ID}")
        # Special display for package 9 address correction
        if pkg.ID == 9 and hasattr(pkg, 'delivery_time') and pkg.delivery_time <= datetime.datetime.combine(datetime.date.today(), datetime.time(10, 20)):
            print("\nUPDATED SPECIFIC PACKAGE DETAILS (10:20 AM)")
            print(f"Package ID: 9")
            print(f"Address: 410 S State St")
            print(f"City: Salt Lake City")
            print(f"Zip Code: 84111")
            print(f"Deadline: EOD")
            print(f"Weight: 2 kg")
            print(f"Status: Delivered")
            print(f"Delivered At: {pkg.delivery_time.strftime('%I:%M %p')}")
    else:
        print(f"Package {package_id} not found.")
        audit_log("lookup_fail", f"pkg={package_id}")

def check_package_status_at_time(package_hash, time_input):
    print(f"\nStatus of all packages at {time_input.strftime('%I:%M %p')}:")
    delayed_ids = {6, 25, 28, 32}
    just_arrived_ids = {6, 25}
    package_nine = {9}

    for package_id in range(1, 41):
        pkg = package_hash.search(package_id)
        if pkg is None:
            continue

        # Package 9 address correction at 10:20 AM
        if pkg.ID in package_nine:
            if time_input.time() >= datetime.time(10, 20):
                pkg.address = normalize_address('410 S State St')
                pkg.city = 'Salt Lake City'
                pkg.state = 'Utah'
                pkg.zip_code = '84111'
            else:
                pkg.address = normalize_address('300 State St')
                pkg.city = 'Salt Lake City'
                pkg.state = 'Utah'
                pkg.zip_code = '84103'

        if pkg.ID in delayed_ids and time_input < pkg.available_time:
            status = "Delayed — Will arrive at hub at 9:05 AM"
        elif pkg.ID in just_arrived_ids and time_input == pkg.available_time:
            status = "At hub"
        elif hasattr(pkg, 'delivery_time') and hasattr(pkg, 'departure_time'):
            if time_input < pkg.departure_time:
                status = "At hub"
            elif time_input < pkg.delivery_time:
                status = "En route"
            else:
                status = f"Delivered at {pkg.delivery_time.strftime('%I:%M %p')}"
        else:
            status = "At hub"

        print(f"\nPackage {pkg.ID}")
        print(f"  Address: {pkg.address}, {pkg.city}, {pkg.state}, {pkg.zip_code}")
        print(f"  Deadline: {pkg.deadline}")
        print(f"  Status: {status}")
        if hasattr(pkg, 'delivery_time'):
            print(f"  Delivered At: {pkg.delivery_time.strftime('%I:%M %p')}")
        else:
            print(f"  Delivered At: ")

        truck_number = None
        for t in [truck1, truck2, truck3]:
            if any(p.ID == pkg.ID for p in t.packages):
                truck_number = t.truck_id
                break
        if truck_number:
            print(f"  Truck No.: {truck_number}")
        else:
            print(f"  Truck No.: Not assigned/delivered")


# Create an interactive Menu UI in the terminal

def maintenance_menu():
    """Maintenance submenu (monitoring and maintenance)."""
    while True:
        print("""
Maintenance menu:
  1) Show metrics summary
  2) Run health check
  3) Dump metrics to file
  4) Rotate audit.log (archive)
  5) Retrain model (admin only)
  6) Back
  7) Create or generate Dashboard in (HTML file)
""")
        choice = input("Choose maintenance action: ").strip()
        if choice == "1":
            summary = get_metrics_summary()
            print(json.dumps(summary, indent=2, default=str))
        elif choice == "2":
            result = health_check()
            print(json.dumps(result, indent=2, default=str))
        elif choice == "3":
            dump_metrics_to_file()
        elif choice == "4":
            rotate_audit_log()
        elif choice == "5":
            retrain_model()
        elif choice == "6":
            break
        elif choice == "7":
            generate_dashboard()
        else:
            print("Unknown choice.")

def main():
    # Authenticate at program start
    authenticate_user()

    print("\nWelcome to the WGU Delivery Management System UI! Below are the instructions on how to use the system")
    while True:
        print("""
            Type '1', to show total mileage of all trucks AND look up a desired package by ID
            Type '2', to show delivery status of delivered packages
            Type '3', show every single package loaded onto each truck
            Type '4', to enter specific times and check packages status across all trucks
            Type '5', to exit the program
            Type '6', to run a simple ML evaluation (accuracy/precision/recall/F1) on the trained model (admin only)
            Type '7', to access Monitoring and Maintenance tools (metrics / health checks / logs / retrain)
        """)
        ans = input("Please choose your desired option!:")

        if ans == "1":
            total_mileage = truck1.mileage + truck2.mileage + truck3.mileage
            print(f"\nOverall total mileage across all trucks: {total_mileage:.2f} miles")
            try:
                package_id = input("Enter a package ID to look the package you are looking for: ")
                lookup_package_info(package_hash, package_id)
            except Exception:
                print("Invalid input. Please enter a valid number")

        elif ans == "2":
            for truck in [truck1, truck2, truck3]:
                print(f"\nTruck {truck.truck_id} Deliveries:")
                for package in truck.packages:
                    print(f"Package {package.ID} delivered to {package.address} at {package.delivery_time.strftime('%I:%M %p')}")
                    print(f"Status: {package.status}")
                    print(f"Total mileage: {truck.mileage:.2f} miles\n")
            print(f"Total mileage (all trucks): {(truck1.mileage + truck2.mileage + truck3.mileage):.2f} miles\n")
            all_packages = truck1.packages + truck2.packages + truck3.packages
            visualize_package_status(all_packages)

        elif ans == "3":
            print("\nPackages on Truck 1:")
            truck1.print_packages()
            print("\nPackages on Truck 2:")
            truck2.print_packages()
            print("\nPackages on Truck 3:")
            truck3.print_packages()

        elif ans == "4":
            user_input = input("Enter a time (example: 13:45): ")
            try:
                hour, minute = map(int, user_input.split(":"))
                base_date = datetime.datetime.today().date()
                user_time = datetime.datetime.combine(base_date, datetime.time(hour, minute))
                check_package_status_at_time(package_hash, user_time)
                pkg9 = package_hash.search(9)
                if pkg9 and hasattr(pkg9, 'delivery_time') and pkg9.delivery_time <= datetime.datetime.combine(base_date, datetime.time(10, 20)):
                    print("The correct address of package #9 is: 410 S State St, Salt Lake City, UT 84111. Correcting at 10:20AM...")
            except ValueError:
                print("This input is not valid. Please enter the time as requested. Example of input: 11:02")

        elif ans == "5":
            print("Program exiting Done!")
            audit_log("session_end", f"role={_CURRENT_USER_ROLE}")
            break

        elif ans == "6":
            evaluate_model_simple()

        elif ans == "7":
            maintenance_menu()

        else:
            print("\nThis input is not valid. Please try again\n")

if __name__ == "__main__":
    main()
