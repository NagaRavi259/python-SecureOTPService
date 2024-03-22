import time
import random
import string

# OTP storage dictionary
otp_storage= {}

def get_identifier():
    x = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(8))
    # print(x)
    return x

def generatre_opt(user_identifier, ttl=30):
    # Check if the user identifier is empty
    if not user_identifier:
        raise ValueError("User identifier cannot be empty")

    if not isinstance(ttl, int) or ttl < 0:
        raise ValueError("TTL must be a non-negative integer")
        
    otp = get_identifier()
    expiry = time.time() + ttl
    otp_storage[user_identifier] = (otp, expiry)
    return otp

def validate_otp(user_identifier, otp):
    if user_identifier in otp_storage:
        stored_otp, expiry = otp_storage[user_identifier]
        if time.time() > expiry:
            del otp_storage[user_identifier]  # Remove expired OTP
            return False  # OTP expired
        if stored_otp == otp:
            otp_storage.pop(user_identifier)
            return True
    return False

def cleanup_expired_otps():
    """
    Remove expired OTPs from the storage.
    """
    current_time = time.time()
    # Create a list of user_identifiers for OTPs that have expired to avoid modifying the dictionary size during iteration
    expired_otps = [user_identifier for user_identifier, (otp, expiry) in otp_storage.items() if current_time > expiry]
    # Remove the expired OTPs
    for user_identifier in expired_otps:
        del otp_storage[user_identifier]