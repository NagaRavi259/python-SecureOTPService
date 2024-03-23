import time
import random
import string
import threading

# OTP storage dictionary
otp_storage = {}
# Adding a lock for thread-safe operations
storage_lock = threading.Lock()

def generate_otp(user_identifier, ttl=30):
    if not user_identifier:
        raise ValueError("User identifier cannot be empty")
    
    if not isinstance(ttl, int) or ttl < 0:
        raise ValueError("TTL must be a non-negative integer")
    
    otp = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(8))
    expiry = time.time() + ttl
    
    with storage_lock:
        otp_storage[user_identifier] = (otp, expiry)
    
    return otp

def validate_otp(user_identifier, otp):
    with storage_lock:
        if user_identifier in otp_storage:
            stored_otp, expiry = otp_storage[user_identifier]
            if time.time() > expiry:
                otp_storage.pop(user_identifier, None)  # Remove expired OTP
                return False  # OTP expired
            if stored_otp == otp:
                otp_storage.pop(user_identifier, None)
                return True
    return False

def cleanup_expired_otps():
    with storage_lock:
        current_time = time.time()
        expired_otps = [user_identifier for user_identifier, (_, expiry) in otp_storage.items() if current_time > expiry]
        for user_identifier in expired_otps:
            otp_storage.pop(user_identifier, None)