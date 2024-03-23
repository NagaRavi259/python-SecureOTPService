import time
import secrets
import string
import threading
from threading import Timer
import logging

# Basic logging setup
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# OTP storage dictionary
otp_storage = {}
# Adding a lock for thread-safe operations
storage_lock = threading.Lock()

# Asynchronous cleanup setup
cleanup_interval = 30  # seconds

def generate_otp(user_identifier, ttl=30):
    try:
        if not user_identifier:
            raise ValueError("User identifier cannot be empty")
        
        if not isinstance(ttl, int) or ttl < 0:
            raise ValueError("TTL must be a non-negative integer")
        
        otp = ''.join(secrets.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(8))
        expiry = time.time() + ttl
        
        with storage_lock:
            otp_storage[user_identifier] = (otp, expiry)
        
        logging.info(f"OTP generated for user {user_identifier}")
        return otp
    except Exception as e:
        logging.error(f"Error generating OTP for user {user_identifier}: {e}")
        raise

def validate_otp(user_identifier, otp):
    try:
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
    except Exception as e:
        logging.error(f"Error validating OTP for user {user_identifier}: {e}")
        # Depending on application's requirement, either raise the exception or return False
        raise

def cleanup_expired_otps():
    try:
        with storage_lock:
            current_time = time.time()
            expired_otps = [user_identifier for user_identifier, (_, expiry) in otp_storage.items() if current_time > expiry]
            for user_identifier in expired_otps:
                otp_storage.pop(user_identifier, None)
        logging.info("Expired OTPs cleaned up")
    except Exception as e:
        logging.error(f"Error during OTP cleanup: {e}")
    finally:
        # Reschedule the cleanup task
        Timer(cleanup_interval, cleanup_expired_otps).start()

# Start the initial cleanup task
timer = Timer(cleanup_interval, cleanup_expired_otps)

timer.start()