import time
import secrets
import string
import threading
from threading import Timer
import logging

# Basic logging setup
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class OTPService:
    def __init__(self, cleanup_interval=30, is_test=False, max_attempts=5, lockout_period=300, otp_format='alphanumeric', default_ttl=30):
        self.otp_storage = {}
        self.attempt_storage = {}  # Track failed attempts
        self.lockout_period = lockout_period  # Time in seconds
        self.max_attempts = max_attempts
        self.storage_lock = threading.Lock()
        self.cleanup_interval = cleanup_interval
        self.is_test = is_test
        self.timer = None
        self.otp_format = otp_format  # New: OTP format
        self.default_ttl = default_ttl  # New: Default TTL for OTPs

    def generate_otp(self, user_identifier, ttl=None):
        if not user_identifier:
            raise ValueError("User identifier cannot be empty")
        
        ttl = ttl if ttl is not None else self.default_ttl  # Use specified TTL or default
        if not isinstance(ttl, int) or ttl < 0:
            raise ValueError("TTL must be a non-negative integer")
        
        if self.otp_format == 'numeric':
            otp = ''.join(secrets.choice(string.digits) for _ in range(8))
        elif self.otp_format == 'alphanumeric':
            otp = ''.join(secrets.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(8))
        else:
            raise ValueError("Unsupported OTP format")
        
        expiry = time.time() + ttl
        
        with self.storage_lock:
            # Log when an OTP is overwritten for the same user_identifier
            if user_identifier in self.otp_storage:
                logging.warning(f"Overwriting existing OTP for user {user_identifier}")
            self.otp_storage[user_identifier] = (otp, expiry)
        
        logging.info(f"OTP generated for user {user_identifier}: {otp}")
        return otp

    def validate_otp(self, user_identifier, otp):
        with self.storage_lock:
            # Check for lockout status
            if user_identifier in self.attempt_storage:
                attempts, last_attempt_time = self.attempt_storage[user_identifier]
                if time.time() - last_attempt_time < self.lockout_period:
                    logging.info(f"User {user_identifier} is temporarily locked out.")
                    return False
                if attempts >= self.max_attempts:
                    self.attempt_storage[user_identifier] = (0, time.time())  # Reset after lockout period
            # Existing validation logic...
            if user_identifier in self.otp_storage:
                stored_otp, expiry = self.otp_storage[user_identifier]
                if time.time() > expiry or stored_otp != otp:
                    if time.time() > expiry:
                        # Remove expired OTP and log this event
                        self.otp_storage.pop(user_identifier, None)
                        logging.info(f"Expired OTP removed for user {user_identifier} upon validation attempt")
                    # Increment failed attempts
                    attempts, _ = self.attempt_storage.get(user_identifier, (0, 0))
                    self.attempt_storage[user_identifier] = (attempts + 1, time.time())
                    if attempts + 1 >= self.max_attempts:
                        logging.warning(f"User {user_identifier} reached maximum OTP attempt limit.")
                    return False
                else:
                    # Successful validation, reset attempt counter, , remove it from storage
                    self.attempt_storage.pop(user_identifier, None)
                    self.otp_storage.pop(user_identifier, None)
                    logging.info(f"OTP validated for user {user_identifier}")
                    return True
        return False

    def cleanup_expired_otps(self):
        with self.storage_lock:
            current_time = time.time()
            expired_otps = [user_identifier for user_identifier, (_, expiry) in self.otp_storage.items() if current_time > expiry]
            for user_identifier in expired_otps:
                self.otp_storage.pop(user_identifier, None)
                logging.info(f"Expired OTP removed for user {user_identifier}")
        logging.info("Expired OTPs cleaned up")

        if not self.is_test:
            # Reschedule the cleanup task only in production
            self.timer = Timer(self.cleanup_interval, self.cleanup_expired_otps)
            self.timer.start()

    def start_cleanup_process(self):
        if not self.is_test and not self.timer:
            self.timer = Timer(self.cleanup_interval, self.cleanup_expired_otps)
            self.timer.start()

    def stop_cleanup_process(self):
        if self.timer:
            self.timer.cancel()
            self.timer = None

# Example usage
if __name__ == "__main__":
    otp_service = OTPService(is_test=False)  # Set is_test=True if running in test environment
    otp_service.start_cleanup_process()