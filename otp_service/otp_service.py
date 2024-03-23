import time
import secrets
import string
import threading
from threading import Timer
import logging

# Basic logging setup
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class OTPService:
    def __init__(self, cleanup_interval=30, is_test=False):
        self.otp_storage = {}
        self.storage_lock = threading.Lock()
        self.cleanup_interval = cleanup_interval
        self.is_test = is_test
        self.timer = None

    def generate_otp(self, user_identifier, ttl=30):
        if not user_identifier:
            raise ValueError("User identifier cannot be empty")
        
        if not isinstance(ttl, int) or ttl < 0:
            raise ValueError("TTL must be a non-negative integer")
        
        otp = ''.join(secrets.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(8))
        expiry = time.time() + ttl
        
        with self.storage_lock:
            self.otp_storage[user_identifier] = (otp, expiry)
        
        logging.info(f"OTP generated for user {user_identifier}")
        return otp

    def validate_otp(self, user_identifier, otp):
        with self.storage_lock:
            if user_identifier in self.otp_storage:
                stored_otp, expiry = self.otp_storage[user_identifier]
                if time.time() > expiry:
                    self.otp_storage.pop(user_identifier, None)  # Remove expired OTP
                    return False  # OTP expired
                if stored_otp == otp:
                    self.otp_storage.pop(user_identifier, None)
                    return True
        return False

    def cleanup_expired_otps(self):
        try:
            with self.storage_lock:
                current_time = time.time()
                expired_otps = [user_identifier for user_identifier, (_, expiry) in self.otp_storage.items() if current_time > expiry]
                for user_identifier in expired_otps:
                    self.otp_storage.pop(user_identifier, None)
            logging.info("Expired OTPs cleaned up")
        except Exception as e:
            logging.error(f"Error during OTP cleanup: {e}")
        finally:
            if not self.is_test:
                # Reschedule the cleanup task only in production
                self.timer = Timer(self.cleanup_interval, self.cleanup_expired_otps)
                self.timer.start()

    def start_cleanup_process(self):
        if not self.is_test:
            self.timer = Timer(self.cleanup_interval, self.cleanup_expired_otps)
            self.timer.start()

    def stop_cleanup_process(self):
        if self.timer:
            self.timer.cancel()

# Example usage
if __name__ == "__main__":
    otp_service = OTPService(is_test=False)  # Set is_test=True if running in test environment
    otp_service.start_cleanup_process()