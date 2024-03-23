import time
import secrets
import string
import threading
import logging

# Basic logging setup
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class OTPService:
    """
    A service for generating and validating one-time passwords (OTPs), with automated cleanup for expired OTPs.

    Attributes:
        otp_storage (dict): Stores OTPs and their expiration times, keyed by user identifier.
        attempt_storage (dict): Tracks the number of failed attempts and last attempt time, keyed by user identifier.
        lockout_period (int): Time in seconds a user is locked out after exceeding max_attempts.
        max_attempts (int): Maximum allowed validation attempts before a user is locked out.
        storage_lock (threading.Lock): Ensures thread-safe operations on otp_storage and attempt_storage.
        cleanup_interval (int): Frequency in seconds at which expired OTPs are cleaned up.
        is_test (bool): If True, disables automatic cleanup scheduling for testing purposes.
        timer (threading.Timer or None): Timer object for scheduling the next cleanup task.
        otp_format (str): Specifies the format of generated OTPs ('numeric' or 'alphanumeric').
        default_ttl (int): Default time-to-live in seconds for generated OTPs.
    """
    def __init__(self, cleanup_interval=30, is_test=False, max_attempts=5, lockout_period=300,
                 otp_format='alphanumeric', default_ttl=30):
        self.otp_storage = {}
        self.attempt_storage = {}
        self.lockout_period = lockout_period
        self.max_attempts = max_attempts
        self.storage_lock = threading.Lock()
        self.cleanup_interval = cleanup_interval
        self.is_test = is_test
        self.timer = None
        self.otp_format = otp_format
        self.default_ttl = default_ttl

    def generate_otp(self, user_identifier, ttl=None):
        """
        Generates a one-time password for a given user identifier, storing it with an expiration time.

        Args:
            user_identifier (str): The unique identifier for the user.
            ttl (int, optional): Time-to-live in seconds for the OTP. Defaults to self.default_ttl.

        Returns:
            str: The generated OTP.
        """
        if not user_identifier:
            raise ValueError("User identifier cannot be empty")

        ttl = ttl if ttl is not None else self.default_ttl
        if not isinstance(ttl, int) or ttl < 0:
            raise ValueError("TTL must be a non-negative integer")

        otp = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(8)) if self.otp_format == 'alphanumeric' else \
              ''.join(secrets.choice(string.digits) for _ in range(8))

        expiry = time.time() + ttl

        with self.storage_lock:
            if user_identifier in self.otp_storage:
                logging.warning("Overwriting existing OTP for user %s", user_identifier)
            self.otp_storage[user_identifier] = (otp, expiry)

        logging.info("OTP generated for user %s: %s", user_identifier, otp)
        return otp

    def validate_otp(self, user_identifier, otp):
        """
        Validates an OTP for a given user identifier, considering lockout mechanisms for repeated failures.

        Args:
            user_identifier (str): The unique identifier for the user.
            otp (str): The one-time password to validate.

        Returns:
            bool: True if the OTP is valid and not expired; False otherwise.
        """
        with self.storage_lock:
            if user_identifier in self.attempt_storage:
                attempts, last_attempt_time = self.attempt_storage[user_identifier]
                if time.time() - last_attempt_time < self.lockout_period:
                    logging.info("User %s is temporarily locked out.", user_identifier)
                    return False
                if attempts >= self.max_attempts:
                    self.attempt_storage[user_identifier] = (0, time.time())

            if user_identifier in self.otp_storage:
                stored_otp, expiry = self.otp_storage[user_identifier]
                if time.time() > expiry or stored_otp != otp:
                    if time.time() > expiry:
                        self.otp_storage.pop(user_identifier, None)
                        logging.info("Expired OTP removed for user %s upon validation attempt", user_identifier)
                    attempts, _ = self.attempt_storage.get(user_identifier, (0, 0))
                    self.attempt_storage[user_identifier] = (attempts + 1, time.time())
                    if attempts + 1 >= self.max_attempts:
                        logging.warning("User %s reached maximum OTP attempt limit.", user_identifier)
                    return False
                else:
                    # OTP is valid, reset attempt counter and remove OTP from storage
                    self.attempt_storage.pop(user_identifier, None)
                    self.otp_storage.pop(user_identifier, None)
                    logging.info("OTP validated for user %s", user_identifier)
                    return True
            else:
                # Handle case where user_identifier does not have an OTP issued (not found in storage)
                logging.info("No OTP found for user %s upon validation attempt", user_identifier)
                return False

    def cleanup_expired_otps(self):
        """
        Cleans up expired OTPs from storage. This method is intended to be run at regular intervals.
        """
        with self.storage_lock:
            current_time = time.time()
            expired_otps = [user_identifier for user_identifier, (_, expiry) in self.otp_storage.items() if current_time > expiry]
            for user_identifier in expired_otps:
                self.otp_storage.pop(user_identifier, None)
                logging.info("Expired OTP removed for user %s", user_identifier)
        logging.info("Expired OTPs cleaned up")

        if not self.is_test:
            # Reschedule the cleanup task only in non-test environments
            self.timer = threading.Timer(self.cleanup_interval, self.cleanup_expired_otps)
            self.timer.start()

    def start_cleanup_process(self):
        """
        Starts the periodic cleanup process for expired OTPs, if it's not already running.
        """
        if not self.is_test and not self.timer:
            self.timer = threading.Timer(self.cleanup_interval, self.cleanup_expired_otps)
            self.timer.start()

    def stop_cleanup_process(self):
        """
        Stops the periodic cleanup process for expired OTPs, if it's currently running.
        """
        if self.timer:
            self.timer.cancel()
            self.timer = None

# Example usage
if __name__ == "__main__":
    otp_service = OTPService(is_test=False)  # Set is_test=True if running in test environment
    otp_service.start_cleanup_process()