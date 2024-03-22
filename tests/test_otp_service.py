import time
from concurrent.futures import ThreadPoolExecutor
from faker import Faker
from unittest import TestCase

# Assuming the provided OTP generation and validation logic is in a module named otp_module
from otp_service.otp_service import generatre_opt, validate_otp, otp_storage, cleanup_expired_otps

# Initialize Faker
fake = Faker('en_IN')

class TestOTPGeneration(TestCase):
    def setUp(self):
        # Reset otp_storage before each test
        otp_storage.clear()
        self.user_identifier = fake.email()

    def test_otp_generation_success(self):
        """OTP Generation Success"""
        user_identifier = fake.email()
        otp = generatre_opt(user_identifier)
        self.assertTrue(otp in otp_storage[user_identifier])

    def test_otp_validation_success(self):
        """OTP Validation Success"""
        user_identifier = fake.email()
        otp = generatre_opt(user_identifier)
        self.assertTrue(validate_otp(user_identifier, otp))

    def test_otp_expiry(self):
        """OTP Expiry"""
        user_identifier = fake.email()
        ttl = 1  # Set TTL to 1 second for testing
        generatre_opt(user_identifier, ttl)
        time.sleep(1.1)  # Wait for the OTP to expire
        self.assertFalse(validate_otp(user_identifier, otp_storage[user_identifier][0]))

    def test_invalid_otp(self):
        """Invalid OTP"""
        user_identifier = fake.email()
        generatre_opt(user_identifier)
        wrong_otp = "123456"
        self.assertFalse(validate_otp(user_identifier, wrong_otp))

    def test_invalid_user_identifier(self):
        """Invalid User Identifier"""
        user_identifier = fake.email()
        generatre_opt(user_identifier)
        invalid_user_identifier = "nonexistent@example.com"
        self.assertFalse(validate_otp(invalid_user_identifier, otp_storage[user_identifier][0]))

    def test_case_sensitivity_in_otp_validation(self):
        """Case Sensitivity in OTP Validation"""
        user_identifier = fake.email()
        otp = generatre_opt(user_identifier).lower()  # Force lowercase to test case sensitivity
        stored_otp, _ = otp_storage[user_identifier]
        # Assuming OTPs are case-sensitive, modify the assertion based on your system's behavior
        self.assertNotEqual(otp, stored_otp)  # Use assertEqual if OTPs are not case-sensitive
        
    def test_otp_uniqueness(self):
        """OTP Uniqueness"""
        otps = set()
        # Generate 5 OTPs for the same user identifier and add to a set (sets only store unique items)
        for _ in range(5):
            otp = generatre_opt(self.user_identifier)
            otps.add(otp)

        # If all generated OTPs are unique, the set size should be equal to the number of generated OTPs
        self.assertEqual(len(otps), 5)

    def test_replay_attack_prevention(self):
        """Replay Attack Prevention"""
        otp = generatre_opt(self.user_identifier)
        # First validation should succeed
        self.assertTrue(validate_otp(self.user_identifier, otp))

        # Second validation should fail, as the OTP should have been invalidated/removed
        self.assertFalse(validate_otp(self.user_identifier, otp))

    def generate_otp_concurrently(self, user_identifier):
        return generatre_opt(user_identifier)

    def test_concurrent_otp_generation(self):
        with ThreadPoolExecutor(max_workers=10) as executor:
            user_identifiers = [fake.email() for _ in range(10)]
            results = list(executor.map(self.generate_otp_concurrently, user_identifiers))

            # Check if OTPs were generated and stored for all user identifiers
            for user_identifier in user_identifiers:
                self.assertTrue(user_identifier in otp_storage)
                self.assertIsNotNone(otp_storage[user_identifier][0])

    def validate_otp_concurrently(self, user_identifier):
        otp = generatre_opt(user_identifier)
        return validate_otp(user_identifier, otp)

    def test_concurrent_otp_validation(self):
        with ThreadPoolExecutor(max_workers=10) as executor:
            user_identifiers = [fake.email() for _ in range(10)]
            results = list(executor.map(self.validate_otp_concurrently, user_identifiers))

            # Check if all OTPs were successfully validated
            self.assertTrue(all(results))
            
            
    def test_negative_ttl(self):
        """Negative TTL input"""
        user_identifier = fake.email()
        with self.assertRaises(ValueError):
            generatre_opt(user_identifier, ttl=-5)
            
    def test_non_integer_ttl(self):
        """Non-integer TTL input"""
        user_identifier = fake.email()
        with self.assertRaises(ValueError):
            generatre_opt(user_identifier, ttl="ten")
            
    def test_special_characters_in_user_identifier(self):
        """Special characters in user identifier"""
        user_identifier = "user@#$.com"
        otp = generatre_opt(user_identifier)
        self.assertTrue(validate_otp(user_identifier, otp))

        user_identifier_with_space = "user @example.com"
        otp = generatre_opt(user_identifier_with_space)
        self.assertTrue(validate_otp(user_identifier_with_space, otp))
        
    def test_zero_second_ttl(self):
        """Zero-second TTL"""
        user_identifier = fake.email()
        generatre_opt(user_identifier, ttl=0)
        time.sleep(1)  # Wait to ensure the OTP has a chance to expire
        self.assertFalse(validate_otp(user_identifier, otp_storage[user_identifier][0]))

    def test_very_long_ttl(self):
        """Very long TTL"""
        user_identifier = fake.email()
        generatre_opt(user_identifier, ttl=999999)
        self.assertTrue(validate_otp(user_identifier, otp_storage[user_identifier][0]))
        
    def test_empty_user_identifier(self):
        """Empty user identifier"""
        with self.assertRaises(ValueError):
            generatre_opt('')
            
    def test_large_volume_of_otps(self):
        """Generate a large volume of OTPs"""
        for _ in range(10000):  # Adjust the number based on system capability
            user_identifier = f"{fake.email()}-{_}"
            generatre_opt(user_identifier)

        # This part of the test is more qualitative, assessing memory usage and performance manually
        # Consider using profiling tools to measure memory and performance here
        self.assertTrue(len(otp_storage) == 10000)
        
        
    def test_large_volume_of_otp_validation(self):
        """Generate and validate a large volume of OTPs"""
        expected_count = 10000
        otps = []  # Store tuples of (user_identifier, otp) for validation

        # Generate OTPs and store them for validation
        for i in range(expected_count):
            user_identifier = f"{fake.email()}-{i}"  # Ensure unique identifiers
            otp = generatre_opt(user_identifier)
            self.assertIsNotNone(otp)  # Ensure OTP was generated
            otps.append((user_identifier, otp))

        # Validate each OTP
        for user_identifier, otp in otps:
            self.assertTrue(validate_otp(user_identifier, otp), f"OTP validation failed for {user_identifier}")

        # After all validations, ensure the storage does not contain any of these OTPs if they should be invalidated upon validation
        for user_identifier, _ in otps:
            self.assertFalse(user_identifier in otp_storage, f"OTP for {user_identifier} was not removed after validation")

        # Optionally, you can also check the size of otp_storage to ensure it's empty or contains only entries unrelated to this test
        self.assertTrue(len(otp_storage) == 0, "otp_storage is not empty after all OTP validations")

    def test_expired_otp_is_removed_after_validation_attempt(self):
        """Expired OTP is properly removed after a validation attempt"""
        user_identifier = fake.email()
        # Set a very short TTL for quick expiry
        generatre_opt(user_identifier, ttl=1)
        time.sleep(2)  # Wait for the OTP to expire
        self.assertFalse(validate_otp(user_identifier, otp_storage.get(user_identifier, ('', 0))[0]))
        # Verify OTP is removed from storage after failed validation due to expiry
        self.assertNotIn(user_identifier, otp_storage)

    def test_periodic_cleanup_removes_expired_otps(self):
        """Expired OTPs are removed during periodic cleanup"""
        # Generate OTPs with immediate expiry
        for _ in range(10):
            user_identifier = fake.email()
            generatre_opt(user_identifier, ttl=0)
        # Assume some time has passed, and then manually trigger cleanup
        cleanup_expired_otps()  # This is where you'd call your cleanup function
        # Verify that storage is empty or does not contain expired OTPs
        # This check might need to be adjusted based on the exact cleanup logic
        for otp_info in otp_storage.values():
            self.assertTrue(time.time() < otp_info[1], "Found an expired OTP that should have been cleaned up")
        
        
        
        
## Example usage to run tests, 
## if using a framework like unittest
if __name__ == "__main__":
    import unittest
    unittest.main() 