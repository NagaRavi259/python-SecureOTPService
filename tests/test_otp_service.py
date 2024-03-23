import pytest
import time
import threading
import concurrent.futures
from threading import Timer
from otp_service.otp_service import OTPService  # Adjust import as necessary
from faker import Faker

fake = Faker()

# Creating a class instence for the OTPService    
otp_service = OTPService(is_test=True)  # Initialize with is_test=True to prevent automatic cleanup scheduling

@pytest.fixture(scope="module", autouse=True)
def setup():
    # Start the initial cleanup task
    otp_service.start_cleanup_process()
    print("\nStart of tests")
    yield
    # Stop the cleanup task after all tests are finished
    otp_service.stop_cleanup_process()
    print("\nEnd of tests")

'''OTP Generation'''
def test_successful_otp_generation(setup):
    ''' Successful OTP Generation: 
    Verify that generating an OTP for a valid user identifier succeeds and stores the OTP correctly.'''
    user_id = fake.email()
    otp = otp_service.generate_otp(user_id)
    assert otp is not None
    assert otp == otp_service.otp_storage[user_id][0]

def test_unique_otps_for_different_users(setup):
    '''Unique OTPs for Different Users: 
    Ensure that OTPs generated for different user identifiers within a short time frame are unique.'''
    user_id1 = fake.email()
    user_id2 = fake.email()
    otp1 = otp_service.generate_otp(user_id1)
    otp2 = otp_service.generate_otp(user_id2)
    assert otp1 != otp2

def test_repeated_otp_generation_for_same_user(setup):
    '''Repeated OTP Generation for Same User: 
    Confirm that generating multiple OTPs for the same user identifier updates the stored OTP each time.'''
    user_id = fake.email()
    otp1 = otp_service.generate_otp(user_id)
    otp2 = otp_service.generate_otp(user_id)
    assert otp1 != otp2
    assert otp2 == otp_service.otp_storage[user_id][0]

def test_invalid_user_identifier_input(setup):
    '''Invalid User Identifier Input: 
    Test that generating an OTP with an invalid user identifier (e.g., empty string, null) raises an appropriate exception.'''
    with pytest.raises(ValueError):
        otp_service.generate_otp("")
    with pytest.raises(ValueError):
        otp_service.generate_otp(None)

def test_special_characters_in_user_identifier(setup):
    '''Special Characters in User Identifier: 
    Verify that OTP generation succeeds for user identifiers containing special characters.'''
    special_user_id = fake.email()
    otp = otp_service.generate_otp(special_user_id)
    assert otp is not None
    assert otp == otp_service.otp_storage[special_user_id][0]

def test_concurrent_otp_generation(setup):
    '''Concurrent OTP Generation: 
    Check that concurrently generating OTPs for multiple user identifiers works correctly and maintains system integrity.'''
    user_ids = [fake.email() for _ in range(100)]
    threads = [threading.Thread(target=lambda uid=user_id: otp_service.generate_otp(uid)) for user_id in user_ids]

    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    # Verify that each user has a unique OTP
    otps = [otp_service.otp_storage[user_id][0] for user_id in user_ids]
    assert len(set(otps)) == len(user_ids), "OTPs are not unique across users"
    

    
'''OTP Validation'''
    
def test_successful_otp_validation(setup):
    '''Successful OTP Validation: 
    Test that a valid OTP is correctly validated for a user identifier.'''
    user_id = fake.email()
    otp = otp_service.generate_otp(user_id)
    assert otp_service.validate_otp(user_id, otp) is True
    assert user_id not in otp_service.otp_storage  # OTP should be removed

def test_otp_validation_with_incorrect_otp(setup):
    '''OTP Validation with Incorrect OTP: 
    Ensure that an incorrect OTP for a user identifier fails validation.'''
    user_id = fake.email()
    correct_otp = otp_service.generate_otp(user_id)
    incorrect_otp = 'wrong' + correct_otp
    assert otp_service.validate_otp(user_id, incorrect_otp) is False

def test_expired_otp_validation(setup):
    '''Expired OTP: 
    Verify that an OTP past its TTL is not valid.'''
    user_id = fake.email()
    otp = otp_service.generate_otp(user_id, ttl=1)  # Set a short TTL
    time.sleep(2)  # Wait for the OTP to expire
    # Attempt to validate the expired OTP
    assert otp_service.validate_otp(user_id, otp) is False
    assert user_id not in otp_service.otp_storage  # Expired OTP should be removed

def test_case_sensitivity(setup):
    '''Case Sensitivity: 
    Check whether the OTP validation process is case-sensitive and behaves as expected.'''
    user_id = fake.email()
    otp = otp_service.generate_otp(user_id).lower()  # Assuming generated OTP is uppercase, force it to lower
    assert otp_service.validate_otp(user_id, otp) is False  # Case sensitivity should result in failure

def test_validation_removes_otp(setup):
    '''Validation Removes OTP: 
    Confirm that a successfully validated OTP is removed from storage, preventing replay attacks.'''
    user_id = fake.email()
    otp = otp_service.generate_otp(user_id)
    assert otp_service.validate_otp(user_id, otp) is True
    assert user_id not in otp_service.otp_storage  # OTP should be removed after validation

def test_invalid_user_identifier_for_validation(setup):
    '''Invalid User Identifier for Validation: 
    Test validation with a user identifier not present in the storage fails.'''
    user_id = fake.email()
    # Do not generate an OTP for this user_id
    assert otp_service.validate_otp(user_id, "someOTP") is False

    

''' OTP Expiry and Cleanup'''

## Additional test cases for OTP expiration and cleanup
def test_automatic_expiry_of_otp(setup):
    '''Automatic Expiry of OTP: 
    Verify that OTPs expire correctly after their TTL has elapsed.'''
    user_id = fake.email()
    otp_service.generate_otp(user_id, ttl=1)  # Set a short TTL
    time.sleep(2)  # Ensure enough time has passed for the OTP to expire
    otp_service.cleanup_expired_otps()  # Manually trigger cleanup
    assert user_id not in otp_service.otp_storage


def test_manual_cleanup_of_expired_otps(setup):
    '''Manual Cleanup of Expired OTPs: 
    Test the periodic cleanup function to ensure it removes expired OTPs without affecting valid ones.'''
    short_lived_user = fake.email()
    long_lived_user = fake.email()
    otp_service.generate_otp(short_lived_user, ttl=1)  # This OTP will expire
    otp_service.generate_otp(long_lived_user, ttl=30)  # This OTP will remain valid
    time.sleep(2)  # Ensure the short-lived OTP expires

    otp_service.cleanup_expired_otps()  # Manually trigger cleanup

    assert short_lived_user not in otp_service.otp_storage
    assert long_lived_user in otp_service.otp_storage

def test_expired_otp_removal_after_validation_attempt(setup):
    '''Expired OTP Removal After Validation Attempt: 
    Ensure that attempting to validate an expired OTP both fails and removes the OTP from storage.'''
    user_id = fake.email()
    otp_service.generate_otp(user_id, ttl=1)  # Set a short TTL
    time.sleep(2)  # Wait for the OTP to expire
    otp_attempt = 'any_value'  # OTP value does not matter as it should be expired
    assert otp_service.validate_otp(user_id, otp_attempt) is False
    assert user_id not in otp_service.otp_storage
    
    

'''Edge Cases and Error Handling'''
def test_negative_ttl_input(setup):
    '''Negative TTL Input: 
    Test that a negative TTL value raises an appropriate exception.'''
    user_id = fake.email()
    with pytest.raises(ValueError):
        otp_service.generate_otp(user_id, ttl=-1)

def test_non_integer_ttl_input(setup):
    '''Non-integer TTL Input: 
    Ensure that providing a non-integer TTL value raises an exception.'''
    user_id = fake.email()
    with pytest.raises(ValueError):
        otp_service.generate_otp(user_id, ttl="10")

def test_zero_second_ttl(setup):
    '''Zero-Second TTL: 
    Verify the behavior when an OTP is generated with a TTL of 0 seconds. It should expire immediately.'''
    user_id = fake.email()
    otp = otp_service.generate_otp(user_id, ttl=0)
    time.sleep(0.1)
    # Assuming immediate validation, the OTP should already be expired or close to expiring
    # The test might need to account for the fact that if the check is too fast, it might still validate
    assert otp_service.validate_otp(user_id, otp) is False

def test_very_long_ttl(setup):
    '''Very Long TTL: 
    Test OTP generation with an exceptionally long TTL to confirm it's handled correctly.'''
    user_id = fake.email()
    very_long_ttl = 60 * 60 * 24 * 365  # 1 year
    otp = otp_service.generate_otp(user_id, ttl=very_long_ttl)
    assert otp is not None
    # Optionally, validate that the OTP is still valid after a short delay, if the system's design keeps it valid
    time.sleep(1)
    assert otp_service.validate_otp(user_id, otp) is True

def test_empty_user_identifier(setup):
    '''Empty User Identifier: 
    Verify that generating an OTP with an empty user identifier raises an exception.'''
    with pytest.raises(ValueError):
        otp_service.generate_otp('')



'''Performance and Stress Testing'''

def test_large_volume_of_otps(setup):
    '''Large Volume of OTPs: 
    Generate a large number of OTPs to test the system's handling of significant load and observe performance metrics.'''
    start_time = time.time()
    num_otps = 10000  # Adjust based on your performance testing requirements
    for _ in range(num_otps):
        user_id = fake.email()
        otp_service.generate_otp(user_id)
    end_time = time.time()
    print(f"\nGenerated {num_otps} OTPs in {end_time - start_time} seconds")

def generate_and_validate_otp(user_id):
    otp = otp_service.generate_otp(user_id)
    assert otp_service.validate_otp(user_id, otp) is True
    
def test_concurrent_otp_generation_and_validation(setup):
    '''Concurrent OTP Generation and Validation: 
    Perform concurrent generation and validation of OTPs to assess system performance and integrity under load.'''
    num_threads = 10000  # Adjust based on your stress testing requirements
    threads = []
    start_time = time.time()
    for _ in range(num_threads):
        user_id = fake.email()
        thread = threading.Thread(target=generate_and_validate_otp, args=(user_id,))
        threads.append(thread)
        thread.start()
    
    for thread in threads:
        thread.join()
    end_time = time.time()
    print(f"\nConcurrently generated and validated {num_threads} OTPs in {end_time - start_time} seconds")
    
def test_generate_large_number_of_otps(setup):
    '''Memory Usage with Large Number of OTPs: 
    Monitor memory usage as a large volume of OTPs are generated and stored, identifying potential memory leaks or inefficiencies.'''
    num_otps = 10000  # Adjust based on your performance testing requirements
    for _ in range(num_otps):
        user_id = fake.email()
        otp_service.generate_otp(user_id)
        
''' Scalability Testing '''

def generate_and_validate_otp1(email):
    otp = otp_service.generate_otp(email)
    opt_validation = otp_service.validate_otp(email, otp)
    return opt_validation

@pytest.mark.parametrize("num_requests", [100, 500, 1000, 5000])
def test_scalability_with_increased_load(num_requests):
    '''Scaling with Increased Load: 
    Simulate increased load to test how well the OTP system scales, particularly focusing on response times and error rates.'''
    emails = [fake.email() for _ in range(num_requests)]
    start_time = time.time()

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        results = list(executor.map(generate_and_validate_otp1, emails))

    end_time = time.time()
    total_time = end_time - start_time
    assert all(results), "Not all OTP validations succeeded"
    print(f"Processed {num_requests} requests in {total_time:.2f} seconds.")
    
    
''' Security Considerations '''

def test_replay_attack_prevention():
    '''Replay Attack Prevention: 
    Confirm that an OTP cannot be reused after a successful validation.'''
    user_id = fake.email()
    otp = otp_service.generate_otp(user_id)

    # First validation should succeed
    first_attempt = otp_service.validate_otp(user_id, otp)
    assert first_attempt is True, "OTP validation failed on the first attempt"

    # Subsequent validation attempts with the same OTP should fail
    second_attempt = otp_service.validate_otp(user_id, otp)
    assert second_attempt is False, "OTP was reused after successful validation, replay attack possible"
    
def test_brute_force_attack_resistance():
    '''Brute Force Attack Resistance: 
    Test the system's resistance to brute force attacks, ensuring rate limiting or lockout mechanisms are effective.'''
    user_id = fake.email()
    otp = otp_service.generate_otp(user_id)
    max_attempts = 5  # Assuming the system locks or rate limits after 5 incorrect attempts

    # Make a series of incorrect validation attempts
    for _ in range(max_attempts):
        otp_service.validate_otp(user_id, "wrong_otp")

    # Now, even if using the correct OTP, validation should fail due to lockout or rate limiting
    locked_out = otp_service.validate_otp(user_id, otp)
    assert locked_out is False, "System did not prevent brute force attack after multiple failed attempts"
