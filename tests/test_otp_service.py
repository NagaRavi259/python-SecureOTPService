import pytest
import threading
from otp_service.otp_service import generate_otp, validate_otp, otp_storage, cleanup_expired_otps  # Adjust import as necessary
from faker import Faker
import time

fake = Faker()

def test_successful_otp_generation():
    ''' Successful OTP Generation: 
    Verify that generating an OTP for a valid user identifier succeeds and stores the OTP correctly.'''
    user_id = fake.email()
    otp = generate_otp(user_id)
    assert otp is not None
    assert otp == otp_storage[user_id][0]

def test_unique_otps_for_different_users():
    '''Unique OTPs for Different Users: 
    Ensure that OTPs generated for different user identifiers within a short time frame are unique.'''
    user_id1 = fake.email()
    user_id2 = fake.email()
    otp1 = generate_otp(user_id1)
    otp2 = generate_otp(user_id2)
    assert otp1 != otp2

def test_repeated_otp_generation_for_same_user():
    '''Repeated OTP Generation for Same User: 
    Confirm that generating multiple OTPs for the same user identifier updates the stored OTP each time.'''
    user_id = fake.email()
    otp1 = generate_otp(user_id)
    otp2 = generate_otp(user_id)
    assert otp1 != otp2
    assert otp2 == otp_storage[user_id][0]

def test_invalid_user_identifier_input():
    '''Invalid User Identifier Input: 
    Test that generating an OTP with an invalid user identifier (e.g., empty string, null) raises an appropriate exception.'''
    with pytest.raises(ValueError):
        generate_otp("")
    with pytest.raises(ValueError):
        generate_otp(None)

def test_special_characters_in_user_identifier():
    '''Special Characters in User Identifier: 
    Verify that OTP generation succeeds for user identifiers containing special characters.'''
    special_user_id = fake.email()
    otp = generate_otp(special_user_id)
    assert otp is not None
    assert otp == otp_storage[special_user_id][0]

def test_concurrent_otp_generation():
    '''Concurrent OTP Generation: 
    Check that concurrently generating OTPs for multiple user identifiers works correctly and maintains system integrity.'''
    user_ids = [fake.email() for _ in range(100)]
    threads = [threading.Thread(target=lambda uid=user_id: generate_otp(uid)) for user_id in user_ids]

    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    # Verify that each user has a unique OTP
    otps = [otp_storage[user_id][0] for user_id in user_ids]
    assert len(set(otps)) == len(user_ids), "OTPs are not unique across users"
    

def test_successful_otp_validation():
    '''Successful OTP Validation: 
    Test that a valid OTP is correctly validated for a user identifier.'''
    user_id = fake.email()
    otp = generate_otp(user_id)
    assert validate_otp(user_id, otp) is True
    assert user_id not in otp_storage  # OTP should be removed

def test_otp_validation_with_incorrect_otp():
    '''OTP Validation with Incorrect OTP: 
    Ensure that an incorrect OTP for a user identifier fails validation.'''
    user_id = fake.email()
    correct_otp = generate_otp(user_id)
    incorrect_otp = 'wrong' + correct_otp
    assert validate_otp(user_id, incorrect_otp) is False

def test_expired_otp():
    '''Expired OTP: 
    Verify that an OTP past its TTL is not valid.'''
    user_id = fake.email()
    generate_otp(user_id, ttl=1)  # Set a short TTL
    time.sleep(2)  # Wait for the OTP to expire
    # Attempt to validate the expired OTP
    assert user_id not in otp_storage  # Expired OTP should be removed

def test_case_sensitivity():
    '''Case Sensitivity: 
    Check whether the OTP validation process is case-sensitive and behaves as expected.'''
    user_id = fake.email()
    otp = generate_otp(user_id).lower()  # Assuming generated OTP is uppercase, force it to lower
    assert validate_otp(user_id, otp) is False  # Case sensitivity should result in failure

def test_validation_removes_otp():
    '''Validation Removes OTP: 
    Confirm that a successfully validated OTP is removed from storage, preventing replay attacks.'''
    user_id = fake.email()
    otp = generate_otp(user_id)
    assert validate_otp(user_id, otp) is True
    assert user_id not in otp_storage  # OTP should be removed after validation

def test_invalid_user_identifier_for_validation():
    '''Invalid User Identifier for Validation: 
    Test validation with a user identifier not present in the storage fails.'''
    user_id = fake.email()
    # Do not generate an OTP for this user_id
    assert validate_otp(user_id, "someOTP") is False
    
def test_expired_otp():
    '''Expired OTP:
    Verify that an OTP past its TTL is not valid.'''
    user_id = fake.email()
    otp = generate_otp(user_id, ttl=1)  # Set a short TTL
    time.sleep(2)  # Wait for the OTP to expire
    # Attempt to validate the expired OTP
    assert validate_otp(user_id, otp) is False, "Expired OTP was considered valid"
    assert user_id not in otp_storage, "Expired OTP was not removed after validation attempt"
    
## OTP Expiry and Cleanup
def test_automatic_expiry_of_otp():
    '''Automatic Expiry of OTP: 
    Verify that OTPs expire correctly after their TTL has elapsed.'''
    user_id = fake.email()
    generate_otp(user_id, ttl=1)  # Set a short TTL
    time.sleep(2)  # Wait for the OTP to expire
    assert validate_otp(user_id, otp_storage.get(user_id, ('', 0))[0]) is False
    assert user_id not in otp_storage


def test_manual_cleanup_of_expired_otps():
    # Generate OTPs with varying TTLs
    short_lived_user = fake.email()
    long_lived_user = fake.email()
    generate_otp(short_lived_user, ttl=1)  # This OTP will expire
    generate_otp(long_lived_user, ttl=30)  # This OTP will remain valid
    time.sleep(2)  # Ensure the short-lived OTP expires

    cleanup_expired_otps()

    assert short_lived_user not in otp_storage
    assert long_lived_user in otp_storage

def test_expired_otp_removal_after_validation_attempt():
    user_id = fake.email()
    generate_otp(user_id, ttl=1)  # Set a short TTL
    time.sleep(2)  # Wait for the OTP to expire
    otp_attempt = 'any_value'  # OTP value does not matter as it should be expired
    assert validate_otp(user_id, otp_attempt) is False
    assert user_id not in otp_storage