# SecureOTPService

SecureOTPService is a robust implementation of an OTP (One-Time Password) service, designed to provide secure, temporary authentication tokens for applications. It supports customizable options like TTL (Time to Live), alphanumeric or numeric OTP formats, and automatic cleanup of expired OTPs. This project also includes a comprehensive test suite developed with pytest to ensure the service's reliability and security.

## Features

- **Customizable OTP Formats**: Choose between alphanumeric or numeric OTPs.
- **Configurable TTL**: Set the lifespan of OTPs according to your security needs.
- **Auto-Cleanup**: Expired OTPs are automatically removed for efficiency.
- **Security Measures**: Includes lockout mechanisms to prevent brute-force attacks.
- **Comprehensive Testing**: A pytest suite covers functionality, security, and performance.

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.

### Prerequisites

Before you begin, ensure you have Python 3.6 or later installed on your system. You'll also need `pip` for installing Python packages.

### Installing

Clone the repository:

```bash
git clone https://github.com/NagaRavi259/python-SecureOTPService.git
cd SecureOTPService
```

Install the required packages:

```bash
pip install -r requirements.txt
```

### Running the OTP Service

To start the OTP service:

```bash
python src/otp_service.py
```

This will initiate the service and start the cleanup process if not in test mode.

### Running the Tests

To run the automated tests for this system, use:

```bash
pytest tests/
```

This will run the comprehensive test suite and report any failures.