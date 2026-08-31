import random
import hashlib
USERS = {
    "employee_a": {
        "password_hash": hashlib.sha256(
            "Employee@123".encode()
        ).hexdigest()
    }
}
def verify_password(username, password):
    if username not in USERS:
        return False
    password_hash = hashlib.sha256(
        password.encode()
    ).hexdigest()
    return password_hash == USERS[
        username
    ]["password_hash"]
def generate_otp():
    return str(
        random.randint(
            100000,
            999999
        )
    )
def verify_otp(generated_otp, entered_otp):
    return generated_otp == entered_otp