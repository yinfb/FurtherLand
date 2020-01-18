import bcrypt
import hashlib
password = "123456!"
x=bcrypt.hashpw(
            hashlib.sha256(password.encode()
                           ).hexdigest().encode(), bcrypt.gensalt()
        )
print(x)