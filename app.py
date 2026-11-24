
import hashlib
import os

# 1. Hardcoded secret
password = "demo_password_123"

# 2. SQL Injection
cursor.execute("SELECT * FROM users WHERE name = '" + username)

# 3. XSS
element.innerHTML = user_input

# 4. Command Injection
os.system(user_input)

# 5. Insecure CORS
allow_origins = ["*"]

# 6. Weak authentication
app.secret_key = "hardcoded-demo-key"

# 7. Weak cryptography
hashlib.md5(data)

# 8. Debug mode
DEBUG = True

# 9. Error disclosure
return str(e)
