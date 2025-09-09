# EX-NO-13-MESSAGE-AUTHENTICATION-CODE-MAC

## AIM:
To implement MESSAGE AUTHENTICATION CODE(MAC)

## ALGORITHM:

1. Message Authentication Code (MAC) is a cryptographic technique used to verify the integrity and authenticity of a message by using a secret key.

2. Initialization:
   - Choose a cryptographic hash function \( H \) (e.g., SHA-256) and a secret key \( K \).
   - The message \( M \) to be authenticated is input along with the secret key \( K \).

3. MAC Generation:
   - Compute the MAC by applying the hash function to the combination of the message \( M \) and the secret key \( K \): 
     \[
     \text{MAC}(M, K) = H(K || M)
     \]
     where \( || \) denotes concatenation of \( K \) and \( M \).

4. Verification:
   - The recipient, who knows the secret key \( K \), computes the MAC using the received message \( M \) and the same hash function.
   - The recipient compares the computed MAC with the received MAC. If they match, the message is authentic and unchanged.

5. Security: The security of the MAC relies on the secret key \( K \) and the strength of the hash function \( H \), ensuring that an attacker cannot forge a valid MAC without knowledge of the key.

## Program:
```
import hmac
import hashlib
import base64

def compute_hmac(key: bytes, message: bytes) -> str:
    tag = hmac.new(key, message, digestmod=hashlib.sha256).digest()
    return base64.b64encode(tag).decode()

def verify_hmac(key: bytes, message: bytes, tag_b64: str) -> bool:
    expected = base64.b64decode(tag_b64)
    actual = hmac.new(key, message, digestmod=hashlib.sha256).digest()
    return hmac.compare_digest(expected, actual)

if __name__ == "__main__":
    key = input("Enter key (text): ").encode()
    msg = input("Enter message: ").encode()

    tag = compute_hmac(key, msg)
    print("\nComputed HMAC (Base64):", tag)

    ok = verify_hmac(key, msg, tag)
    print("Verification result:", "VALID" if ok else "INVALID")

```


## Output:
<img width="497" height="180" alt="image" src="https://github.com/user-attachments/assets/1b2f6e18-95c1-4f06-8630-1365e73c6723" />

## Result:
The program is executed successfully.
