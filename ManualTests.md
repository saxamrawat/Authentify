# Level 2 Manual Testing Checklist

---

# 1. Registration Validation Tests

## Valid Registration [PASSED]
- Create a user with valid credentials.
- Expected:
  - User created successfully
  - Verification email sent

---

## Invalid Email [PASSED]
- Try invalid email formats.
- Expected:
  - Pydantic validation error

---

## Weak Password [PASSED]
Test:
- password
- Password
- Password1

Expected:
- Password validation errors

---

## Invalid Username [PASSED]
Test:
- sa xam
- @@user

Expected:
- Username validation error

---

## Duplicate Email [PASSED]
- Register using existing email.
- Expected:
  - "Email already registered."

---

## Duplicate Username [PASSED]
- Register using existing username.
- Expected:
  - "Username already taken."

---

# 2. Email Verification Tests

## Login Before Verification [PASSED]
- Try logging in before verifying email.
- Expected:
  - "Invalid credentials"

---

## Verify With Valid Token [PASSED]
- Open verification link.
- Expected:
  - Account verified successfully

---

## Reuse Verification Token [PASSED]
- Use same verification token again.
- Expected:
  - Invalid/expired token

---

## Expired Verification Token [PASSED]
- Wait until token expires and retry.
- Expected:
  - Invalid/expired token

---

# 3. Login Tests

## Correct Login [PASSED]
- Login with correct credentials.
- Expected:
  - Access token returned
  - Refresh token returned

---

## Wrong Password [PASSED]
- Login with wrong password.
- Expected:
  - failed_attempts incremented

---

## Wrong Username [PASSED]
- Login with invalid username.
- Expected:
  - Generic invalid credentials response

---

## Username Normalization [PASSED]
Test:
- Saxam
- SAXAM
- saxam

Expected:
- All work identically

---

# 4. Account Locking Tests 

## 3 Failed Attempts [PASSED]
- Enter wrong password 3 times.
- Expected:
  - Account locked

---

## Login During Lock [PASSED]
- Try logging in while locked.
- Expected:
  - "User temporarily locked."

---

## Existing Access Token During Lock [PASSED]
- Lock user while access token still exists.
- Call protected route.
- Expected:
  - Access denied

---

## Admin Unlock [PASSED]
- Unlock user through admin endpoint.
- Expected:
  - Login works again

---

# 5. Rate Limiting Tests

## Rapid Login Attempts [PASSED]
- Spam login endpoint rapidly.
- Expected:
  - 429 Too Many Requests

---

## Wait For Window Reset [PASSED]
- Wait for rate-limit duration.
- Retry login.
- Expected:
  - Login works again

---

# 6. Refresh Token Rotation Tests 

## Initial Login [PASSED]
- Login normally.
- Store Refresh Token A.

---

## Refresh Once [PASSED]
- Use Refresh Token A.
- Expected:
  - New Access Token
  - New Refresh Token B

---

## Reuse Old Refresh Token [PASSED]
- Use Refresh Token A again.
- Expected:
  - Session security violation

---

## After Reuse Detection [PASSED]
- Try using Refresh Token B.
- Expected:
  - Session revoked
  - Forced logout

---

# 7. Logout Tests

## Logout Current Session [PASSED]
- Logout using refresh token.
- Expected:
  - Session revoked

---

## Reuse Logged-Out Refresh Token [PASSED]
- Try using revoked refresh token.
- Expected:
  - Unauthorized / invalid token

---

# 8. Password Reset Tests

## Request Password Reset [PASSED]
- Submit reset request.
- Expected:
  - Reset email sent

---

## Reset Password [PASSED]
- Reset password using token.
- Expected:
  - Password updated

---

## Login With Old Password [PASSED]
- Try old password.
- Expected:
  - Login fails

---

## Login With New Password [PASSED]
- Try new password.
- Expected:
  - Login succeeds

---

## Old Refresh Tokens After Reset [PASSED]
- Try using old refresh tokens.
- Expected:
  - Tokens revoked

---

# 9. RBAC Tests

## Normal User Accessing Admin Route [PASSED]
- Access admin endpoint as regular user.
- Expected:
  - 403 Forbidden

---

## Admin Access [PASSED]
- Access admin route as admin.
- Expected:
  - Success

---

## Role Change [PASSED]
- Change user role.
- Expected:
  - Permissions updated

---

## Self-Demotion [PASSED]
- Admin tries to demote self.
- Expected:
  - Request blocked

---

# 10. Session Consistency Tests

## Lock User While Logged In [PASSED]
- Lock account while user still has tokens.
- Test:
  - Existing access token
  - Existing refresh token

Expected:
- Sessions blocked/revoked

---

# 11. Validation Consistency Tests

## Email Normalization [PASSED]
Test:
- TEST@EMAIL.COM
- test@email.com

Expected:
- Treated identically

---

## Username Normalization [PASSED]
Test:
- Saxam
- saxam
- SAXAM

Expected:
- Treated identically

---

# 12. Edge Case Security Tests

## Invalid Token Type [PASSED]
- Use refresh token where access token required.
- Expected:
  - Invalid token type

---

## Tampered JWT [PASSED]
- Modify JWT payload manually.
- Expected:
  - Authentication failure

---

## Expired Access Token [PASSED]
- Wait until access token expires.
- Expected:
  - Unauthorized response