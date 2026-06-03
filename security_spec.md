# ZRADX STORE Firebase Hardened Security Spec

This document details the Zero-Trust security patterns and assertions for the ZRADX STORE application database layer (Firestore).

## 1. Data Invariants

- **Users**: A user document must have a `uid` that matches their authenticated account (`request.auth.uid`). Users cannot manually elevate their role to `admin` or toggle their `isVerifiedSeller` status.
- **Game Metadata**: Only administrator accounts can create, update, or delete games and pricing structures. Guest or regular users have read-only access.
- **Account Listings**: Regular users can list accounts with a status of `pending`. Only administrators can toggle account listings to `active`, `sold`, or `rejected`. Sellers cannot modify listings that are not theirs.
- **Orders**: Orders must reflect the correct price paid based on the products. Once an order reaches `completed` or `refunded` stage, it becomes immutable to standard clients.
- **Promo Codes**: Regular clients can check promo codes but only admins can provision, alter, or remove codes.
- **Wallet Transactions**: Wallet deposits, purchases, or refunds must be registered with exact audit logs. The core balance is controlled strictly.

---

## 2. The "Dirty Dozen" Payloads (Exploit Vector Audits)

Below are twelve malicious payloads designed to bypass client validation. The FireStore Fortress rules must block these unconditionally.

1. **Privilege Escalation**: Standard user registers with `{"uid": "attacker_123", "role": "admin"}`.
   - *Result*: `PERMISSION_DENIED` (role is protected).
2. **Seller Self-Verification**: User self-claims verification badge with `{"isVerifiedSeller": true}`.
   - *Result*: `PERMISSION_DENIED` (isVerifiedSeller is protected).
3. **Identity Spoofing**: Attacker lists an item under a victim's ID: `{"sellerUid": "victim_uid", "price": 100}`.
   - *Result*: `PERMISSION_DENIED` (sellerUid must match request.auth.uid).
4. **Self-Approval (Account Listings)**: User bypasses admin review: `{"status": "active"}`.
   - *Result*: `PERMISSION_DENIED` (status transition restricted to Admin).
5. **Ghost Field Injection**: Submitting `{"title": "Awesome MLBB Acc", "price": 50, "ghost_field_is_premium": true}`.
   - *Result*: `PERMISSION_DENIED` (only schema approved attributes allowed).
6. **Denial of Wallet ID Flooding**: Attacker attempts to write a document with a 2MB binary string as its Document ID.
   - *Result*: `PERMISSION_DENIED` (isValidId() restricts length to 128 characters and chars via Regex).
7. **Negative Balance Adjustment**: Attacker deposits `{"type": "deposit", "amount": -1000}`.
   - *Result*: `PERMISSION_DENIED` (numbers must be positive).
8. **Direct Balance Injection**: Bypassing ledger logs to update `users/{uid}` directly: `{"walletBalance": 999999}`.
   - *Result*: `PERMISSION_DENIED` (immutable / restricted update fields).
9. **Order Hijacking**: User attempts to view other users' order receipts: `get /orders/some_other_user_order`.
   - *Result*: `PERMISSION_DENIED` (orders read must belong to owner or admin).
10. **Coupon Poisoning**: Bypassing logic to list coupon: `{"code": "90PERCENT", "discountPercentage": 90, "isActive": true}`.
    - *Result*: `PERMISSION_DENIED` (create/write restricted to admin).
11. **Chat Impersonation**: Attacker sends a message with `{"sender": "admin"}` to trick customer support agent.
    - *Result*: `PERMISSION_DENIED` (sender role must match actual user credentials).
12. **Completed Order Lock Tampering**: User attempts to update standard fields of an order after status is marked `'completed'`.
    - *Result*: `PERMISSION_DENIED` (status field lock on terminal states).
