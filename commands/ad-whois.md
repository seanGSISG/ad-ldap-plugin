---
description: Quick Active Directory user lookup — resolve a name / sAMAccountName / UPN / mail to a user and present key fields including password expiry.
argument-hint: <name | sAMAccountName | UPN | mail>
---

Look up the Active Directory user identified by: **$ARGUMENTS**

Use the `ad-ldap` MCP tools (read-only):

1. If `$ARGUMENTS` is an exact account form (sAMAccountName, UPN, mail, or a DN containing `=`),
   call `ad_get_user(identifier="$ARGUMENTS")` directly.
2. Otherwise call `ad_find_users(query="$ARGUMENTS")` first:
   - No matches → say so and stop.
   - One match → `ad_get_user` on it.
   - Several matches → list them (displayName + sAMAccountName + UPN) and ask which one; do not guess.

Then present these key fields from `ad_get_user` concisely:
- displayName, sAMAccountName, userPrincipalName, mail
- title, department, physicalDeliveryOfficeName (office), telephoneNumber
- manager
- distinguishedName
- **Account status:** whether disabled (from userAccountControl) and lockoutTime if locked
- **Password:** `password_expired` (bool) and `days_until_expiry` (int or null) — call out expired or
  soon-to-expire accounts explicitly.

This is a read-only lookup: do not modify anything. If the bind fails, run `ad_check_connection`
and report the error.
