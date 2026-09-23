# AD/LDAP domain glossary

Terms that actually appear in this codebase, for newcomers to Active Directory.

## Identifiers

| Term | Meaning |
| --- | --- |
| `sAMAccountName` | Legacy short account name (e.g. `jdoe`). Tools accept it as a user identifier. |
| `userPrincipalName` (UPN) | Email-style identifier (`jdoe@example.com`). Alternative bind/lookup form. |
| DN (`distinguishedName`) | Full LDAP path of an object (`CN=John Doe,OU=Staff,DC=example,DC=com`). Writes target DNs; the client resolves identifiers to DNs first. |
| `displayName` | Human name; the bulk-assign matcher keys on it (normalized: case-insensitive, whitespace-collapsed). |

## Attributes & flags

| Term | Meaning |
| --- | --- |
| `userAccountControl` (UAC) | Bitfield of account flags. Bits used in code (`mcp/ad_client.py`): `0x2` ACCOUNTDISABLE (account disabled), `0x200` NORMAL_ACCOUNT (default), `0x10000` DONT_EXPIRE_PASSWORD. |
| `LDAP_MATCHING_RULE_BIT_AND` | Extensible-match OID `1.2.840.113556.1.4.803` used in filters to test UAC bits (e.g. exclude disabled accounts). Not supported by ldap3 MOCK_SYNC — see tests. |
| `managedBy` | DN of the user/group managing a computer object. Target of the bulk-assign workflow. |
| `unicodePwd` | AD's password attribute; writable only over an encrypted connection, via the ldap3 Microsoft extension. |
| `extensionAttribute1`/`…10` | Free-form Exchange schema attributes; two are in the user write whitelist. |
| `physicalDeliveryOfficeName` | The "Office" field in ADUC. |

## Time & search

| Term | Meaning |
| --- | --- |
| FILETIME | Windows timestamp: 100-ns ticks since 1601-01-01 (`_FILETIME_EPOCH`, `_TICKS_PER_DAY` in `ad_client.py`). Used for password-expiry math. |
| Paged search | LDAP simple-paged-results control; `AD_PAGE_SIZE` (default 500) bounds each page. All searches go through the client's paging helper. |
| Global Catalog | Forest-wide partial-attribute search on port 3269 (SSL). |
| Search base / scoped OU | `AD_BASE_DN` is the root; `AD_USER_SEARCH_BASE` / `AD_COMPUTER_SEARCH_BASE` optionally narrow searches to an OU. |

## Project-specific terms

| Term | Meaning |
| --- | --- |
| Plan → review → apply | The bulk-assign workflow: dry-run plan, human review of unresolved/ambiguous buckets, chunked apply. |
| Owner hint | Free-text owner name parsed from a computer's `description` field, matched against user displayNames. |
| story-NNN | Spec story IDs from `DESIGN.md` referenced in module docstrings (e.g. story-001 = dry-run framework, story-005 = bulk assign). |
