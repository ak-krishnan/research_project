## ⚙️ Phase 1: Deterministic Engine (Raw Semgrep Output)
```json
{
  "version": "1.160.0",
  "results": [
    {
      "check_id": "javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection",
      "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/dbSchemaChallenge_1.ts",
      "start": {
        "line": 5,
        "col": 28,
        "offset": 284
      },
      "end": {
        "line": 5,
        "col": 162,
        "offset": 418
      },
      "extra": {
        "message": "Detected a sequelize statement that is tainted by user-input. This could lead to SQL injection if the variable is user-controlled and is not properly sanitized. In order to prevent SQL injection, it is recommended to use parameterized queries or prepared statements.",
        "metadata": {
          "interfile": true,
          "references": [
            "https://sequelize.org/docs/v6/core-concepts/raw-queries/#replacements"
          ],
          "category": "security",
          "technology": [
            "express"
          ],
          "cwe": [
            "CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"
          ],
          "owasp": [
            "A01:2017 - Injection",
            "A03:2021 - Injection",
            "A05:2025 - Injection"
          ],
          "cwe2022-top25": true,
          "cwe2021-top25": true,
          "subcategory": [
            "vuln"
          ],
          "likelihood": "HIGH",
          "impact": "HIGH",
          "confidence": "HIGH",
          "license": "Semgrep Rules License v1.0. For more details, visit semgrep.dev/legal/rules-license",
          "vulnerability_class": [
            "SQL Injection"
          ],
          "source": "https://semgrep.dev/r/javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection",
          "shortlink": "https://sg.run/gjoe"
        },
        "severity": "ERROR",
        "fingerprint": "requires login",
        "lines": "requires login",
        "validation_state": "NO_VALIDATOR",
        "engine_kind": "OSS"
      }
    },
    {
      "check_id": "javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection",
      "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/dbSchemaChallenge_3.ts",
      "start": {
        "line": 11,
        "col": 28,
        "offset": 419
      },
      "end": {
        "line": 11,
        "col": 159,
        "offset": 550
      },
      "extra": {
        "message": "Detected a sequelize statement that is tainted by user-input. This could lead to SQL injection if the variable is user-controlled and is not properly sanitized. In order to prevent SQL injection, it is recommended to use parameterized queries or prepared statements.",
        "metadata": {
          "interfile": true,
          "references": [
            "https://sequelize.org/docs/v6/core-concepts/raw-queries/#replacements"
          ],
          "category": "security",
          "technology": [
            "express"
          ],
          "cwe": [
            "CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"
          ],
          "owasp": [
            "A01:2017 - Injection",
            "A03:2021 - Injection",
            "A05:2025 - Injection"
          ],
          "cwe2022-top25": true,
          "cwe2021-top25": true,
          "subcategory": [
            "vuln"
          ],
          "likelihood": "HIGH",
          "impact": "HIGH",
          "confidence": "HIGH",
          "license": "Semgrep Rules License v1.0. For more details, visit semgrep.dev/legal/rules-license",
          "vulnerability_class": [
            "SQL Injection"
          ],
          "source": "https://semgrep.dev/r/javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection",
          "shortlink": "https://sg.run/gjoe"
        },
        "severity": "ERROR",
        "fingerprint": "requires login",
        "lines": "requires login",
        "validation_state": "NO_VALIDATOR",
        "engine_kind": "OSS"
      }
    },
    {
      "check_id": "javascript.audit.detect-replaceall-sanitization.detect-replaceall-sanitization",
      "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/restfulXssChallenge_2.ts",
      "start": {
        "line": 49,
        "col": 34,
        "offset": 1827
      },
      "end": {
        "line": 49,
        "col": 82,
        "offset": 1875
      },
      "extra": {
        "message": "Detected a call to `replaceAll()` in an attempt to HTML escape the string `tableData[i].description`. Manually sanitizing input through a manually built list can be circumvented in many situations, and it's better to use a well known sanitization library such as `sanitize-html` or `DOMPurify`.",
        "metadata": {
          "category": "security",
          "technology": [
            "javascript",
            "typescript"
          ],
          "owasp": [
            "A07:2017 - Cross-Site Scripting (XSS)",
            "A03:2021 - Injection",
            "A05:2025 - Injection"
          ],
          "cwe": [
            "CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"
          ],
          "references": [
            "https://www.npmjs.com/package/dompurify",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
          ],
          "cwe2022-top25": true,
          "cwe2021-top25": true,
          "subcategory": [
            "audit"
          ],
          "likelihood": "LOW",
          "impact": "LOW",
          "confidence": "LOW",
          "license": "Semgrep Rules License v1.0. For more details, visit semgrep.dev/legal/rules-license",
          "vulnerability_class": [
            "Cross-Site-Scripting (XSS)"
          ],
          "source": "https://semgrep.dev/r/javascript.audit.detect-replaceall-sanitization.detect-replaceall-sanitization",
          "shortlink": "https://sg.run/AzoB"
        },
        "severity": "INFO",
        "fingerprint": "requires login",
        "lines": "requires login",
        "validation_state": "NO_VALIDATOR",
        "engine_kind": "OSS"
      }
    },
    {
      "check_id": "javascript.audit.detect-replaceall-sanitization.detect-replaceall-sanitization",
      "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/restfulXssChallenge_2.ts",
      "start": {
        "line": 49,
        "col": 34,
        "offset": 1827
      },
      "end": {
        "line": 49,
        "col": 106,
        "offset": 1899
      },
      "extra": {
        "message": "Detected a call to `replaceAll()` in an attempt to HTML escape the string `tableData[i].description.replaceAll('<', '&lt;')`. Manually sanitizing input through a manually built list can be circumvented in many situations, and it's better to use a well known sanitization library such as `sanitize-html` or `DOMPurify`.",
        "metadata": {
          "category": "security",
          "technology": [
            "javascript",
            "typescript"
          ],
          "owasp": [
            "A07:2017 - Cross-Site Scripting (XSS)",
            "A03:2021 - Injection",
            "A05:2025 - Injection"
          ],
          "cwe": [
            "CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"
          ],
          "references": [
            "https://www.npmjs.com/package/dompurify",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
          ],
          "cwe2022-top25": true,
          "cwe2021-top25": true,
          "subcategory": [
            "audit"
          ],
          "likelihood": "LOW",
          "impact": "LOW",
          "confidence": "LOW",
          "license": "Semgrep Rules License v1.0. For more details, visit semgrep.dev/legal/rules-license",
          "vulnerability_class": [
            "Cross-Site-Scripting (XSS)"
          ],
          "source": "https://semgrep.dev/r/javascript.audit.detect-replaceall-sanitization.detect-replaceall-sanitization",
          "shortlink": "https://sg.run/AzoB"
        },
        "severity": "INFO",
        "fingerprint": "requires login",
        "lines": "requires login",
        "validation_state": "NO_VALIDATOR",
        "engine_kind": "OSS"
      }
    },
    {
      "check_id": "javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection",
      "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/unionSqlInjectionChallenge_1.ts",
      "start": {
        "line": 6,
        "col": 28,
        "offset": 326
      },
      "end": {
        "line": 6,
        "col": 159,
        "offset": 457
      },
      "extra": {
        "message": "Detected a sequelize statement that is tainted by user-input. This could lead to SQL injection if the variable is user-controlled and is not properly sanitized. In order to prevent SQL injection, it is recommended to use parameterized queries or prepared statements.",
        "metadata": {
          "interfile": true,
          "references": [
            "https://sequelize.org/docs/v6/core-concepts/raw-queries/#replacements"
          ],
          "category": "security",
          "technology": [
            "express"
          ],
          "cwe": [
            "CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"
          ],
          "owasp": [
            "A01:2017 - Injection",
            "A03:2021 - Injection",
            "A05:2025 - Injection"
          ],
          "cwe2022-top25": true,
          "cwe2021-top25": true,
          "subcategory": [
            "vuln"
          ],
          "likelihood": "HIGH",
          "impact": "HIGH",
          "confidence": "HIGH",
          "license": "Semgrep Rules License v1.0. For more details, visit semgrep.dev/legal/rules-license",
          "vulnerability_class": [
            "SQL Injection"
          ],
          "source": "https://semgrep.dev/r/javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection",
          "shortlink": "https://sg.run/gjoe"
        },
        "severity": "ERROR",
        "fingerprint": "requires login",
        "lines": "requires login",
        "validation_state": "NO_VALIDATOR",
        "engine_kind": "OSS"
      }
    },
    {
      "check_id": "javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection",
      "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/unionSqlInjectionChallenge_3.ts",
      "start": {
        "line": 10,
        "col": 28,
        "offset": 458
      },
      "end": {
        "line": 10,
        "col": 159,
        "offset": 589
      },
      "extra": {
        "message": "Detected a sequelize statement that is tainted by user-input. This could lead to SQL injection if the variable is user-controlled and is not properly sanitized. In order to prevent SQL injection, it is recommended to use parameterized queries or prepared statements.",
        "metadata": {
          "interfile": true,
          "references": [
            "https://sequelize.org/docs/v6/core-concepts/raw-queries/#replacements"
          ],
          "category": "security",
          "technology": [
            "express"
          ],
          "cwe": [
            "CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"
          ],
          "owasp": [
            "A01:2017 - Injection",
            "A03:2021 - Injection",
            "A05:2025 - Injection"
          ],
          "cwe2022-top25": true,
          "cwe2021-top25": true,
          "subcategory": [
            "vuln"
          ],
          "likelihood": "HIGH",
          "impact": "HIGH",
          "confidence": "HIGH",
          "license": "Semgrep Rules License v1.0. For more details, visit semgrep.dev/legal/rules-license",
          "vulnerability_class": [
            "SQL Injection"
          ],
          "source": "https://semgrep.dev/r/javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection",
          "shortlink": "https://sg.run/gjoe"
        },
        "severity": "ERROR",
        "fingerprint": "requires login",
        "lines": "requires login",
        "validation_state": "NO_VALIDATOR",
        "engine_kind": "OSS"
      }
    },
    {
      "check_id": "generic.secrets.security.detected-generic-secret.detected-generic-secret",
      "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/users.yml",
      "start": {
        "line": 151,
        "col": 7,
        "offset": 3523
      },
      "end": {
        "line": 151,
        "col": 47,
        "offset": 3563
      },
      "extra": {
        "message": "Generic Secret detected",
        "metadata": {
          "cwe": [
            "CWE-798: Use of Hard-coded Credentials"
          ],
          "source-rule-url": "https://github.com/dxa4481/truffleHogRegexes/blob/master/truffleHogRegexes/regexes.json",
          "category": "security",
          "technology": [
            "secrets"
          ],
          "confidence": "LOW",
          "owasp": [
            "A07:2021 - Identification and Authentication Failures",
            "A07:2025 - Authentication Failures"
          ],
          "references": [
            "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures"
          ],
          "cwe2022-top25": true,
          "cwe2021-top25": true,
          "subcategory": [
            "audit"
          ],
          "likelihood": "LOW",
          "impact": "MEDIUM",
          "license": "Semgrep Rules License v1.0. For more details, visit semgrep.dev/legal/rules-license",
          "vulnerability_class": [
            "Hard-coded Secrets"
          ],
          "source": "https://semgrep.dev/r/generic.secrets.security.detected-generic-secret.detected-generic-secret",
          "shortlink": "https://sg.run/l2o5"
        },
        "severity": "ERROR",
        "fingerprint": "requires login",
        "lines": "requires login",
        "validation_state": "NO_VALIDATOR",
        "engine_kind": "OSS"
      }
    },
    {
      "check_id": "generic.secrets.security.detected-jwt-token.detected-jwt-token",
      "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/app.guard.spec.ts",
      "start": {
        "line": 38,
        "col": 36,
        "offset": 1466
      },
      "end": {
        "line": 38,
        "col": 148,
        "offset": 1578
      },
      "extra": {
        "message": "JWT token detected",
        "metadata": {
          "source-rule-url": "https://github.com/Yelp/detect-secrets/blob/master/detect_secrets/plugins/jwt.py",
          "category": "security",
          "technology": [
            "secrets",
            "jwt"
          ],
          "confidence": "LOW",
          "references": [
            "https://semgrep.dev/blog/2020/hardcoded-secrets-unverified-tokens-and-other-common-jwt-mistakes/"
          ],
          "cwe": [
            "CWE-321: Use of Hard-coded Cryptographic Key"
          ],
          "owasp": [
            "A02:2021 - Cryptographic Failures",
            "A04:2025 - Cryptographic Failures"
          ],
          "subcategory": [
            "audit"
          ],
          "likelihood": "LOW",
          "impact": "MEDIUM",
          "license": "Semgrep Rules License v1.0. For more details, visit semgrep.dev/legal/rules-license",
          "vulnerability_class": [
            "Cryptographic Issues"
          ],
          "source": "https://semgrep.dev/r/generic.secrets.security.detected-jwt-token.detected-jwt-token",
          "shortlink": "https://sg.run/05N5"
        },
        "severity": "ERROR",
        "fingerprint": "requires login",
        "lines": "requires login",
        "validation_state": "NO_VALIDATOR",
        "engine_kind": "OSS"
      }
    },
    {
      "check_id": "generic.secrets.security.detected-jwt-token.detected-jwt-token",
      "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/last-login-ip/last-login-ip.component.spec.ts",
      "start": {
        "line": 61,
        "col": 36,
        "offset": 2220
      },
      "end": {
        "line": 61,
        "col": 120,
        "offset": 2304
      },
      "extra": {
        "message": "JWT token detected",
        "metadata": {
          "source-rule-url": "https://github.com/Yelp/detect-secrets/blob/master/detect_secrets/plugins/jwt.py",
          "category": "security",
          "technology": [
            "secrets",
            "jwt"
          ],
          "confidence": "LOW",
          "references": [
            "https://semgrep.dev/blog/2020/hardcoded-secrets-unverified-tokens-and-other-common-jwt-mistakes/"
          ],
          "cwe": [
            "CWE-321: Use of Hard-coded Cryptographic Key"
          ],
          "owasp": [
            "A02:2021 - Cryptographic Failures",
            "A04:2025 - Cryptographic Failures"
          ],
          "subcategory": [
            "audit"
          ],
          "likelihood": "LOW",
          "impact": "MEDIUM",
          "license": "Semgrep Rules License v1.0. For more details, visit semgrep.dev/legal/rules-license",
          "vulnerability_class": [
            "Cryptographic Issues"
          ],
          "source": "https://semgrep.dev/r/generic.secrets.security.detected-jwt-token.detected-jwt-token",
          "shortlink": "https://sg.run/05N5"
        },
        "severity": "ERROR",
        "fingerprint": "requires login",
        "lines": "requires login",
        "validation_state": "NO_VALIDATOR",
        "engine_kind": "OSS"
      }
    },
    {
      "check_id": "generic.secrets.security.detected-jwt-token.detected-jwt-token",
      "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/last-login-ip/last-login-ip.component.spec.ts",
      "start": {
        "line": 67,
        "col": 36,
        "offset": 2661
      },
      "end": {
        "line": 67,
        "col": 89,
        "offset": 2714
      },
      "extra": {
        "message": "JWT token detected",
        "metadata": {
          "source-rule-url": "https://github.com/Yelp/detect-secrets/blob/master/detect_secrets/plugins/jwt.py",
          "category": "security",
          "technology": [
            "secrets",
            "jwt"
          ],
          "confidence": "LOW",
          "references": [
            "https://semgrep.dev/blog/2020/hardcoded-secrets-unverified-tokens-and-other-common-jwt-mistakes/"
          ],
          "cwe": [
            "CWE-321: Use of Hard-coded Cryptographic Key"
          ],
          "owasp": [
            "A02:2021 - Cryptographic Failures",
            "A04:2025 - Cryptographic Failures"
          ],
          "subcategory": [
            "audit"
          ],
          "likelihood": "LOW",
          "impact": "MEDIUM",
          "license": "Semgrep Rules License v1.0. For more details, visit semgrep.dev/legal/rules-license",
          "vulnerability_class": [
            "Cryptographic Issues"
          ],
          "source": "https://semgrep.dev/r/generic.secrets.security.detected-jwt-token.detected-jwt-token",
          "shortlink": "https://sg.run/05N5"
        },
        "severity": "ERROR",
        "fingerprint": "requires login",
        "lines": "requires login",
        "validation_state": "NO_VALIDATOR",
        "engine_kind": "OSS"
      }
    },
    {
      "check_id": "javascript.lang.security.audit.prototype-pollution.prototype-pollution-loop.prototype-pollution-loop",
      "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/hacking-instructor/helpers/helpers.ts",
      "start": {
        "line": 49,
        "col": 9,
        "offset": 1383
      },
      "end": {
        "line": 49,
        "col": 54,
        "offset": 1428
      },
      "extra": {
        "message": "Possibility of prototype polluting function detected. By adding or modifying attributes of an object prototype, it is possible to create attributes that exist on every object, or replace critical attributes with malicious ones. This can be problematic if the software depends on existence or non-existence of certain attributes, or uses pre-defined attributes of object prototype (such as hasOwnProperty, toString or valueOf). Possible mitigations might be: freezing the object prototype, using an object without prototypes (via Object.create(null) ), blocking modifications of attributes that resolve to object prototype, using Map instead of object.",
        "metadata": {
          "cwe": [
            "CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes"
          ],
          "category": "security",
          "references": [
            "https://github.com/HoLyVieR/prototype-pollution-nsec18/blob/master/paper/JavaScript_prototype_pollution_attack_in_NodeJS.pdf"
          ],
          "technology": [
            "typescript"
          ],
          "owasp": [
            "A08:2021 - Software and Data Integrity Failures",
            "A08:2025 - Software or Data Integrity Failures"
          ],
          "subcategory": [
            "audit"
          ],
          "likelihood": "LOW",
          "impact": "LOW",
          "confidence": "LOW",
          "license": "Semgrep Rules License v1.0. For more details, visit semgrep.dev/legal/rules-license",
          "vulnerability_class": [
            "Mass Assignment"
          ],
          "source": "https://semgrep.dev/r/javascript.lang.security.audit.prototype-pollution.prototype-pollution-loop.prototype-pollution-loop",
          "shortlink": "https://sg.run/w1DB"
        },
        "severity": "WARNING",
        "fingerprint": "requires login",
        "lines": "requires login",
        "validation_state": "NO_VALIDATOR",
        "engine_kind": "OSS"
      }
    },
    {
      "check_id": "javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp",
      "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/lib/codingChallenges.ts",
      "start": {
        "line": 76,
        "col": 9,
        "offset": 2985
      },
      "end": {
        "line": 76,
        "col": 67,
        "offset": 3043
      },
      "extra": {
        "message": "RegExp() called with a `challengeKey` function argument, this might allow an attacker to cause a Regular Expression Denial-of-Service (ReDoS) within your application as RegExP blocks the main thread. For this reason, it is recommended to use hardcoded regexes instead. If your regex is run on user-controlled input, consider performing input validation or use a regex checking/sanitization library such as https://www.npmjs.com/package/recheck to verify that the regex does not appear vulnerable to ReDoS.",
        "metadata": {
          "owasp": [
            "A05:2021 - Security Misconfiguration",
            "A06:2017 - Security Misconfiguration",
            "A02:2025 - Security Misconfiguration"
          ],
          "cwe": [
            "CWE-1333: Inefficient Regular Expression Complexity"
          ],
          "references": [
            "https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS"
          ],
          "source-rule-url": "https://github.com/nodesecurity/eslint-plugin-security/blob/master/rules/detect-non-literal-regexp.js",
          "category": "security",
          "technology": [
            "javascript"
          ],
          "subcategory": [
            "vuln"
          ],
          "likelihood": "MEDIUM",
          "impact": "MEDIUM",
          "confidence": "LOW",
          "license": "Semgrep Rules License v1.0. For more details, visit semgrep.dev/legal/rules-license",
          "vulnerability_class": [
            "Denial-of-Service (DoS)"
          ],
          "source": "https://semgrep.dev/r/javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp",
          "shortlink": "https://sg.run/gr65"
        },
        "severity": "WARNING",
        "fingerprint": "requires login",
        "lines": "requires login",
        "validation_state": "NO_VALIDATOR",
        "engine_kind": "OSS"
      }
    },
    {
      "check_id": "javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp",
      "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/lib/codingChallenges.ts",
      "start": {
        "line": 78,
        "col": 16,
        "offset": 3113
      },
      "end": {
        "line": 78,
        "col": 77,
        "offset": 3174
      },
      "extra": {
        "message": "RegExp() called with a `challengeKey` function argument, this might allow an attacker to cause a Regular Expression Denial-of-Service (ReDoS) within your application as RegExP blocks the main thread. For this reason, it is recommended to use hardcoded regexes instead. If your regex is run on user-controlled input, consider performing input validation or use a regex checking/sanitization library such as https://www.npmjs.com/package/recheck to verify that the regex does not appear vulnerable to ReDoS.",
        "metadata": {
          "owasp": [
            "A05:2021 - Security Misconfiguration",
            "A06:2017 - Security Misconfiguration",
            "A02:2025 - Security Misconfiguration"
          ],
          "cwe": [
            "CWE-1333: Inefficient Regular Expression Complexity"
          ],
          "references": [
            "https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS"
          ],
          "source-rule-url": "https://github.com/nodesecurity/eslint-plugin-security/blob/master/rules/detect-non-literal-regexp.js",
          "category": "security",
          "technology": [
            "javascript"
          ],
          "subcategory": [
            "vuln"
          ],
          "likelihood": "MEDIUM",
          "impact": "MEDIUM",
          "confidence": "LOW",
          "license": "Semgrep Rules License v1.0. For more details, visit semgrep.dev/legal/rules-license",
          "vulnerability_class": [
            "Denial-of-Service (DoS)"
          ],
          "source": "https://semgrep.dev/r/javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp",
          "shortlink": "https://sg.run/gr65"
        },
        "severity": "WARNING",
        "fingerprint": "requires login",
        "lines": "requires login",
        "validation_state": "NO_VALIDATOR",
        "engine_kind": "OSS"
      }
    },
    {
      "check_id": "javascript.lang.security.audit.hardcoded-hmac-key.hardcoded-hmac-key",
      "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/lib/insecurity.ts",
      "start": {
        "line": 44,
        "col": 39,
        "offset": 2342
      },
      "end": {
        "line": 44,
        "col": 94,
        "offset": 2397
      },
      "extra": {
        "message": "Detected a hardcoded hmac key. Avoid hardcoding secrets and consider using an alternate option such as reading the secret from a config file or using an environment variable.",
        "metadata": {
          "interfile": true,
          "category": "security",
          "technology": [
            "crypto",
            "hmac"
          ],
          "references": [
            "https://rules.sonarsource.com/javascript/RSPEC-2068",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html#key-management"
          ],
          "owasp": [
            "A07:2021 - Identification and Authentication Failures",
            "A07:2025 - Authentication Failures"
          ],
          "cwe": [
            "CWE-798: Use of Hard-coded Credentials"
          ],
          "cwe2022-top25": true,
          "cwe2021-top25": true,
          "subcategory": [
            "audit"
          ],
          "likelihood": "LOW",
          "impact": "LOW",
          "confidence": "LOW",
          "license": "Semgrep Rules License v1.0. For more details, visit semgrep.dev/legal/rules-license",
          "vulnerability_class": [
            "Hard-coded Secrets"
          ],
          "source": "https://semgrep.dev/r/javascript.lang.security.audit.hardcoded-hmac-key.hardcoded-hmac-key",
          "shortlink": "https://sg.run/K9bn"
        },
        "severity": "WARNING",
        "fingerprint": "requires login",
        "lines": "requires login",
        "validation_state": "NO_VALIDATOR",
        "engine_kind": "OSS"
      }
    },
    {
      "check_id": "javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret",
      "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/lib/insecurity.ts",
      "start": {
        "line": 56,
        "col": 56,
        "offset": 2827
      },
      "end": {
        "line": 56,
        "col": 66,
        "offset": 2837
      },
      "extra": {
        "message": "A hard-coded credential was detected. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).",
        "metadata": {
          "cwe": [
            "CWE-798: Use of Hard-coded Credentials"
          ],
          "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"
          ],
          "owasp": [
            "A07:2021 - Identification and Authentication Failures",
            "A07:2025 - Authentication Failures"
          ],
          "asvs": {
            "control_id": "3.5.2 Static API keys or secret",
            "control_url": "https://github.com/OWASP/ASVS/blob/master/4.0/en/0x12-V3-Session-management.md#v35-token-based-session-management",
            "section": "V3: Session Management Verification Requirements",
            "version": "4"
          },
          "category": "security",
          "technology": [
            "jwt",
            "javascript",
            "secrets"
          ],
          "cwe2022-top25": true,
          "cwe2021-top25": true,
          "subcategory": [
            "vuln"
          ],
          "likelihood": "HIGH",
          "impact": "MEDIUM",
          "confidence": "HIGH",
          "license": "Semgrep Rules License v1.0. For more details, visit semgrep.dev/legal/rules-license",
          "vulnerability_class": [
            "Hard-coded Secrets"
          ],
          "source": "https://semgrep.dev/r/javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret",
          "shortlink": "https://sg.run/4xN9"
        },
        "severity": "WARNING",
        "fingerprint": "requires login",
        "lines": "requires login",
        "validation_state": "NO_VALIDATOR",
        "engine_kind": "OSS"
      }
    },
    {
      "check_id": "javascript.lang.security.audit.hardcoded-hmac-key.hardcoded-hmac-key",
      "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/lib/insecurity.ts",
      "start": {
        "line": 152,
        "col": 16,
        "offset": 6281
      },
      "end": {
        "line": 152,
        "col": 55,
        "offset": 6320
      },
      "extra": {
        "message": "Detected a hardcoded hmac key. Avoid hardcoding secrets and consider using an alternate option such as reading the secret from a config file or using an environment variable.",
        "metadata": {
          "interfile": true,
          "category": "security",
          "technology": [
            "crypto",
            "hmac"
          ],
          "references": [
            "https://rules.sonarsource.com/javascript/RSPEC-2068",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html#key-management"
          ],
          "owasp": [
            "A07:2021 - Identification and Authentication Failures",
            "A07:2025 - Authentication Failures"
          ],
          "cwe": [
            "CWE-798: Use of Hard-coded Credentials"
          ],
          "cwe2022-top25": true,
          "cwe2021-top25": true,
          "subcategory": [
            "audit"
          ],
          "likelihood": "LOW",
          "impact": "LOW",
          "confidence": "LOW",
          "license": "Semgrep Rules License v1.0. For more details, visit semgrep.dev/legal/rules-license",
          "vulnerability_class": [
            "Hard-coded Secrets"
          ],
          "source": "https://semgrep.dev/r/javascript.lang.security.audit.hardcoded-hmac-key.hardcoded-hmac-key",
          "shortlink": "https://sg.run/K9bn"
        },
        "severity": "WARNING",
        "fingerprint": "requires login",
        "lines": "requires login",
        "validation_state": "NO_VALIDATOR",
        "engine_kind": "OSS"
      }
    },
    {
      "check_id": "javascript.express.security.audit.express-detect-notevil-usage.express-detect-notevil-usage",
      "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/routes/b2bOrder.ts",
      "start": {
        "line": 23,
        "col": 9,
        "offset": 907
      },
      "end": {
        "line": 23,
        "col": 80,
        "offset": 978
      },
      "extra": {
        "message": "Detected usage of the `notevil` package, which is unmaintained and has vulnerabilities. Using any sort of `eval()` functionality can be very dangerous, but if you must, the `eval` package is an up to date alternative. Be sure that only trusted input reaches an `eval()` function.",
        "metadata": {
          "category": "security",
          "references": [
            "https://github.com/mmckegg/notevil"
          ],
          "cwe": [
            "CWE-1104: Use of Unmaintained Third Party Components"
          ],
          "owasp": [
            "A06:2021 - Vulnerable and Outdated Components",
            "A03:2025 - Software Supply Chain Failures"
          ],
          "technology": [
            "javascript",
            "typescript"
          ],
          "subcategory": [
            "audit"
          ],
          "likelihood": "LOW",
          "impact": "HIGH",
          "confidence": "LOW",
          "license": "Semgrep Rules License v1.0. For more details, visit semgrep.dev/legal/rules-license",
          "vulnerability_class": [
            "Other"
          ],
          "source": "https://semgrep.dev/r/javascript.express.security.audit.express-detect-notevil-usage.express-detect-notevil-usage",
          "shortlink": "https://sg.run/W70E"
        },
        "severity": "WARNING",
        "fingerprint": "requires login",
        "lines": "requires login",
        "validation_state": "NO_VALIDATOR",
        "engine_kind": "OSS"
      }
    },
    {
      "check_id": "javascript.browser.security.eval-detected.eval-detected",
      "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/routes/captcha.ts",
      "start": {
        "line": 22,
        "col": 20,
        "offset": 874
      },
      "end": {
        "line": 22,
        "col": 36,
        "offset": 890
      },
      "extra": {
        "message": "Detected the use of eval(). eval() can be dangerous if used to evaluate dynamic content. If this content can be input from outside the program, this may be a code injection vulnerability. Ensure evaluated content is not definable by external sources.",
        "metadata": {
          "cwe": [
            "CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')"
          ],
          "owasp": [
            "A03:2021 - Injection",
            "A05:2025 - Injection"
          ],
          "asvs": {
            "control_id": "5.2.4 Dynamic Code Execution Features",
            "control_url": "https://github.com/OWASP/ASVS/blob/master/4.0/en/0x13-V5-Validation-Sanitization-Encoding.md#v52-sanitization-and-sandboxing",
            "section": "V5 Validation, Sanitization and Encoding",
            "version": "4"
          },
          "category": "security",
          "technology": [
            "browser"
          ],
          "subcategory": [
            "audit"
          ],
          "likelihood": "LOW",
          "impact": "MEDIUM",
          "confidence": "LOW",
          "references": [
            "https://owasp.org/Top10/A03_2021-Injection"
          ],
          "license": "Semgrep Rules License v1.0. For more details, visit semgrep.dev/legal/rules-license",
          "vulnerability_class": [
            "Code Injection"
          ],
          "source": "https://semgrep.dev/r/javascript.browser.security.eval-detected.eval-detected",
          "shortlink": "https://sg.run/7ope"
        },
        "severity": "WARNING",
        "fingerprint": "requires login",
        "lines": "requires login",
        "validation_state": "NO_VALIDATOR",
        "engine_kind": "OSS"
      }
    },
    {
      "check_id": "javascript.express.security.injection.raw-html-format.raw-html-format",
      "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/routes/chatbot.ts",
      "start": {
        "line": 205,
        "col": 46,
        "offset": 6297
      },
      "end": {
        "line": 205,
        "col": 56,
        "offset": 6307
      },
      "extra": {
        "message": "User data flows into the host portion of this manually-constructed HTML. This can introduce a Cross-Site-Scripting (XSS) vulnerability if this comes from user-provided input. Consider using a sanitization library such as DOMPurify to sanitize the HTML within.",
        "metadata": {
          "cwe": [
            "CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"
          ],
          "owasp": [
            "A07:2017 - Cross-Site Scripting (XSS)",
            "A03:2021 - Injection",
            "A05:2025 - Injection"
          ],
          "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
          ],
          "category": "security",
          "technology": [
            "express"
          ],
          "cwe2022-top25": true,
          "cwe2021-top25": true,
          "subcategory": [
            "vuln"
          ],
          "likelihood": "HIGH",
          "impact": "MEDIUM",
          "confidence": "MEDIUM",
          "license": "Semgrep Rules License v1.0. For more details, visit semgrep.dev/legal/rules-license",
          "vulnerability_class": [
            "Cross-Site-Scripting (XSS)"
          ],
          "source": "https://semgrep.dev/r/javascript.express.security.injection.raw-html-format.raw-html-format",
          "shortlink": "https://sg.run/5DO3"
        },
        "severity": "WARNING",
        "fingerprint": "requires login",
        "lines": "requires login",
        "validation_state": "NO_VALIDATOR",
        "engine_kind": "OSS"
      }
    },
    {
      "check_id": "javascript.express.security.audit.remote-property-injection.remote-property-injection",
      "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/routes/currentUser.ts",
      "start": {
        "line": 31,
        "col": 15,
        "offset": 1260
      },
      "end": {
        "line": 31,
        "col": 76,
        "offset": 1321
      },
      "extra": {
        "message": "Bracket object notation with user input is present, this might allow an attacker to access all properties of the object and even it's prototype. Use literal values for object properties.",
        "metadata": {
          "confidence": "LOW",
          "owasp": [
            "A02:2017 - Broken Authentication",
            "A04:2021 - Insecure Design",
            "A06:2025 - Insecure Design"
          ],
          "cwe": [
            "CWE-522: Insufficiently Protected Credentials"
          ],
          "category": "security",
          "technology": [
            "express"
          ],
          "references": [
            "https://github.com/nodesecurity/eslint-plugin-security/blob/3c7522ca1be800353513282867a1034c795d9eb4/docs/the-dangers-of-square-bracket-notation.md"
          ],
          "cwe2021-top25": true,
          "subcategory": [
            "vuln"
          ],
          "likelihood": "MEDIUM",
          "impact": "MEDIUM",
          "license": "Semgrep Rules License v1.0. For more details, visit semgrep.dev/legal/rules-license",
          "vulnerability_class": [
            "Cryptographic Issues"
          ],
          "source": "https://semgrep.dev/r/javascript.express.security.audit.remote-property-injection.remote-property-injection",
          "shortlink": "https://sg.run/Z4gn"
        },
        "severity": "ERROR",
        "fingerprint": "requires login",
        "lines": "requires login",
        "validation_state": "NO_VALIDATOR",
        "engine_kind": "OSS"
      }
    },
    {
      "check_id": "javascript.express.security.audit.express-res-sendfile.express-res-sendfile",
      "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/routes/fileServer.ts",
      "start": {
        "line": 33,
        "col": 20,
        "offset": 1142
      },
      "end": {
        "line": 33,
        "col": 46,
        "offset": 1168
      },
      "extra": {
        "message": "The application processes user-input, this is passed to res.sendFile which can allow an attacker to arbitrarily read files on the system through path traversal. It is recommended to perform input validation in addition to canonicalizing the path. This allows you to validate the path against the intended directory it should be accessing.",
        "metadata": {
          "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html"
          ],
          "technology": [
            "express"
          ],
          "category": "security",
          "cwe": [
            "CWE-73: External Control of File Name or Path"
          ],
          "owasp": [
            "A04:2021 - Insecure Design",
            "A06:2025 - Insecure Design"
          ],
          "subcategory": [
            "vuln"
          ],
          "likelihood": "HIGH",
          "impact": "MEDIUM",
          "confidence": "MEDIUM",
          "license": "Semgrep Rules License v1.0. For more details, visit semgrep.dev/legal/rules-license",
          "vulnerability_class": [
            "Path Traversal"
          ],
          "source": "https://semgrep.dev/r/javascript.express.security.audit.express-res-sendfile.express-res-sendfile",
          "shortlink": "https://sg.run/7DJk"
        },
        "severity": "WARNING",
        "fingerprint": "requires login",
        "lines": "requires login",
        "validation_state": "NO_VALIDATOR",
        "engine_kind": "OSS"
      }
    },
    {
      "check_id": "javascript.express.security.audit.express-libxml-vm-noent.express-libxml-vm-noent",
      "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/routes/fileUpload.ts",
      "start": {
        "line": 83,
        "col": 24,
        "offset": 3359
      },
      "end": {
        "line": 83,
        "col": 140,
        "offset": 3475
      },
      "extra": {
        "message": "Detected use of parseXml() function with the `noent` field set to `true`. This can lead to an XML External Entities (XXE) attack if untrusted data is passed into it.",
        "metadata": {
          "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html"
          ],
          "owasp": [
            "A04:2017 - XML External Entities (XXE)",
            "A05:2021 - Security Misconfiguration",
            "A02:2025 - Security Misconfiguration"
          ],
          "cwe": [
            "CWE-611: Improper Restriction of XML External Entity Reference"
          ],
          "category": "security",
          "technology": [
            "express"
          ],
          "cwe2022-top25": true,
          "cwe2021-top25": true,
          "subcategory": [
            "audit"
          ],
          "likelihood": "LOW",
          "impact": "HIGH",
          "confidence": "LOW",
          "license": "Semgrep Rules License v1.0. For more details, visit semgrep.dev/legal/rules-license",
          "vulnerability_class": [
            "XML Injection"
          ],
          "source": "https://semgrep.dev/r/javascript.express.security.audit.express-libxml-vm-noent.express-libxml-vm-noent",
          "shortlink": "https://sg.run/n8Ag"
        },
        "severity": "WARNING",
        "fingerprint": "requires login",
        "lines": "requires login",
        "validation_state": "NO_VALIDATOR",
        "engine_kind": "OSS"
      }
    },
    {
      "check_id": "javascript.express.security.audit.express-res-sendfile.express-res-sendfile",
      "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/routes/keyServer.ts",
      "start": {
        "line": 14,
        "col": 20,
        "offset": 410
      },
      "end": {
        "line": 14,
        "col": 57,
        "offset": 447
      },
      "extra": {
        "message": "The application processes user-input, this is passed to res.sendFile which can allow an attacker to arbitrarily read files on the system through path traversal. It is recommended to perform input validation in addition to canonicalizing the path. This allows you to validate the path against the intended directory it should be accessing.",
        "metadata": {
          "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html"
          ],
          "technology": [
            "express"
          ],
          "category": "security",
          "cwe": [
            "CWE-73: External Control of File Name or Path"
          ],
          "owasp": [
            "A04:2021 - Insecure Design",
            "A06:2025 - Insecure Design"
          ],
          "subcategory": [
            "vuln"
          ],
          "likelihood": "HIGH",
          "impact": "MEDIUM",
          "confidence": "MEDIUM",
          "license": "Semgrep Rules License v1.0. For more details, visit semgrep.dev/legal/rules-license",
          "vulnerability_class": [
            "Path Traversal"
          ],
          "source": "https://semgrep.dev/r/javascript.express.security.audit.express-res-sendfile.express-res-sendfile",
          "shortlink": "https://sg.run/7DJk"
        },
        "severity": "WARNING",
        "fingerprint": "requires login",
        "lines": "requires login",
        "validation_state": "NO_VALIDATOR",
        "engine_kind": "OSS"
      }
    },
    {
      "check_id": "javascript.express.security.audit.express-res-sendfile.express-res-sendfile",
      "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/routes/logfileServer.ts",
      "start": {
        "line": 14,
        "col": 20,
        "offset": 410
      },
      "end": {
        "line": 14,
        "col": 47,
        "offset": 437
      },
      "extra": {
        "message": "The application processes user-input, this is passed to res.sendFile which can allow an attacker to arbitrarily read files on the system through path traversal. It is recommended to perform input validation in addition to canonicalizing the path. This allows you to validate the path against the intended directory it should be accessing.",
        "metadata": {
          "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html"
          ],
          "technology": [
            "express"
          ],
          "category": "security",
          "cwe": [
            "CWE-73: External Control of File Name or Path"
          ],
          "owasp": [
            "A04:2021 - Insecure Design",
            "A06:2025 - Insecure Design"
          ],
          "subcategory": [
            "vuln"
          ],
          "likelihood": "HIGH",
          "impact": "MEDIUM",
          "confidence": "MEDIUM",
          "license": "Semgrep Rules License v1.0. For more details, visit semgrep.dev/legal/rules-license",
          "vulnerability_class": [
            "Path Traversal"
          ],
          "source": "https://semgrep.dev/r/javascript.express.security.audit.express-res-sendfile.express-res-sendfile",
          "shortlink": "https://sg.run/7DJk"
        },
        "severity": "WARNING",
        "fingerprint": "requires login",
        "lines": "requires login",
        "validation_state": "NO_VALIDATOR",
        "engine_kind": "OSS"
      }
    },
    {
      "check_id": "javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection",
      "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/routes/login.ts",
      "start": {
        "line": 34,
        "col": 28,
        "offset": 1459
      },
      "end": {
        "line": 34,
        "col": 169,
        "offset": 1600
      },
      "extra": {
        "message": "Detected a sequelize statement that is tainted by user-input. This could lead to SQL injection if the variable is user-controlled and is not properly sanitized. In order to prevent SQL injection, it is recommended to use parameterized queries or prepared statements.",
        "metadata": {
          "interfile": true,
          "references": [
            "https://sequelize.org/docs/v6/core-concepts/raw-queries/#replacements"
          ],
          "category": "security",
          "technology": [
            "express"
          ],
          "cwe": [
            "CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"
          ],
          "owasp": [
            "A01:2017 - Injection",
            "A03:2021 - Injection",
            "A05:2025 - Injection"
          ],
          "cwe2022-top25": true,
          "cwe2021-top25": true,
          "subcategory": [
            "vuln"
          ],
          "likelihood": "HIGH",
          "impact": "HIGH",
          "confidence": "HIGH",
          "license": "Semgrep Rules License v1.0. For more details, visit semgrep.dev/legal/rules-license",
          "vulnerability_class": [
            "SQL Injection"
          ],
          "source": "https://semgrep.dev/r/javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection",
          "shortlink": "https://sg.run/gjoe"
        },
        "severity": "ERROR",
        "fingerprint": "requires login",
        "lines": "requires login",
        "validation_state": "NO_VALIDATOR",
        "engine_kind": "OSS"
      }
    },
    {
      "check_id": "javascript.express.security.audit.express-res-sendfile.express-res-sendfile",
      "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/routes/quarantineServer.ts",
      "start": {
        "line": 14,
        "col": 20,
        "offset": 424
      },
      "end": {
        "line": 14,
        "col": 57,
        "offset": 461
      },
      "extra": {
        "message": "The application processes user-input, this is passed to res.sendFile which can allow an attacker to arbitrarily read files on the system through path traversal. It is recommended to perform input validation in addition to canonicalizing the path. This allows you to validate the path against the intended directory it should be accessing.",
        "metadata": {
          "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html"
          ],
          "technology": [
            "express"
          ],
          "category": "security",
          "cwe": [
            "CWE-73: External Control of File Name or Path"
          ],
          "owasp": [
            "A04:2021 - Insecure Design",
            "A06:2025 - Insecure Design"
          ],
          "subcategory": [
            "vuln"
          ],
          "likelihood": "HIGH",
          "impact": "MEDIUM",
          "confidence": "MEDIUM",
          "license": "Semgrep Rules License v1.0. For more details, visit semgrep.dev/legal/rules-license",
          "vulnerability_class": [
            "Path Traversal"
          ],
          "source": "https://semgrep.dev/r/javascript.express.security.audit.express-res-sendfile.express-res-sendfile",
          "shortlink": "https://sg.run/7DJk"
        },
        "severity": "WARNING",
        "fingerprint": "requires login",
        "lines": "requires login",
        "validation_state": "NO_VALIDATOR",
        "engine_kind": "OSS"
      }
    },
    {
      "check_id": "javascript.express.security.audit.express-open-redirect.express-open-redirect",
      "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/routes/redirect.ts",
      "start": {
        "line": 19,
        "col": 20,
        "offset": 1045
      },
      "end": {
        "line": 19,
        "col": 25,
        "offset": 1050
      },
      "extra": {
        "message": "The application redirects to a URL specified by user-supplied input `query` that is not validated. This could redirect users to malicious locations. Consider using an allow-list approach to validate URLs, or warn users they are being redirected to a third-party website.",
        "metadata": {
          "technology": [
            "express"
          ],
          "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"
          ],
          "cwe": [
            "CWE-601: URL Redirection to Untrusted Site ('Open Redirect')"
          ],
          "category": "security",
          "owasp": [
            "A01:2021 - Broken Access Control",
            "A01:2025 - Broken Access Control"
          ],
          "subcategory": [
            "vuln"
          ],
          "likelihood": "HIGH",
          "impact": "MEDIUM",
          "confidence": "HIGH",
          "license": "Semgrep Rules License v1.0. For more details, visit semgrep.dev/legal/rules-license",
          "vulnerability_class": [
            "Open Redirect"
          ],
          "source": "https://semgrep.dev/r/javascript.express.security.audit.express-open-redirect.express-open-redirect",
          "shortlink": "https://sg.run/EpoP"
        },
        "severity": "WARNING",
        "fingerprint": "requires login",
        "lines": "requires login",
        "validation_state": "NO_VALIDATOR",
        "engine_kind": "OSS"
      }
    },
    {
      "check_id": "javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection",
      "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/routes/search.ts",
      "start": {
        "line": 23,
        "col": 28,
        "offset": 847
      },
      "end": {
        "line": 23,
        "col": 159,
        "offset": 978
      },
      "extra": {
        "message": "Detected a sequelize statement that is tainted by user-input. This could lead to SQL injection if the variable is user-controlled and is not properly sanitized. In order to prevent SQL injection, it is recommended to use parameterized queries or prepared statements.",
        "metadata": {
          "interfile": true,
          "references": [
            "https://sequelize.org/docs/v6/core-concepts/raw-queries/#replacements"
          ],
          "category": "security",
          "technology": [
            "express"
          ],
          "cwe": [
            "CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"
          ],
          "owasp": [
            "A01:2017 - Injection",
            "A03:2021 - Injection",
            "A05:2025 - Injection"
          ],
          "cwe2022-top25": true,
          "cwe2021-top25": true,
          "subcategory": [
            "vuln"
          ],
          "likelihood": "HIGH",
          "impact": "HIGH",
          "confidence": "HIGH",
          "license": "Semgrep Rules License v1.0. For more details, visit semgrep.dev/legal/rules-license",
          "vulnerability_class": [
            "SQL Injection"
          ],
          "source": "https://semgrep.dev/r/javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection",
          "shortlink": "https://sg.run/gjoe"
        },
        "severity": "ERROR",
        "fingerprint": "requires login",
        "lines": "requires login",
        "validation_state": "NO_VALIDATOR",
        "engine_kind": "OSS"
      }
    },
    {
      "check_id": "javascript.browser.security.eval-detected.eval-detected",
      "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/routes/userProfile.ts",
      "start": {
        "line": 62,
        "col": 20,
        "offset": 1855
      },
      "end": {
        "line": 62,
        "col": 30,
        "offset": 1865
      },
      "extra": {
        "message": "Detected the use of eval(). eval() can be dangerous if used to evaluate dynamic content. If this content can be input from outside the program, this may be a code injection vulnerability. Ensure evaluated content is not definable by external sources.",
        "metadata": {
          "cwe": [
            "CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')"
          ],
          "owasp": [
            "A03:2021 - Injection",
            "A05:2025 - Injection"
          ],
          "asvs": {
            "control_id": "5.2.4 Dynamic Code Execution Features",
            "control_url": "https://github.com/OWASP/ASVS/blob/master/4.0/en/0x13-V5-Validation-Sanitization-Encoding.md#v52-sanitization-and-sandboxing",
            "section": "V5 Validation, Sanitization and Encoding",
            "version": "4"
          },
          "category": "security",
          "technology": [
            "browser"
          ],
          "subcategory": [
            "audit"
          ],
          "likelihood": "LOW",
          "impact": "MEDIUM",
          "confidence": "LOW",
          "references": [
            "https://owasp.org/Top10/A03_2021-Injection"
          ],
          "license": "Semgrep Rules License v1.0. For more details, visit semgrep.dev/legal/rules-license",
          "vulnerability_class": [
            "Code Injection"
          ],
          "source": "https://semgrep.dev/r/javascript.browser.security.eval-detected.eval-detected",
          "shortlink": "https://sg.run/7ope"
        },
        "severity": "WARNING",
        "fingerprint": "requires login",
        "lines": "requires login",
        "validation_state": "NO_VALIDATOR",
        "engine_kind": "OSS"
      }
    },
    {
      "check_id": "javascript.lang.security.audit.code-string-concat.code-string-concat",
      "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/routes/userProfile.ts",
      "start": {
        "line": 62,
        "col": 20,
        "offset": 1855
      },
      "end": {
        "line": 62,
        "col": 30,
        "offset": 1865
      },
      "extra": {
        "message": "Found data from an Express or Next web request flowing to `eval`. If this data is user-controllable this can lead to execution of arbitrary system commands in the context of your application process. Avoid `eval` whenever possible.",
        "metadata": {
          "interfile": true,
          "confidence": "HIGH",
          "owasp": [
            "A03:2021 - Injection",
            "A05:2025 - Injection"
          ],
          "cwe": [
            "CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')"
          ],
          "references": [
            "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval",
            "https://nodejs.org/api/child_process.html#child_processexeccommand-options-callback",
            "https://www.stackhawk.com/blog/nodejs-command-injection-examples-and-prevention/",
            "https://ckarande.gitbooks.io/owasp-nodegoat-tutorial/content/tutorial/a1_-_server_side_js_injection.html"
          ],
          "category": "security",
          "technology": [
            "node.js",
            "Express",
            "Next.js"
          ],
          "subcategory": [
            "vuln"
          ],
          "likelihood": "MEDIUM",
          "impact": "MEDIUM",
          "license": "Semgrep Rules License v1.0. For more details, visit semgrep.dev/legal/rules-license",
          "vulnerability_class": [
            "Code Injection"
          ],
          "source": "https://semgrep.dev/r/javascript.lang.security.audit.code-string-concat.code-string-concat",
          "shortlink": "https://sg.run/96Yk"
        },
        "severity": "ERROR",
        "fingerprint": "requires login",
        "lines": "requires login",
        "validation_state": "NO_VALIDATOR",
        "engine_kind": "OSS"
      }
    },
    {
      "check_id": "javascript.lang.security.audit.unknown-value-with-script-tag.unknown-value-with-script-tag",
      "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/routes/videoHandler.ts",
      "start": {
        "line": 58,
        "col": 90,
        "offset": 1893
      },
      "end": {
        "line": 58,
        "col": 94,
        "offset": 1897
      },
      "extra": {
        "message": "Cannot determine what 'subs' is and it is used with a '<script>' tag. This could be susceptible to cross-site scripting (XSS). Ensure 'subs' is not externally controlled, or sanitize this data.",
        "metadata": {
          "owasp": [
            "A07:2017 - Cross-Site Scripting (XSS)",
            "A03:2021 - Injection",
            "A05:2025 - Injection"
          ],
          "cwe": [
            "CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"
          ],
          "references": [
            "https://www.developsec.com/2017/11/09/xss-in-a-script-tag/",
            "https://github.com/juice-shop/juice-shop/blob/1ceb8751e986dacd3214a618c37e7411be6bc11a/routes/videoHandler.ts#L68"
          ],
          "category": "security",
          "technology": [
            "javascript"
          ],
          "cwe2022-top25": true,
          "cwe2021-top25": true,
          "subcategory": [
            "audit"
          ],
          "likelihood": "LOW",
          "impact": "LOW",
          "confidence": "LOW",
          "license": "Semgrep Rules License v1.0. For more details, visit semgrep.dev/legal/rules-license",
          "vulnerability_class": [
            "Cross-Site-Scripting (XSS)"
          ],
          "source": "https://semgrep.dev/r/javascript.lang.security.audit.unknown-value-with-script-tag.unknown-value-with-script-tag",
          "shortlink": "https://sg.run/1Zy1"
        },
        "severity": "WARNING",
        "fingerprint": "requires login",
        "lines": "requires login",
        "validation_state": "NO_VALIDATOR",
        "engine_kind": "OSS"
      }
    },
    {
      "check_id": "javascript.lang.security.audit.unknown-value-with-script-tag.unknown-value-with-script-tag",
      "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/routes/videoHandler.ts",
      "start": {
        "line": 71,
        "col": 165,
        "offset": 2827
      },
      "end": {
        "line": 71,
        "col": 169,
        "offset": 2831
      },
      "extra": {
        "message": "Cannot determine what 'subs' is and it is used with a '<script>' tag. This could be susceptible to cross-site scripting (XSS). Ensure 'subs' is not externally controlled, or sanitize this data.",
        "metadata": {
          "owasp": [
            "A07:2017 - Cross-Site Scripting (XSS)",
            "A03:2021 - Injection",
            "A05:2025 - Injection"
          ],
          "cwe": [
            "CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"
          ],
          "references": [
            "https://www.developsec.com/2017/11/09/xss-in-a-script-tag/",
            "https://github.com/juice-shop/juice-shop/blob/1ceb8751e986dacd3214a618c37e7411be6bc11a/routes/videoHandler.ts#L68"
          ],
          "category": "security",
          "technology": [
            "javascript"
          ],
          "cwe2022-top25": true,
          "cwe2021-top25": true,
          "subcategory": [
            "audit"
          ],
          "likelihood": "LOW",
          "impact": "LOW",
          "confidence": "LOW",
          "license": "Semgrep Rules License v1.0. For more details, visit semgrep.dev/legal/rules-license",
          "vulnerability_class": [
            "Cross-Site-Scripting (XSS)"
          ],
          "source": "https://semgrep.dev/r/javascript.lang.security.audit.unknown-value-with-script-tag.unknown-value-with-script-tag",
          "shortlink": "https://sg.run/1Zy1"
        },
        "severity": "WARNING",
        "fingerprint": "requires login",
        "lines": "requires login",
        "validation_state": "NO_VALIDATOR",
        "engine_kind": "OSS"
      }
    },
    {
      "check_id": "javascript.lang.security.audit.unsafe-formatstring.unsafe-formatstring",
      "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/server.ts",
      "start": {
        "line": 155,
        "col": 21,
        "offset": 7505
      },
      "end": {
        "line": 155,
        "col": 63,
        "offset": 7547
      },
      "extra": {
        "message": "Detected string concatenation with a non-literal variable in a util.format / console.log function. If an attacker injects a format specifier in the string, it will forge the log message. Try to use constant values for the format string.",
        "metadata": {
          "cwe": [
            "CWE-134: Use of Externally-Controlled Format String"
          ],
          "owasp": [
            "A01:2021 - Broken Access Control",
            "A01:2025 - Broken Access Control"
          ],
          "category": "security",
          "technology": [
            "javascript"
          ],
          "subcategory": [
            "audit"
          ],
          "likelihood": "MEDIUM",
          "impact": "LOW",
          "confidence": "LOW",
          "references": [
            "https://cwe.mitre.org/data/definitions/134.html"
          ],
          "license": "Semgrep Rules License v1.0. For more details, visit semgrep.dev/legal/rules-license",
          "vulnerability_class": [
            "Improper Validation"
          ],
          "source": "https://semgrep.dev/r/javascript.lang.security.audit.unsafe-formatstring.unsafe-formatstring",
          "shortlink": "https://sg.run/7Y5R"
        },
        "severity": "INFO",
        "fingerprint": "requires login",
        "lines": "requires login",
        "validation_state": "NO_VALIDATOR",
        "engine_kind": "OSS"
      }
    },
    {
      "check_id": "javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing",
      "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/server.ts",
      "start": {
        "line": 269,
        "col": 3,
        "offset": 12274
      },
      "end": {
        "line": 269,
        "col": 76,
        "offset": 12347
      },
      "extra": {
        "message": "Directory listing/indexing is enabled, which may lead to disclosure of sensitive directories and files. It is recommended to disable directory listing unless it is a public resource. If you need directory listing, ensure that sensitive files are inaccessible when querying the resource.",
        "metadata": {
          "interfile": true,
          "cwe": [
            "CWE-548: Exposure of Information Through Directory Listing"
          ],
          "owasp": [
            "A06:2017 - Security Misconfiguration",
            "A01:2021 - Broken Access Control",
            "A01:2025 - Broken Access Control"
          ],
          "category": "security",
          "technology": [
            "express"
          ],
          "references": [
            "https://www.npmjs.com/package/serve-index",
            "https://www.acunetix.com/blog/articles/directory-listing-information-disclosure/"
          ],
          "subcategory": [
            "vuln"
          ],
          "likelihood": "HIGH",
          "impact": "MEDIUM",
          "confidence": "MEDIUM",
          "license": "Semgrep Rules License v1.0. For more details, visit semgrep.dev/legal/rules-license",
          "vulnerability_class": [
            "Mishandled Sensitive Information"
          ],
          "source": "https://semgrep.dev/r/javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing",
          "shortlink": "https://sg.run/DX2G"
        },
        "severity": "WARNING",
        "fingerprint": "requires login",
        "lines": "requires login",
        "validation_state": "NO_VALIDATOR",
        "engine_kind": "OSS"
      }
    },
    {
      "check_id": "javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing",
      "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/server.ts",
      "start": {
        "line": 273,
        "col": 3,
        "offset": 12643
      },
      "end": {
        "line": 273,
        "col": 109,
        "offset": 12749
      },
      "extra": {
        "message": "Directory listing/indexing is enabled, which may lead to disclosure of sensitive directories and files. It is recommended to disable directory listing unless it is a public resource. If you need directory listing, ensure that sensitive files are inaccessible when querying the resource.",
        "metadata": {
          "interfile": true,
          "cwe": [
            "CWE-548: Exposure of Information Through Directory Listing"
          ],
          "owasp": [
            "A06:2017 - Security Misconfiguration",
            "A01:2021 - Broken Access Control",
            "A01:2025 - Broken Access Control"
          ],
          "category": "security",
          "technology": [
            "express"
          ],
          "references": [
            "https://www.npmjs.com/package/serve-index",
            "https://www.acunetix.com/blog/articles/directory-listing-information-disclosure/"
          ],
          "subcategory": [
            "vuln"
          ],
          "likelihood": "HIGH",
          "impact": "MEDIUM",
          "confidence": "MEDIUM",
          "license": "Semgrep Rules License v1.0. For more details, visit semgrep.dev/legal/rules-license",
          "vulnerability_class": [
            "Mishandled Sensitive Information"
          ],
          "source": "https://semgrep.dev/r/javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing",
          "shortlink": "https://sg.run/DX2G"
        },
        "severity": "WARNING",
        "fingerprint": "requires login",
        "lines": "requires login",
        "validation_state": "NO_VALIDATOR",
        "engine_kind": "OSS"
      }
    },
    {
      "check_id": "javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing",
      "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/server.ts",
      "start": {
        "line": 277,
        "col": 3,
        "offset": 12853
      },
      "end": {
        "line": 277,
        "col": 115,
        "offset": 12965
      },
      "extra": {
        "message": "Directory listing/indexing is enabled, which may lead to disclosure of sensitive directories and files. It is recommended to disable directory listing unless it is a public resource. If you need directory listing, ensure that sensitive files are inaccessible when querying the resource.",
        "metadata": {
          "interfile": true,
          "cwe": [
            "CWE-548: Exposure of Information Through Directory Listing"
          ],
          "owasp": [
            "A06:2017 - Security Misconfiguration",
            "A01:2021 - Broken Access Control",
            "A01:2025 - Broken Access Control"
          ],
          "category": "security",
          "technology": [
            "express"
          ],
          "references": [
            "https://www.npmjs.com/package/serve-index",
            "https://www.acunetix.com/blog/articles/directory-listing-information-disclosure/"
          ],
          "subcategory": [
            "vuln"
          ],
          "likelihood": "HIGH",
          "impact": "MEDIUM",
          "confidence": "MEDIUM",
          "license": "Semgrep Rules License v1.0. For more details, visit semgrep.dev/legal/rules-license",
          "vulnerability_class": [
            "Mishandled Sensitive Information"
          ],
          "source": "https://semgrep.dev/r/javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing",
          "shortlink": "https://sg.run/DX2G"
        },
        "severity": "WARNING",
        "fingerprint": "requires login",
        "lines": "requires login",
        "validation_state": "NO_VALIDATOR",
        "engine_kind": "OSS"
      }
    },
    {
      "check_id": "javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing",
      "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/server.ts",
      "start": {
        "line": 281,
        "col": 3,
        "offset": 13117
      },
      "end": {
        "line": 281,
        "col": 103,
        "offset": 13217
      },
      "extra": {
        "message": "Directory listing/indexing is enabled, which may lead to disclosure of sensitive directories and files. It is recommended to disable directory listing unless it is a public resource. If you need directory listing, ensure that sensitive files are inaccessible when querying the resource.",
        "metadata": {
          "interfile": true,
          "cwe": [
            "CWE-548: Exposure of Information Through Directory Listing"
          ],
          "owasp": [
            "A06:2017 - Security Misconfiguration",
            "A01:2021 - Broken Access Control",
            "A01:2025 - Broken Access Control"
          ],
          "category": "security",
          "technology": [
            "express"
          ],
          "references": [
            "https://www.npmjs.com/package/serve-index",
            "https://www.acunetix.com/blog/articles/directory-listing-information-disclosure/"
          ],
          "subcategory": [
            "vuln"
          ],
          "likelihood": "HIGH",
          "impact": "MEDIUM",
          "confidence": "MEDIUM",
          "license": "Semgrep Rules License v1.0. For more details, visit semgrep.dev/legal/rules-license",
          "vulnerability_class": [
            "Mishandled Sensitive Information"
          ],
          "source": "https://semgrep.dev/r/javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing",
          "shortlink": "https://sg.run/DX2G"
        },
        "severity": "WARNING",
        "fingerprint": "requires login",
        "lines": "requires login",
        "validation_state": "NO_VALIDATOR",
        "engine_kind": "OSS"
      }
    },
    {
      "check_id": "javascript.express.security.audit.xss.pug.explicit-unescape.template-explicit-unescape",
      "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/views/promotionVideo.pug",
      "start": {
        "line": 78,
        "col": 13,
        "offset": 3816
      },
      "end": {
        "line": 78,
        "col": 40,
        "offset": 3843
      },
      "extra": {
        "message": "Detected an explicit unescape in a Pug template, using either '!=' or '!{...}'. If external data can reach these locations, your application is exposed to a cross-site scripting (XSS) vulnerability. If you must do this, ensure no external data can reach this location.",
        "metadata": {
          "cwe": [
            "CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"
          ],
          "owasp": [
            "A07:2017 - Cross-Site Scripting (XSS)",
            "A03:2021 - Injection",
            "A05:2025 - Injection"
          ],
          "references": [
            "https://pugjs.org/language/code.html#unescaped-buffered-code",
            "https://pugjs.org/language/attributes.html#unescaped-attributes"
          ],
          "category": "security",
          "technology": [
            "express"
          ],
          "cwe2022-top25": true,
          "cwe2021-top25": true,
          "subcategory": [
            "audit"
          ],
          "likelihood": "LOW",
          "impact": "MEDIUM",
          "confidence": "LOW",
          "license": "Semgrep Rules License v1.0. For more details, visit semgrep.dev/legal/rules-license",
          "vulnerability_class": [
            "Cross-Site-Scripting (XSS)"
          ],
          "source": "https://semgrep.dev/r/javascript.express.security.audit.xss.pug.explicit-unescape.template-explicit-unescape",
          "shortlink": "https://sg.run/3xbe"
        },
        "severity": "WARNING",
        "fingerprint": "requires login",
        "lines": "requires login",
        "validation_state": "NO_VALIDATOR",
        "engine_kind": "OSS"
      }
    }
  ],
  "errors": [
    {
      "code": 3,
      "level": "warn",
      "type": "Syntax error",
      "message": "Syntax error at line /var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/registerAdminChallenge_2.ts:1:\n `/* Generated API endpoints */\n  finale.initialize({ app, sequelize })\n\n  const autoModels = [\n    { name: 'Product', exclude: [], model: ProductModel },\n    { name: 'Feedback', exclude: [], model: FeedbackModel },\n    { name: 'BasketItem', exclude: [], model: BasketItemModel },\n    { name: 'Challenge', exclude: [], model: ChallengeModel },\n    { name: 'Complaint', exclude: [], model: ComplaintModel },\n    { name: 'Recycle', exclude: [], model: RecycleModel },\n    { name: 'SecurityQuestion', exclude: [], model: SecurityQuestionModel },\n    { name: 'SecurityAnswer', exclude: [], model: SecurityAnswerModel },\n    { name: 'Address', exclude: [], model: AddressModel },\n    { name: 'PrivacyRequest', exclude: [], model: PrivacyRequestModel },\n    { name: 'Card', exclude: [], model: CardModel },\n    { name: 'Quantity', exclude: [], model: QuantityModel },\n    { name: 'Hint', exclude: [], model: HintModel }\n  ]\n\n  for (const { name, exclude, model } of autoModels) {\n    const resource = finale.resource({\n      model,\n      endpoints: [`/api/${name}s`, `/api/${name}s/:id`],\n      excludeAttributes: exclude,\n      pagination: false\n    })` was unexpected",
      "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/registerAdminChallenge_2.ts"
    },
    {
      "code": 3,
      "level": "warn",
      "type": "Syntax error",
      "message": "Syntax error at line /var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/registerAdminChallenge_4.ts:1:\n `/* Generated API endpoints */\n  finale.initialize({ app, sequelize })\n\n  const autoModels = [\n    { name: 'User', exclude: ['password', 'totpSecret', 'role'], model: UserModel },\n    { name: 'Product', exclude: [], model: ProductModel },\n    { name: 'Feedback', exclude: [], model: FeedbackModel },\n    { name: 'BasketItem', exclude: [], model: BasketItemModel },\n    { name: 'Challenge', exclude: [], model: ChallengeModel },\n    { name: 'Complaint', exclude: [], model: ComplaintModel },\n    { name: 'Recycle', exclude: [], model: RecycleModel },\n    { name: 'SecurityQuestion', exclude: [], model: SecurityQuestionModel },\n    { name: 'SecurityAnswer', exclude: [], model: SecurityAnswerModel },\n    { name: 'Address', exclude: [], model: AddressModel },\n    { name: 'PrivacyRequest', exclude: [], model: PrivacyRequestModel },\n    { name: 'Card', exclude: [], model: CardModel },\n    { name: 'Quantity', exclude: [], model: QuantityModel },\n    { name: 'Hint', exclude: [], model: HintModel }\n  ]\n\n  for (const { name, exclude, model } of autoModels) {\n    const resource = finale.resource({\n      model,\n      endpoints: [`/api/${name}s`, `/api/${name}s/:id`],\n      excludeAttributes: exclude,\n      pagination: false\n    })\n\n    // create a wallet when a new user is registered using API\n    if (name === 'User') {\n      resource.create.send.before((req: Request, res: Response, context: { instance: { id: any }, continue: any }) => {\n        WalletModel.create({ UserId: context.instance.id }).catch((err: unknown) => {\n          console.log(err)\n        })\n        return context.continue\n      })\n    }` was unexpected",
      "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/registerAdminChallenge_4.ts"
    },
    {
      "code": 3,
      "level": "warn",
      "type": "Syntax error",
      "message": "Syntax error at line /var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/registerAdminChallenge_3_correct.ts:1:\n `/* Generated API endpoints */\n  finale.initialize({ app, sequelize })\n\n  const autoModels = [\n    { name: 'User', exclude: ['password', 'totpSecret'], model: UserModel },\n    { name: 'Product', exclude: [], model: ProductModel },\n    { name: 'Feedback', exclude: [], model: FeedbackModel },\n    { name: 'BasketItem', exclude: [], model: BasketItemModel },\n    { name: 'Challenge', exclude: [], model: ChallengeModel },\n    { name: 'Complaint', exclude: [], model: ComplaintModel },\n    { name: 'Recycle', exclude: [], model: RecycleModel },\n    { name: 'SecurityQuestion', exclude: [], model: SecurityQuestionModel },\n    { name: 'SecurityAnswer', exclude: [], model: SecurityAnswerModel },\n    { name: 'Address', exclude: [], model: AddressModel },\n    { name: 'PrivacyRequest', exclude: [], model: PrivacyRequestModel },\n    { name: 'Card', exclude: [], model: CardModel },\n    { name: 'Quantity', exclude: [], model: QuantityModel },\n    { name: 'Hint', exclude: [], model: HintModel }\n  ]\n\n  for (const { name, exclude, model } of autoModels) {\n    const resource = finale.resource({\n      model,\n      endpoints: [`/api/${name}s`, `/api/${name}s/:id`],\n      excludeAttributes: exclude,\n      pagination: false\n    })\n\n    // create a wallet when a new user is registered using API\n    if (name === 'User') {\n      resource.create.send.before((req: Request, res: Response, context: { instance: { id: any }, continue: any }) => {\n        WalletModel.create({ UserId: context.instance.id }).catch((err: unknown) => {\n          console.log(err)\n        })\n        context.instance.role = 'customer'\n        return context.continue\n      })\n    }` was unexpected",
      "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/registerAdminChallenge_3_correct.ts"
    },
    {
      "code": 3,
      "level": "warn",
      "type": "Syntax error",
      "message": "Syntax error at line /var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/registerAdminChallenge_1.ts:1:\n `/* Generated API endpoints */\n  finale.initialize({ app, sequelize })\n\n  const autoModels = [\n    { name: 'User', exclude: ['password', 'totpSecret'], model: UserModel },\n    { name: 'Product', exclude: [], model: ProductModel },\n    { name: 'Feedback', exclude: [], model: FeedbackModel },\n    { name: 'BasketItem', exclude: [], model: BasketItemModel },\n    { name: 'Challenge', exclude: [], model: ChallengeModel },\n    { name: 'Complaint', exclude: [], model: ComplaintModel },\n    { name: 'Recycle', exclude: [], model: RecycleModel },\n    { name: 'SecurityQuestion', exclude: [], model: SecurityQuestionModel },\n    { name: 'SecurityAnswer', exclude: [], model: SecurityAnswerModel },\n    { name: 'Address', exclude: [], model: AddressModel },\n    { name: 'PrivacyRequest', exclude: [], model: PrivacyRequestModel },\n    { name: 'Card', exclude: [], model: CardModel },\n    { name: 'Quantity', exclude: [], model: QuantityModel },\n    { name: 'Hint', exclude: [], model: HintModel }\n  ]\n\n  for (const { name, exclude, model } of autoModels) {\n    const resource = finale.resource({\n      model,\n      endpoints: [`/api/${name}s`, `/api/${name}s/:id`],\n      excludeAttributes: exclude,\n      pagination: false\n    })\n\n    // create a wallet when a new user is registered using API\n    if (name === 'User') {\n      resource.create.send.before((req: Request, res: Response, context: { instance: { id: any }, continue: any }) => {\n        WalletModel.create({ UserId: context.instance.id }).catch((err: unknown) => {\n          console.log(err)\n        })\n        context.instance.role = context.instance.role ? context.instance.role : 'customer'\n        return context.continue\n      })\n    }` was unexpected",
      "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/registerAdminChallenge_1.ts"
    },
    {
      "code": 3,
      "level": "warn",
      "type": "Syntax error",
      "message": "Syntax error at line /var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/weakPasswordChallenge_3.ts:1:\n `User.init(\n      password: {\n        type: DataTypes.STRING,\n        set (clearTextPassword: string) {\n          validatePasswordHasAtLeastOneNumber(clearTextPassword)\n          validatePasswordHasAtLeastOneSpecialChar(clearTextPassword)\n          validatePasswordHasAtLeastOneUpperCaseChar(clearTextPassword)\n          validatePasswordHasAtLeastOneLowerCaseChar(clearTextPassword)\n          validatePasswordHasAtLeastTenChar(clearTextPassword)\n          this.setDataValue('password', security.hash(clearTextPassword))\n        }\n      },` was unexpected",
      "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/weakPasswordChallenge_3.ts"
    },
    {
      "code": 3,
      "level": "warn",
      "type": "Syntax error",
      "message": "Syntax error at line /var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/weakPasswordChallenge_2.ts:1:\n `User.init(\n      password: {\n        type: DataTypes.STRING,\n        set (clearTextPassword: string) {\n          validatePasswordHasAtLeastOneNumber(clearTextPassword)\n          validatePasswordHasAtLeastOneSpecialChar(clearTextPassword)\n          validatePasswordHasAtLeastOneUpperCaseChar(clearTextPassword)\n          validatePasswordHasAtLeastOneLowerCaseChar(clearTextPassword)\n          validatePasswordHasAtLeastTenChar(clearTextPassword)\n          validatePasswordIsNotInTopOneMillionCommonPasswordsList(clearTextPassword)\n          this.setDataValue('password', security.hash(clearTextPassword))\n        }\n      },` was unexpected",
      "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/weakPasswordChallenge_2.ts"
    },
    {
      "code": 3,
      "level": "warn",
      "type": "Syntax error",
      "message": "Syntax error at line /var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/weakPasswordChallenge_1_correct.ts:1:\n `User.init(\n      password: {\n        type: DataTypes.STRING,\n        set (clearTextPassword: string) {\n          validatePasswordHasAtLeastTenChar(clearTextPassword)\n          validatePasswordIsNotInTopOneMillionCommonPasswordsList(clearTextPassword)\n          this.setDataValue('password', security.hash(clearTextPassword))\n        }\n      },` was unexpected",
      "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/weakPasswordChallenge_1_correct.ts"
    },
    {
      "code": 3,
      "level": "warn",
      "type": "Syntax error",
      "message": "Syntax error at line /var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/weakPasswordChallenge_4.ts:1:\n `User.init(\n      password: {\n        type: DataTypes.STRING,\n        set (clearTextPassword: string) {\n          validatePasswordIsNotInTopOneMillionCommonPasswordsList(clearTextPassword)\n          this.setDataValue('password', security.hash(clearTextPassword))\n        }\n      },` was unexpected",
      "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/weakPasswordChallenge_4.ts"
    },
    {
      "code": 3,
      "level": "warn",
      "type": "Syntax error",
      "message": "Syntax error at line /var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/loginAdminChallenge_1.ts:1:\n `export function login () {\n  function afterLogin (user: { data: User, bid: number }, res: Response, next: NextFunction) {\n    BasketModel.findOrCreate({ where: { UserId: user.data.id } })\n      .then(([basket]: [BasketModel, boolean]) => {\n        const token = security.authorize(user)\n        user.bid = basket.id // keep track of original basket\n        security.authenticatedUsers.put(token, user)\n        res.json({ authentication: { token, bid: basket.id, umail: user.data.email } })\n      }).catch((error: Error) => {\n        next(error)\n      })\n  }\n\n  return (req: Request, res: Response, next: NextFunction) => {\n    if (req.body.email.match(/.*['-;].*/) || req.body.password.match(/.*['-;].*/)) {\n      res.status(451).send(res.__('SQL Injection detected.'))\n    }\n    models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`, { model: models.User, plain: true })\n      .then((authenticatedUser) => {\n        const user = utils.queryResultToJson(authenticatedUser)\n        if (user.data?.id && user.data.totpSecret !== '') {\n          res.status(401).json({\n            status: 'totp_token_required',\n            data: {\n              tmpToken: security.authorize({\n                userId: user.data.id,\n                type: 'password_valid_needs_second_factor_token'\n              })\n            }\n          })\n        } else if (user.data?.id) {\n          afterLogin(user, res, next)\n        } else {\n          res.status(401).send(res.__('Invalid email or password.'))\n        }\n      }).catch((error: Error) => {\n        next(error)\n      })\n  }` was unexpected",
      "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/loginAdminChallenge_1.ts"
    },
    {
      "code": 3,
      "level": "warn",
      "type": "Syntax error",
      "message": "Syntax error at line /var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/loginBenderChallenge_1.ts:1:\n `export function login () {\n  function afterLogin (user: { data: User, bid: number }, res: Response, next: NextFunction) {\n    BasketModel.findOrCreate({ where: { UserId: user.data.id } })\n      .then(([basket]: [BasketModel, boolean]) => {\n        const token = security.authorize(user)\n        user.bid = basket.id // keep track of original basket\n        security.authenticatedUsers.put(token, user)\n        res.json({ authentication: { token, bid: basket.id, umail: user.data.email } })\n      }).catch((error: Error) => {\n        next(error)\n      })\n  }\n\n  return (req: Request, res: Response, next: NextFunction) => {\n    if (req.body.email.match(/.*['-;].*/) || req.body.password.match(/.*['-;].*/)) {\n      res.status(451).send(res.__('SQL Injection detected.'))\n    }\n    models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`, { model: models.User, plain: true })\n      .then((authenticatedUser) => {\n        const user = utils.queryResultToJson(authenticatedUser)\n        if (user.data?.id && user.data.totpSecret !== '') {\n          res.status(401).json({\n            status: 'totp_token_required',\n            data: {\n              tmpToken: security.authorize({\n                userId: user.data.id,\n                type: 'password_valid_needs_second_factor_token'\n              })\n            }\n          })\n        } else if (user.data?.id) {\n          afterLogin(user, res, next)\n        } else {\n          res.status(401).send(res.__('Invalid email or password.'))\n        }\n      }).catch((error: Error) => {\n        next(error)\n      })\n  }` was unexpected",
      "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/loginBenderChallenge_1.ts"
    },
    {
      "code": 3,
      "level": "warn",
      "type": "Syntax error",
      "message": "Syntax error at line /var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/loginJimChallenge_4.ts:1:\n `export function login () {\n  function afterLogin (user: { data: User, bid: number }, res: Response, next: NextFunction) {\n    BasketModel.findOrCreate({ where: { UserId: user.data.id } })\n      .then(([basket]: [BasketModel, boolean]) => {\n        const token = security.authorize(user)\n        user.bid = basket.id // keep track of original basket\n        security.authenticatedUsers.put(token, user)\n        res.json({ authentication: { token, bid: basket.id, umail: user.data.email } })\n      }).catch((error: Error) => {\n        next(error)\n      })\n  }\n\n  return (req: Request, res: Response, next: NextFunction) => {\n    if (req.body.email.match(/.*['-;].*/) || req.body.password.match(/.*['-;].*/)) {\n      res.status(451).send(res.__('SQL Injection detected.'))\n    }\n    models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`, { model: models.User, plain: true })\n      .then((authenticatedUser) => {\n        const user = utils.queryResultToJson(authenticatedUser)\n        if (user.data?.id && user.data.totpSecret !== '') {\n          res.status(401).json({\n            status: 'totp_token_required',\n            data: {\n              tmpToken: security.authorize({\n                userId: user.data.id,\n                type: 'password_valid_needs_second_factor_token'\n              })\n            }\n          })\n        } else if (user.data?.id) {\n          afterLogin(user, res, next)\n        } else {\n          res.status(401).send(res.__('Invalid email or password.'))\n        }\n      }).catch((error: Error) => {\n        next(error)\n      })\n  }` was unexpected",
      "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/loginJimChallenge_4.ts"
    },
    {
      "code": 3,
      "level": "warn",
      "type": "Syntax error",
      "message": "Syntax error at line /var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/loginAdminChallenge_3.ts:1:\n `export function login () {\n  function afterLogin (user: { data: User, bid: number }, res: Response, next: NextFunction) {\n    BasketModel.findOrCreate({ where: { UserId: user.data.id } })\n      .then(([basket]: [BasketModel, boolean]) => {\n        const token = security.authorize(user)\n        user.bid = basket.id // keep track of original basket\n        security.authenticatedUsers.put(token, user)\n        res.json({ authentication: { token, bid: basket.id, umail: user.data.email } })\n      }).catch((error: Error) => {\n        next(error)\n      })\n  }\n\n  return (req: Request, res: Response, next: NextFunction) => {\n    models.sequelize.query(`SELECT * FROM Users WHERE email = $1 AND password = $2 AND deletedAt IS NULL`,\n      { bind: [ req.body.email, req.body.password ], model: models.User, plain: true })\n      .then((authenticatedUser) => {\n        const user = utils.queryResultToJson(authenticatedUser)\n        if (user.data?.id && user.data.totpSecret !== '') {\n          res.status(401).json({\n            status: 'totp_token_required',\n            data: {\n              tmpToken: security.authorize({\n                userId: user.data.id,\n                type: 'password_valid_needs_second_factor_token'\n              })\n            }\n          })\n        } else if (user.data?.id) {\n          afterLogin(user, res, next)\n        } else {\n          res.status(401).send(res.__('Invalid email or password.'))\n        }\n      }).catch((error: Error) => {\n        next(error)\n      })\n  }` was unexpected",
      "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/loginAdminChallenge_3.ts"
    },
    {
      "code": 3,
      "level": "warn",
      "type": "Syntax error",
      "message": "Syntax error at line /var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/loginAdminChallenge_4_correct.ts:1:\n `export function login () {\n  function afterLogin (user: { data: User, bid: number }, res: Response, next: NextFunction) {\n    BasketModel.findOrCreate({ where: { UserId: user.data.id } })\n      .then(([basket]: [BasketModel, boolean]) => {\n        const token = security.authorize(user)\n        user.bid = basket.id // keep track of original basket\n        security.authenticatedUsers.put(token, user)\n        res.json({ authentication: { token, bid: basket.id, umail: user.data.email } })\n      }).catch((error: Error) => {\n        next(error)\n      })\n  }\n\n  return (req: Request, res: Response, next: NextFunction) => {\n    models.sequelize.query(`SELECT * FROM Users WHERE email = $1 AND password = $2 AND deletedAt IS NULL`,\n      { bind: [ req.body.email, security.hash(req.body.password) ], model: models.User, plain: true })\n      .then((authenticatedUser) => {\n        const user = utils.queryResultToJson(authenticatedUser)\n        if (user.data?.id && user.data.totpSecret !== '') {\n          res.status(401).json({\n            status: 'totp_token_required',\n            data: {\n              tmpToken: security.authorize({\n                userId: user.data.id,\n                type: 'password_valid_needs_second_factor_token'\n              })\n            }\n          })\n        } else if (user.data?.id) {\n          afterLogin(user, res, next)\n        } else {\n          res.status(401).send(res.__('Invalid email or password.'))\n        }\n      }).catch((error: Error) => {\n        next(error)\n      })\n  }` was unexpected",
      "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/loginAdminChallenge_4_correct.ts"
    },
    {
      "code": 3,
      "level": "warn",
      "type": "Syntax error",
      "message": "Syntax error at line /var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/loginJimChallenge_1_correct.ts:1:\n `export function login () {\n  function afterLogin (user: { data: User, bid: number }, res: Response, next: NextFunction) {\n    BasketModel.findOrCreate({ where: { UserId: user.data.id } })\n      .then(([basket]: [BasketModel, boolean]) => {\n        const token = security.authorize(user)\n        user.bid = basket.id // keep track of original basket\n        security.authenticatedUsers.put(token, user)\n        res.json({ authentication: { token, bid: basket.id, umail: user.data.email } })\n      }).catch((error: Error) => {\n        next(error)\n      })\n  }\n\n  return (req: Request, res: Response, next: NextFunction) => {\n    models.sequelize.query(`SELECT * FROM Users WHERE email = $1 AND password = $2 AND deletedAt IS NULL`,\n      { bind: [ req.body.email, security.hash(req.body.password) ], model: models.User, plain: true })\n      .then((authenticatedUser) => {\n        const user = utils.queryResultToJson(authenticatedUser)\n        if (user.data?.id && user.data.totpSecret !== '') {\n          res.status(401).json({\n            status: 'totp_token_required',\n            data: {\n              tmpToken: security.authorize({\n                userId: user.data.id,\n                type: 'password_valid_needs_second_factor_token'\n              })\n            }\n          })\n        } else if (user.data?.id) {\n          afterLogin(user, res, next)\n        } else {\n          res.status(401).send(res.__('Invalid email or password.'))\n        }\n      }).catch((error: Error) => {\n        next(error)\n      })\n  }` was unexpected",
      "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/loginJimChallenge_1_correct.ts"
    },
    {
      "code": 3,
      "level": "warn",
      "type": "Syntax error",
      "message": "Syntax error at line /var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/loginAdminChallenge_2.ts:1:\n `export function login () {\n  function afterLogin (user: { data: User, bid: number }, res: Response, next: NextFunction) {\n    BasketModel.findOrCreate({ where: { UserId: user.data.id } })\n      .then(([basket]: [BasketModel, boolean]) => {\n        const token = security.authorize(user)\n        user.bid = basket.id // keep track of original basket\n        security.authenticatedUsers.put(token, user)\n        res.json({ authentication: { token, bid: basket.id, umail: user.data.email } })\n      }).catch((error: Error) => {\n        next(error)\n      })\n  }\n\n  return (req: Request, res: Response, next: NextFunction) => {\n    models.sequelize.query(`SELECT * FROM Users WHERE email = $1 AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`,\n      { bind: [ req.body.email ], model: models.User, plain: true })\n      .then((authenticatedUser) => {\n        const user = utils.queryResultToJson(authenticatedUser)\n        if (user.data?.id && user.data.totpSecret !== '') {\n          res.status(401).json({\n            status: 'totp_token_required',\n            data: {\n              tmpToken: security.authorize({\n                userId: user.data.id,\n                type: 'password_valid_needs_second_factor_token'\n              })\n            }\n          })\n        } else if (user.data?.id) {\n          afterLogin(user, res, next)\n        } else {\n          res.status(401).send(res.__('Invalid email or password.'))\n        }\n      }).catch((error: Error) => {\n        next(error)\n      })\n  }` was unexpected",
      "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/loginAdminChallenge_2.ts"
    },
    {
      "code": 3,
      "level": "warn",
      "type": "Syntax error",
      "message": "Syntax error at line /var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/loginBenderChallenge_2_correct.ts:1:\n `export function login () {\n  function afterLogin (user: { data: User, bid: number }, res: Response, next: NextFunction) {\n    BasketModel.findOrCreate({ where: { UserId: user.data.id } })\n      .then(([basket]: [BasketModel, boolean]) => {\n        const token = security.authorize(user)\n        user.bid = basket.id // keep track of original basket\n        security.authenticatedUsers.put(token, user)\n        res.json({ authentication: { token, bid: basket.id, umail: user.data.email } })\n      }).catch((error: Error) => {\n        next(error)\n      })\n  }\n\n  return (req: Request, res: Response, next: NextFunction) => {\n    models.sequelize.query(`SELECT * FROM Users WHERE email = $mail AND password = $pass AND deletedAt IS NULL`,\n      { bind: { mail: req.body.email, pass: security.hash(req.body.password) }, model: models.User, plain: true })\n      .then((authenticatedUser) => {\n        const user = utils.queryResultToJson(authenticatedUser)\n        if (user.data?.id && user.data.totpSecret !== '') {\n          res.status(401).json({\n            status: 'totp_token_required',\n            data: {\n              tmpToken: security.authorize({\n                userId: user.data.id,\n                type: 'password_valid_needs_second_factor_token'\n              })\n            }\n          })\n        } else if (user.data?.id) {\n          afterLogin(user, res, next)\n        } else {\n          res.status(401).send(res.__('Invalid email or password.'))\n        }\n      }).catch((error: Error) => {\n        next(error)\n      })\n  }` was unexpected",
      "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/loginBenderChallenge_2_correct.ts"
    },
    {
      "code": 3,
      "level": "warn",
      "type": "Syntax error",
      "message": "Syntax error at line /var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/loginBenderChallenge_4.ts:1:\n `export function login () {\n  function afterLogin (user: { data: User, bid: number }, res: Response, next: NextFunction) {\n    BasketModel.findOrCreate({ where: { UserId: user.data.id } })\n      .then(([basket]: [BasketModel, boolean]) => {\n        const token = security.authorize(user)\n        user.bid = basket.id // keep track of original basket\n        security.authenticatedUsers.put(token, user)\n        res.json({ authentication: { token, bid: basket.id, umail: user.data.email } })\n      }).catch((error: Error) => {\n        next(error)\n      })\n  }\n\n  return (req: Request, res: Response, next: NextFunction) => {\n    models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`, { model: models.User, plain: false })\n      .then((authenticatedUser) => {\n        const user = utils.queryResultToJson(authenticatedUser)\n        if (user.data?.id && user.data.totpSecret !== '') {\n          res.status(401).json({\n            status: 'totp_token_required',\n            data: {\n              tmpToken: security.authorize({\n                userId: user.data.id,\n                type: 'password_valid_needs_second_factor_token'\n              })\n            }\n          })\n        } else if (user.data?.id) {\n          afterLogin(user, res, next)\n        } else {\n          res.status(401).send(res.__('Invalid email or password.'))\n        }\n      }).catch((error: Error) => {\n        next(error)\n      })\n  }` was unexpected",
      "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/loginBenderChallenge_4.ts"
    },
    {
      "code": 3,
      "level": "warn",
      "type": "Syntax error",
      "message": "Syntax error at line /var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/loginJimChallenge_2.ts:1:\n `export function login () {\n  function afterLogin (user: { data: User, bid: number }, res: Response, next: NextFunction) {\n    BasketModel.findOrCreate({ where: { UserId: user.data.id } })\n      .then(([basket]: [BasketModel, boolean]) => {\n        const token = security.authorize(user)\n        user.bid = basket.id // keep track of original basket\n        security.authenticatedUsers.put(token, user)\n        res.json({ authentication: { token, bid: basket.id, umail: user.data.email } })\n      }).catch((error: Error) => {\n        next(error)\n      })\n  }\n\n  return (req: Request, res: Response, next: NextFunction) => {\n    models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`, { model: models.User, plain: false })\n      .then((authenticatedUser) => {\n        const user = utils.queryResultToJson(authenticatedUser)\n        if (user.data?.id && user.data.totpSecret !== '') {\n          res.status(401).json({\n            status: 'totp_token_required',\n            data: {\n              tmpToken: security.authorize({\n                userId: user.data.id,\n                type: 'password_valid_needs_second_factor_token'\n              })\n            }\n          })\n        } else if (user.data?.id) {\n          afterLogin(user, res, next)\n        } else {\n          res.status(401).send(res.__('Invalid email or password.'))\n        }\n      }).catch((error: Error) => {\n        next(error)\n      })\n  }` was unexpected",
      "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/loginJimChallenge_2.ts"
    },
    {
      "code": 3,
      "level": "warn",
      "type": "Syntax error",
      "message": "Syntax error at line /var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/loginBenderChallenge_3.ts:1:\n `export function login () {\n  function afterLogin (user: { data: User, bid: number }, res: Response, next: NextFunction) {\n    BasketModel.findOrCreate({ where: { UserId: user.data.id } })\n      .then(([basket]: [BasketModel, boolean]) => {\n        const token = security.authorize(user)\n        user.bid = basket.id // keep track of original basket\n        security.authenticatedUsers.put(token, user)\n        res.json({ authentication: { token, bid: basket.id, umail: user.data.email } })\n      }).catch((error: Error) => {\n        next(error)\n      })\n  }\n\n  return (req: Request, res: Response, next: NextFunction) => {\n    models.sequelize.query(`SELECT * FROM Users WHERE email = :mail AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`,\n      { replacements: { mail: req.body.email }, model: models.User, plain: true })\n      .then((authenticatedUser) => {\n        const user = utils.queryResultToJson(authenticatedUser)\n        if (user.data?.id && user.data.totpSecret !== '') {\n          res.status(401).json({\n            status: 'totp_token_required',\n            data: {\n              tmpToken: security.authorize({\n                userId: user.data.id,\n                type: 'password_valid_needs_second_factor_token'\n              })\n            }\n          })\n        } else if (user.data?.id) {\n          afterLogin(user, res, next)\n        } else {\n          res.status(401).send(res.__('Invalid email or password.'))\n        }\n      }).catch((error: Error) => {\n        next(error)\n      })\n  }` was unexpected",
      "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/loginBenderChallenge_3.ts"
    },
    {
      "code": 3,
      "level": "warn",
      "type": "Syntax error",
      "message": "Syntax error at line /var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/loginJimChallenge_3.ts:1:\n `export function login () {\n  function afterLogin (user: { data: User, bid: number }, res: Response, next: NextFunction) {\n    BasketModel.findOrCreate({ where: { UserId: user.data.id } })\n      .then(([basket]: [BasketModel, boolean]) => {\n        const token = security.authorize(user)\n        user.bid = basket.id // keep track of original basket\n        security.authenticatedUsers.put(token, user)\n        res.json({ authentication: { token, bid: basket.id, umail: user.data.email } })\n      }).catch((error: Error) => {\n        next(error)\n      })\n  }\n\n  return (req: Request, res: Response, next: NextFunction) => {\n    models.sequelize.query(`SELECT * FROM Users WHERE email = ? AND password = ? AND deletedAt IS NULL`,\n      { replacements: [ req.body.email, req.body.password ], model: models.User, plain: true })\n      .then((authenticatedUser) => {\n        const user = utils.queryResultToJson(authenticatedUser)\n        if (user.data?.id && user.data.totpSecret !== '') {\n          res.status(401).json({\n            status: 'totp_token_required',\n            data: {\n              tmpToken: security.authorize({\n                userId: user.data.id,\n                type: 'password_valid_needs_second_factor_token'\n              })\n            }\n          })\n        } else if (user.data?.id) {\n          afterLogin(user, res, next)\n        } else {\n          res.status(401).send(res.__('Invalid email or password.'))\n        }\n      }).catch((error: Error) => {\n        next(error)\n      })\n  }` was unexpected",
      "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/loginJimChallenge_3.ts"
    },
    {
      "code": 3,
      "level": "warn",
      "type": [
        "PartialParsing",
        [
          {
            "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/.github/workflows/frontend-bundle-analysis.yml",
            "start": {
              "line": 49,
              "col": 32,
              "offset": 1082
            },
            "end": {
              "line": 49,
              "col": 50,
              "offset": 1100
            }
          }
        ]
      ],
      "message": "Syntax error at line /var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/.github/workflows/frontend-bundle-analysis.yml:49:\n When parsing a snippet as Bash for metavariable-pattern in rule 'yaml.github-actions.security.curl-eval.curl-eval', `{ github.workspace` was unexpected",
      "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/.github/workflows/frontend-bundle-analysis.yml",
      "spans": [
        {
          "file": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/.github/workflows/frontend-bundle-analysis.yml",
          "start": {
            "line": 49,
            "col": 32,
            "offset": 1082
          },
          "end": {
            "line": 49,
            "col": 50,
            "offset": 1100
          }
        }
      ]
    },
    {
      "code": 3,
      "level": "warn",
      "type": [
        "PartialParsing",
        [
          {
            "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/.github/workflows/frontend-bundle-analysis.yml",
            "start": {
              "line": 64,
              "col": 64,
              "offset": 1871
            },
            "end": {
              "line": 65,
              "col": 24,
              "offset": 1938
            }
          }
        ]
      ],
      "message": "Syntax error at line /var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/.github/workflows/frontend-bundle-analysis.yml:64:\n When parsing a snippet as Bash for metavariable-pattern in rule 'yaml.github-actions.security.curl-eval.curl-eval', `\"R`Ty Update bundle analysis screenshot\" -s\ngit push origin master\n` was unexpected",
      "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/.github/workflows/frontend-bundle-analysis.yml",
      "spans": [
        {
          "file": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/.github/workflows/frontend-bundle-analysis.yml",
          "start": {
            "line": 64,
            "col": 64,
            "offset": 1871
          },
          "end": {
            "line": 65,
            "col": 24,
            "offset": 1938
          }
        }
      ]
    },
    {
      "code": 3,
      "level": "warn",
      "type": [
        "PartialParsing",
        [
          {
            "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/.github/workflows/release.yml",
            "start": {
              "line": 24,
              "col": 55,
              "offset": 721
            },
            "end": {
              "line": 24,
              "col": 58,
              "offset": 724
            }
          }
        ]
      ],
      "message": "Syntax error at line /var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/.github/workflows/release.yml:24:\n When parsing a snippet as Bash for metavariable-pattern in rule 'yaml.github-actions.security.curl-eval.curl-eval', `${{` was unexpected",
      "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/.github/workflows/release.yml",
      "spans": [
        {
          "file": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/.github/workflows/release.yml",
          "start": {
            "line": 24,
            "col": 55,
            "offset": 721
          },
          "end": {
            "line": 24,
            "col": 58,
            "offset": 724
          }
        }
      ]
    },
    {
      "code": 3,
      "level": "warn",
      "type": [
        "PartialParsing",
        [
          {
            "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/.github/workflows/release.yml",
            "start": {
              "line": 36,
              "col": 27,
              "offset": 902
            },
            "end": {
              "line": 36,
              "col": 48,
              "offset": 923
            }
          }
        ]
      ],
      "message": "Syntax error at line /var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/.github/workflows/release.yml:36:\n When parsing a snippet as Bash for metavariable-pattern in rule 'yaml.github-actions.security.curl-eval.curl-eval', `{ matrix.node-version` was unexpected",
      "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/.github/workflows/release.yml",
      "spans": [
        {
          "file": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/.github/workflows/release.yml",
          "start": {
            "line": 36,
            "col": 27,
            "offset": 902
          },
          "end": {
            "line": 36,
            "col": 48,
            "offset": 923
          }
        }
      ]
    },
    {
      "code": 3,
      "level": "warn",
      "type": [
        "PartialParsing",
        [
          {
            "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/.github/workflows/update-challenges-ebook.yml",
            "start": {
              "line": 24,
              "col": 62,
              "offset": 586
            },
            "end": {
              "line": 24,
              "col": 65,
              "offset": 589
            }
          }
        ]
      ],
      "message": "Syntax error at line /var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/.github/workflows/update-challenges-ebook.yml:24:\n When parsing a snippet as Bash for metavariable-pattern in rule 'yaml.github-actions.security.curl-eval.curl-eval', `${{` was unexpected",
      "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/.github/workflows/update-challenges-ebook.yml",
      "spans": [
        {
          "file": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/.github/workflows/update-challenges-ebook.yml",
          "start": {
            "line": 24,
            "col": 62,
            "offset": 586
          },
          "end": {
            "line": 24,
            "col": 65,
            "offset": 589
          }
        }
      ]
    },
    {
      "code": 3,
      "level": "warn",
      "type": [
        "PartialParsing",
        [
          {
            "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/restfulXssChallenge_1_correct.ts",
            "start": {
              "line": 46,
              "col": 18,
              "offset": 0
            },
            "end": {
              "line": 46,
              "col": 23,
              "offset": 5
            }
          },
          {
            "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/restfulXssChallenge_1_correct.ts",
            "start": {
              "line": 50,
              "col": 3,
              "offset": 0
            },
            "end": {
              "line": 50,
              "col": 56,
              "offset": 53
            }
          },
          {
            "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/restfulXssChallenge_1_correct.ts",
            "start": {
              "line": 56,
              "col": 3,
              "offset": 0
            },
            "end": {
              "line": 56,
              "col": 4,
              "offset": 1
            }
          }
        ]
      ],
      "message": "Syntax error at line /var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/restfulXssChallenge_1_correct.ts:46:\n `: any` was unexpected",
      "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/restfulXssChallenge_1_correct.ts",
      "spans": [
        {
          "file": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/restfulXssChallenge_1_correct.ts",
          "start": {
            "line": 46,
            "col": 18,
            "offset": 0
          },
          "end": {
            "line": 46,
            "col": 23,
            "offset": 5
          }
        },
        {
          "file": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/restfulXssChallenge_1_correct.ts",
          "start": {
            "line": 50,
            "col": 3,
            "offset": 0
          },
          "end": {
            "line": 50,
            "col": 56,
            "offset": 53
          }
        },
        {
          "file": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/restfulXssChallenge_1_correct.ts",
          "start": {
            "line": 56,
            "col": 3,
            "offset": 0
          },
          "end": {
            "line": 56,
            "col": 4,
            "offset": 1
          }
        }
      ]
    },
    {
      "code": 3,
      "level": "warn",
      "type": [
        "PartialParsing",
        [
          {
            "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/restfulXssChallenge_2.ts",
            "start": {
              "line": 47,
              "col": 38,
              "offset": 0
            },
            "end": {
              "line": 47,
              "col": 45,
              "offset": 7
            }
          },
          {
            "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/restfulXssChallenge_2.ts",
            "start": {
              "line": 53,
              "col": 18,
              "offset": 0
            },
            "end": {
              "line": 53,
              "col": 23,
              "offset": 5
            }
          },
          {
            "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/restfulXssChallenge_2.ts",
            "start": {
              "line": 57,
              "col": 3,
              "offset": 0
            },
            "end": {
              "line": 57,
              "col": 56,
              "offset": 53
            }
          },
          {
            "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/restfulXssChallenge_2.ts",
            "start": {
              "line": 63,
              "col": 3,
              "offset": 0
            },
            "end": {
              "line": 63,
              "col": 4,
              "offset": 1
            }
          }
        ]
      ],
      "message": "Syntax error at line /var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/restfulXssChallenge_2.ts:47:\n `: any[]` was unexpected",
      "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/restfulXssChallenge_2.ts",
      "spans": [
        {
          "file": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/restfulXssChallenge_2.ts",
          "start": {
            "line": 47,
            "col": 38,
            "offset": 0
          },
          "end": {
            "line": 47,
            "col": 45,
            "offset": 7
          }
        },
        {
          "file": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/restfulXssChallenge_2.ts",
          "start": {
            "line": 53,
            "col": 18,
            "offset": 0
          },
          "end": {
            "line": 53,
            "col": 23,
            "offset": 5
          }
        },
        {
          "file": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/restfulXssChallenge_2.ts",
          "start": {
            "line": 57,
            "col": 3,
            "offset": 0
          },
          "end": {
            "line": 57,
            "col": 56,
            "offset": 53
          }
        },
        {
          "file": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/restfulXssChallenge_2.ts",
          "start": {
            "line": 63,
            "col": 3,
            "offset": 0
          },
          "end": {
            "line": 63,
            "col": 4,
            "offset": 1
          }
        }
      ]
    },
    {
      "code": 3,
      "level": "warn",
      "type": [
        "PartialParsing",
        [
          {
            "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/restfulXssChallenge_3.ts",
            "start": {
              "line": 46,
              "col": 37,
              "offset": 0
            },
            "end": {
              "line": 46,
              "col": 44,
              "offset": 7
            }
          }
        ]
      ],
      "message": "Syntax error at line /var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/restfulXssChallenge_3.ts:46:\n `: any[]` was unexpected",
      "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/restfulXssChallenge_3.ts",
      "spans": [
        {
          "file": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/restfulXssChallenge_3.ts",
          "start": {
            "line": 46,
            "col": 37,
            "offset": 0
          },
          "end": {
            "line": 46,
            "col": 44,
            "offset": 7
          }
        }
      ]
    },
    {
      "code": 3,
      "level": "warn",
      "type": [
        "PartialParsing",
        [
          {
            "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/restfulXssChallenge_4.ts",
            "start": {
              "line": 47,
              "col": 37,
              "offset": 0
            },
            "end": {
              "line": 47,
              "col": 44,
              "offset": 7
            }
          },
          {
            "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/restfulXssChallenge_4.ts",
            "start": {
              "line": 53,
              "col": 18,
              "offset": 0
            },
            "end": {
              "line": 53,
              "col": 23,
              "offset": 5
            }
          },
          {
            "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/restfulXssChallenge_4.ts",
            "start": {
              "line": 57,
              "col": 3,
              "offset": 0
            },
            "end": {
              "line": 57,
              "col": 56,
              "offset": 53
            }
          },
          {
            "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/restfulXssChallenge_4.ts",
            "start": {
              "line": 63,
              "col": 3,
              "offset": 0
            },
            "end": {
              "line": 63,
              "col": 4,
              "offset": 1
            }
          }
        ]
      ],
      "message": "Syntax error at line /var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/restfulXssChallenge_4.ts:47:\n `: any[]` was unexpected",
      "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/restfulXssChallenge_4.ts",
      "spans": [
        {
          "file": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/restfulXssChallenge_4.ts",
          "start": {
            "line": 47,
            "col": 37,
            "offset": 0
          },
          "end": {
            "line": 47,
            "col": 44,
            "offset": 7
          }
        },
        {
          "file": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/restfulXssChallenge_4.ts",
          "start": {
            "line": 53,
            "col": 18,
            "offset": 0
          },
          "end": {
            "line": 53,
            "col": 23,
            "offset": 5
          }
        },
        {
          "file": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/restfulXssChallenge_4.ts",
          "start": {
            "line": 57,
            "col": 3,
            "offset": 0
          },
          "end": {
            "line": 57,
            "col": 56,
            "offset": 53
          }
        },
        {
          "file": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/restfulXssChallenge_4.ts",
          "start": {
            "line": 63,
            "col": 3,
            "offset": 0
          },
          "end": {
            "line": 63,
            "col": 4,
            "offset": 1
          }
        }
      ]
    },
    {
      "code": 3,
      "level": "warn",
      "type": [
        "PartialParsing",
        [
          {
            "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/tokenSaleChallenge_1.ts",
            "start": {
              "line": 18,
              "col": 1,
              "offset": 0
            },
            "end": {
              "line": 18,
              "col": 2,
              "offset": 1
            }
          }
        ]
      ],
      "message": "Syntax error at line /var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/tokenSaleChallenge_1.ts:18:\n `]` was unexpected",
      "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/tokenSaleChallenge_1.ts",
      "spans": [
        {
          "file": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/tokenSaleChallenge_1.ts",
          "start": {
            "line": 18,
            "col": 1,
            "offset": 0
          },
          "end": {
            "line": 18,
            "col": 2,
            "offset": 1
          }
        }
      ]
    },
    {
      "code": 3,
      "level": "warn",
      "type": [
        "PartialParsing",
        [
          {
            "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/tokenSaleChallenge_2.ts",
            "start": {
              "line": 19,
              "col": 1,
              "offset": 0
            },
            "end": {
              "line": 19,
              "col": 2,
              "offset": 1
            }
          }
        ]
      ],
      "message": "Syntax error at line /var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/tokenSaleChallenge_2.ts:19:\n `]` was unexpected",
      "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/tokenSaleChallenge_2.ts",
      "spans": [
        {
          "file": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/tokenSaleChallenge_2.ts",
          "start": {
            "line": 19,
            "col": 1,
            "offset": 0
          },
          "end": {
            "line": 19,
            "col": 2,
            "offset": 1
          }
        }
      ]
    },
    {
      "code": 3,
      "level": "warn",
      "type": [
        "PartialParsing",
        [
          {
            "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/tokenSaleChallenge_3_correct.ts",
            "start": {
              "line": 14,
              "col": 1,
              "offset": 0
            },
            "end": {
              "line": 14,
              "col": 2,
              "offset": 1
            }
          }
        ]
      ],
      "message": "Syntax error at line /var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/tokenSaleChallenge_3_correct.ts:14:\n `]` was unexpected",
      "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/tokenSaleChallenge_3_correct.ts",
      "spans": [
        {
          "file": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/tokenSaleChallenge_3_correct.ts",
          "start": {
            "line": 14,
            "col": 1,
            "offset": 0
          },
          "end": {
            "line": 14,
            "col": 2,
            "offset": 1
          }
        }
      ]
    },
    {
      "code": 3,
      "level": "warn",
      "type": [
        "PartialParsing",
        [
          {
            "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/deluxe-user/deluxe-user.component.html",
            "start": {
              "line": 6,
              "col": 1,
              "offset": 0
            },
            "end": {
              "line": 6,
              "col": 14,
              "offset": 13
            }
          },
          {
            "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/deluxe-user/deluxe-user.component.html",
            "start": {
              "line": 10,
              "col": 1,
              "offset": 0
            },
            "end": {
              "line": 10,
              "col": 2,
              "offset": 1
            }
          }
        ]
      ],
      "message": "Syntax error at line /var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/deluxe-user/deluxe-user.component.html:6:\n `@if (error) {` was unexpected",
      "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/deluxe-user/deluxe-user.component.html",
      "spans": [
        {
          "file": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/deluxe-user/deluxe-user.component.html",
          "start": {
            "line": 6,
            "col": 1,
            "offset": 0
          },
          "end": {
            "line": 6,
            "col": 14,
            "offset": 13
          }
        },
        {
          "file": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/deluxe-user/deluxe-user.component.html",
          "start": {
            "line": 10,
            "col": 1,
            "offset": 0
          },
          "end": {
            "line": 10,
            "col": 2,
            "offset": 1
          }
        }
      ]
    },
    {
      "code": 3,
      "level": "warn",
      "type": [
        "PartialParsing",
        [
          {
            "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/order-completion/order-completion.component.html",
            "start": {
              "line": 15,
              "col": 41,
              "offset": 0
            },
            "end": {
              "line": 15,
              "col": 77,
              "offset": 36
            }
          }
        ]
      ],
      "message": "Syntax error at line /var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/order-completion/order-completion.component.html:15:\n `&& orderDetails.eta !== undefined) {` was unexpected",
      "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/order-completion/order-completion.component.html",
      "spans": [
        {
          "file": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/order-completion/order-completion.component.html",
          "start": {
            "line": 15,
            "col": 41,
            "offset": 0
          },
          "end": {
            "line": 15,
            "col": 77,
            "offset": 36
          }
        }
      ]
    },
    {
      "code": 3,
      "level": "warn",
      "type": [
        "PartialParsing",
        [
          {
            "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/payment/payment.component.html",
            "start": {
              "line": 42,
              "col": 31,
              "offset": 0
            },
            "end": {
              "line": 42,
              "col": 57,
              "offset": 26
            }
          },
          {
            "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/payment/payment.component.html",
            "start": {
              "line": 47,
              "col": 24,
              "offset": 0
            },
            "end": {
              "line": 47,
              "col": 50,
              "offset": 26
            }
          },
          {
            "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/payment/payment.component.html",
            "start": {
              "line": 58,
              "col": 36,
              "offset": 0
            },
            "end": {
              "line": 58,
              "col": 108,
              "offset": 72
            }
          },
          {
            "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/payment/payment.component.html",
            "start": {
              "line": 160,
              "col": 32,
              "offset": 0
            },
            "end": {
              "line": 160,
              "col": 55,
              "offset": 23
            }
          }
        ]
      ],
      "message": "Syntax error at line /var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/payment/payment.component.html:42:\n `&& !couponControl.dirty) {` was unexpected",
      "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/payment/payment.component.html",
      "spans": [
        {
          "file": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/payment/payment.component.html",
          "start": {
            "line": 42,
            "col": 31,
            "offset": 0
          },
          "end": {
            "line": 42,
            "col": 57,
            "offset": 26
          }
        },
        {
          "file": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/payment/payment.component.html",
          "start": {
            "line": 47,
            "col": 24,
            "offset": 0
          },
          "end": {
            "line": 47,
            "col": 50,
            "offset": 26
          }
        },
        {
          "file": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/payment/payment.component.html",
          "start": {
            "line": 58,
            "col": 36,
            "offset": 0
          },
          "end": {
            "line": 58,
            "col": 108,
            "offset": 72
          }
        },
        {
          "file": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/payment/payment.component.html",
          "start": {
            "line": 160,
            "col": 32,
            "offset": 0
          },
          "end": {
            "line": 160,
            "col": 55,
            "offset": 23
          }
        }
      ]
    },
    {
      "code": 3,
      "level": "warn",
      "type": [
        "PartialParsing",
        [
          {
            "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/photo-wall/photo-wall.component.html",
            "start": {
              "line": 62,
              "col": 40,
              "offset": 0
            },
            "end": {
              "line": 62,
              "col": 85,
              "offset": 45
            }
          }
        ]
      ],
      "message": "Syntax error at line /var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/photo-wall/photo-wall.component.html:62:\n `&& imagePreview && form.get('image').valid) {` was unexpected",
      "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/photo-wall/photo-wall.component.html",
      "spans": [
        {
          "file": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/photo-wall/photo-wall.component.html",
          "start": {
            "line": 62,
            "col": 40,
            "offset": 0
          },
          "end": {
            "line": 62,
            "col": 85,
            "offset": 45
          }
        }
      ]
    },
    {
      "code": 3,
      "level": "warn",
      "type": [
        "PartialParsing",
        [
          {
            "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/privacy-policy/privacy-policy.component.html",
            "start": {
              "line": 58,
              "col": 25,
              "offset": 0
            },
            "end": {
              "line": 58,
              "col": 39,
              "offset": 14
            }
          }
        ]
      ],
      "message": "Syntax error at line /var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/privacy-policy/privacy-policy.component.html:58:\n `& Cookies Data` was unexpected",
      "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/privacy-policy/privacy-policy.component.html",
      "spans": [
        {
          "file": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/privacy-policy/privacy-policy.component.html",
          "start": {
            "line": 58,
            "col": 25,
            "offset": 0
          },
          "end": {
            "line": 58,
            "col": 39,
            "offset": 14
          }
        }
      ]
    },
    {
      "code": 3,
      "level": "warn",
      "type": [
        "PartialParsing",
        [
          {
            "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/score-board/components/challenge-card/challenge-card.component.html",
            "start": {
              "line": 20,
              "col": 41,
              "offset": 0
            },
            "end": {
              "line": 20,
              "col": 85,
              "offset": 44
            }
          },
          {
            "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/score-board/components/challenge-card/challenge-card.component.html",
            "start": {
              "line": 37,
              "col": 82,
              "offset": 0
            },
            "end": {
              "line": 37,
              "col": 116,
              "offset": 34
            }
          },
          {
            "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/score-board/components/challenge-card/challenge-card.component.html",
            "start": {
              "line": 57,
              "col": 34,
              "offset": 0
            },
            "end": {
              "line": 57,
              "col": 56,
              "offset": 22
            }
          },
          {
            "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/score-board/components/challenge-card/challenge-card.component.html",
            "start": {
              "line": 70,
              "col": 27,
              "offset": 0
            },
            "end": {
              "line": 70,
              "col": 86,
              "offset": 59
            }
          },
          {
            "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/score-board/components/challenge-card/challenge-card.component.html",
            "start": {
              "line": 81,
              "col": 63,
              "offset": 0
            },
            "end": {
              "line": 81,
              "col": 100,
              "offset": 37
            }
          },
          {
            "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/score-board/components/challenge-card/challenge-card.component.html",
            "start": {
              "line": 91,
              "col": 35,
              "offset": 0
            },
            "end": {
              "line": 91,
              "col": 41,
              "offset": 6
            }
          }
        ]
      ],
      "message": "Syntax error at line /var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/score-board/components/challenge-card/challenge-card.component.html:20:\n `&& challenge.disabledEnv !== 'safetyMode') {` was unexpected",
      "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/score-board/components/challenge-card/challenge-card.component.html",
      "spans": [
        {
          "file": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/score-board/components/challenge-card/challenge-card.component.html",
          "start": {
            "line": 20,
            "col": 41,
            "offset": 0
          },
          "end": {
            "line": 20,
            "col": 85,
            "offset": 44
          }
        },
        {
          "file": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/score-board/components/challenge-card/challenge-card.component.html",
          "start": {
            "line": 37,
            "col": 82,
            "offset": 0
          },
          "end": {
            "line": 37,
            "col": 116,
            "offset": 34
          }
        },
        {
          "file": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/score-board/components/challenge-card/challenge-card.component.html",
          "start": {
            "line": 57,
            "col": 34,
            "offset": 0
          },
          "end": {
            "line": 57,
            "col": 56,
            "offset": 22
          }
        },
        {
          "file": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/score-board/components/challenge-card/challenge-card.component.html",
          "start": {
            "line": 70,
            "col": 27,
            "offset": 0
          },
          "end": {
            "line": 70,
            "col": 86,
            "offset": 59
          }
        },
        {
          "file": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/score-board/components/challenge-card/challenge-card.component.html",
          "start": {
            "line": 81,
            "col": 63,
            "offset": 0
          },
          "end": {
            "line": 81,
            "col": 100,
            "offset": 37
          }
        },
        {
          "file": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/score-board/components/challenge-card/challenge-card.component.html",
          "start": {
            "line": 91,
            "col": 35,
            "offset": 0
          },
          "end": {
            "line": 91,
            "col": 41,
            "offset": 6
          }
        }
      ]
    },
    {
      "code": 3,
      "level": "warn",
      "type": [
        "PartialParsing",
        [
          {
            "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/sidenav/sidenav.component.html",
            "start": {
              "line": 42,
              "col": 23,
              "offset": 0
            },
            "end": {
              "line": 42,
              "col": 43,
              "offset": 20
            }
          },
          {
            "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/sidenav/sidenav.component.html",
            "start": {
              "line": 279,
              "col": 27,
              "offset": 0
            },
            "end": {
              "line": 279,
              "col": 56,
              "offset": 29
            }
          }
        ]
      ],
      "message": "Syntax error at line /var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/sidenav/sidenav.component.html:42:\n `&& isAccounting()) {` was unexpected",
      "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/sidenav/sidenav.component.html",
      "spans": [
        {
          "file": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/sidenav/sidenav.component.html",
          "start": {
            "line": 42,
            "col": 23,
            "offset": 0
          },
          "end": {
            "line": 42,
            "col": 43,
            "offset": 20
          }
        },
        {
          "file": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/sidenav/sidenav.component.html",
          "start": {
            "line": 279,
            "col": 27,
            "offset": 0
          },
          "end": {
            "line": 279,
            "col": 56,
            "offset": 29
          }
        }
      ]
    },
    {
      "code": 3,
      "level": "warn",
      "type": [
        "PartialParsing",
        [
          {
            "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/wallet/wallet.component.html",
            "start": {
              "line": 24,
              "col": 35,
              "offset": 0
            },
            "end": {
              "line": 24,
              "col": 71,
              "offset": 36
            }
          },
          {
            "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/wallet/wallet.component.html",
            "start": {
              "line": 29,
              "col": 35,
              "offset": 0
            },
            "end": {
              "line": 29,
              "col": 97,
              "offset": 62
            }
          }
        ]
      ],
      "message": "Syntax error at line /var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/wallet/wallet.component.html:24:\n `&& balanceControl.errors.required) {` was unexpected",
      "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/wallet/wallet.component.html",
      "spans": [
        {
          "file": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/wallet/wallet.component.html",
          "start": {
            "line": 24,
            "col": 35,
            "offset": 0
          },
          "end": {
            "line": 24,
            "col": 71,
            "offset": 36
          }
        },
        {
          "file": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/wallet/wallet.component.html",
          "start": {
            "line": 29,
            "col": 35,
            "offset": 0
          },
          "end": {
            "line": 29,
            "col": 97,
            "offset": 62
          }
        }
      ]
    }
  ],
  "paths": {
    "scanned": [
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/.claude/CLAUDE.md",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/.codeclimate.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/.codeium/instructions.md",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/.continue/instructions.md",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/.cursor/rules",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/.dependabot/config.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/.devcontainer.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/.dockerignore",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/.eslintrc.js",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/.github/FUNDING.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/.github/ISSUE_TEMPLATE/bug-report.md",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/.github/ISSUE_TEMPLATE/challenge-idea.md",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/.github/ISSUE_TEMPLATE/config.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/.github/ISSUE_TEMPLATE/feature-request.md",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/.github/PULL_REQUEST_TEMPLATE.md",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/.github/copilot-instructions.md",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/.github/workflows/ci.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/.github/workflows/codeql-analysis.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/.github/workflows/frontend-bundle-analysis.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/.github/workflows/lint-fixer.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/.github/workflows/lock.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/.github/workflows/pr-compliance.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/.github/workflows/rebase.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/.github/workflows/release.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/.github/workflows/stale.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/.github/workflows/update-challenges-ebook.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/.github/workflows/update-challenges-www-legacy.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/.github/workflows/update-challenges-www.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/.github/workflows/update-news-www-legacy.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/.github/workflows/update-news-www.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/.github/workflows/zap_scan.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/.gitignore",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/.gitlab/auto-deploy-values.yaml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/.gitlab-ci.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/.gitpod.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/.junie/skills/add-reference/SKILL.md",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/.junie/skills/add-reference/types/award.md",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/.junie/skills/add-reference/types/blog.md",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/.junie/skills/add-reference/types/conference.md",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/.junie/skills/add-reference/types/gsoc.md",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/.junie/skills/add-reference/types/lecture.md",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/.junie/skills/add-reference/types/podcast.md",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/.junie/skills/add-reference/types/summit.md",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/.junie/skills/add-reference/types/tools.md",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/.junie/skills/add-solution/SKILL.md",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/.junie/skills/add-solution/types/tool.md",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/.junie/skills/add-solution/types/video.md",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/.junie/skills/add-solution/types/walkthrough.md",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/.junie/skills/verify-challenge/SKILL.md",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/.junie/skills/verify-challenge/checklists/challenge-checklist.md",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/.mailmap",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/.npmrc",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/.well-known/csaf/2017/juice-shop-sa-20200513-express-jwt.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/.well-known/csaf/2017/juice-shop-sa-20200513-express-jwt.json.asc",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/.well-known/csaf/2017/juice-shop-sa-20200513-express-jwt.json.sha512",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/.well-known/csaf/2021/juice-shop-sa-20211014-proto.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/.well-known/csaf/2021/juice-shop-sa-20211014-proto.json.asc",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/.well-known/csaf/2021/juice-shop-sa-20211014-proto.json.sha512",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/.well-known/csaf/2024/juice-shop-sa-disclaimer.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/.well-known/csaf/2024/juice-shop-sa-disclaimer.json.asc",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/.well-known/csaf/2024/juice-shop-sa-disclaimer.json.sha512",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/.well-known/csaf/changes.csv",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/.well-known/csaf/index.txt",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/.well-known/csaf/provider-metadata.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/.well-known/security.txt",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/.zap/rules.tsv",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/AGENTS.md",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/CODE_OF_CONDUCT.md",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/CONTRIBUTING.md",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/Dockerfile",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/Gruntfile.js",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/HALL_OF_FAME.md",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/LICENSE",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/README.md",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/REFERENCES.md",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/SECURITY.md",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/SOLUTIONS.md",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/app.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/app.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/config/7ms.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/config/addo.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/config/bodgeit.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/config/ctf.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/config/default.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/config/defcon33.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/config/fbctf.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/config/juicebox.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/config/mozilla.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/config/oss.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/config/quiet.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/config/test.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/config/tutorial.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/config/unsafe.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/config.schema.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/crowdin.yaml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/ctf.key",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/cypress.config.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/chatbot/.gitkeep",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/datacache.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/datacreator.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/mongodb.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/botDefaultTrainingData.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/challenges.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/.editorconfig",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/accessLogDisclosureChallenge.info.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/accessLogDisclosureChallenge_1_correct.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/accessLogDisclosureChallenge_2.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/accessLogDisclosureChallenge_3.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/accessLogDisclosureChallenge_4.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/adminSectionChallenge.info.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/adminSectionChallenge_1_correct.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/adminSectionChallenge_2.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/adminSectionChallenge_3.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/adminSectionChallenge_4.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/changeProductChallenge.info.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/changeProductChallenge_1.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/changeProductChallenge_2.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/changeProductChallenge_3_correct.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/changeProductChallenge_4.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/dbSchemaChallenge.info.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/dbSchemaChallenge_1.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/dbSchemaChallenge_2_correct.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/dbSchemaChallenge_3.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/directoryListingChallenge.info.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/directoryListingChallenge_1_correct.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/directoryListingChallenge_2.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/directoryListingChallenge_3.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/directoryListingChallenge_4.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/exposedMetricsChallenge.info.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/exposedMetricsChallenge_1.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/exposedMetricsChallenge_2.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/exposedMetricsChallenge_3_correct.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/forgedReviewChallenge.info.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/forgedReviewChallenge_1.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/forgedReviewChallenge_2_correct.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/forgedReviewChallenge_3.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/localXssChallenge.info.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/localXssChallenge_1.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/localXssChallenge_2_correct.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/localXssChallenge_3.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/localXssChallenge_4.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/loginAdminChallenge.info.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/loginAdminChallenge_1.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/loginAdminChallenge_2.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/loginAdminChallenge_3.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/loginAdminChallenge_4_correct.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/loginBenderChallenge.info.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/loginBenderChallenge_1.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/loginBenderChallenge_2_correct.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/loginBenderChallenge_3.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/loginBenderChallenge_4.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/loginJimChallenge.info.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/loginJimChallenge_1_correct.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/loginJimChallenge_2.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/loginJimChallenge_3.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/loginJimChallenge_4.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/nftMintChallenge.info.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/nftMintChallenge_1.sol",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/nftMintChallenge_2.sol",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/nftMintChallenge_3.sol",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/nftMintChallenge_4_correct.sol",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/nftUnlockChallenge.info.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/nftUnlockChallenge_1.sol",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/nftUnlockChallenge_2_correct.sol",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/nftUnlockChallenge_3.sol",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/nftUnlockChallenge_4.sol",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/noSqlReviewsChallenge.info.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/noSqlReviewsChallenge_1.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/noSqlReviewsChallenge_2.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/noSqlReviewsChallenge_3_correct.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/redirectChallenge.info.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/redirectChallenge_1.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/redirectChallenge_2.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/redirectChallenge_3.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/redirectChallenge_4_correct.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/redirectCryptoCurrencyChallenge.info.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/redirectCryptoCurrencyChallenge_1.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/redirectCryptoCurrencyChallenge_2.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/redirectCryptoCurrencyChallenge_3_correct.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/redirectCryptoCurrencyChallenge_4.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/registerAdminChallenge.info.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/registerAdminChallenge_1.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/registerAdminChallenge_2.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/registerAdminChallenge_3_correct.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/registerAdminChallenge_4.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/resetPasswordBenderChallenge.info.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/resetPasswordBenderChallenge_1.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/resetPasswordBenderChallenge_2_correct.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/resetPasswordBenderChallenge_3.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/resetPasswordBjoernChallenge.info.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/resetPasswordBjoernChallenge_1_correct.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/resetPasswordBjoernChallenge_2.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/resetPasswordBjoernChallenge_3.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/resetPasswordBjoernOwaspChallenge.info.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/resetPasswordBjoernOwaspChallenge_1.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/resetPasswordBjoernOwaspChallenge_2_correct.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/resetPasswordBjoernOwaspChallenge_3.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/resetPasswordJimChallenge.info.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/resetPasswordJimChallenge_1.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/resetPasswordJimChallenge_2.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/resetPasswordJimChallenge_3_correct.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/resetPasswordMortyChallenge.info.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/resetPasswordMortyChallenge_1.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/resetPasswordMortyChallenge_2.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/resetPasswordMortyChallenge_3.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/resetPasswordMortyChallenge_4_correct.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/resetPasswordUvoginChallenge.info.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/resetPasswordUvoginChallenge_1.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/resetPasswordUvoginChallenge_2.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/resetPasswordUvoginChallenge_3_correct.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/restfulXssChallenge.info.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/restfulXssChallenge_1_correct.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/restfulXssChallenge_2.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/restfulXssChallenge_3.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/restfulXssChallenge_4.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/scoreBoardChallenge.info.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/scoreBoardChallenge_1_correct.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/scoreBoardChallenge_2.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/scoreBoardChallenge_3.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/tokenSaleChallenge.info.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/tokenSaleChallenge_1.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/tokenSaleChallenge_2.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/tokenSaleChallenge_3_correct.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/unionSqlInjectionChallenge.info.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/unionSqlInjectionChallenge_1.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/unionSqlInjectionChallenge_2_correct.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/unionSqlInjectionChallenge_3.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/weakPasswordChallenge.info.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/weakPasswordChallenge_1_correct.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/weakPasswordChallenge_2.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/weakPasswordChallenge_3.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/weakPasswordChallenge_4.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/web3SandboxChallenge.info.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/web3SandboxChallenge_1_correct.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/web3SandboxChallenge_2.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/web3SandboxChallenge_3.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/web3WalletChallenge.info.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/web3WalletChallenge_1.sol",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/web3WalletChallenge_2.sol",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/web3WalletChallenge_3_correct.sol",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/web3WalletChallenge_4.sol",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/xssBonusChallenge.info.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/xssBonusChallenge_1_correct.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/xssBonusChallenge_2.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/xssBonusChallenge_3.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/codefixes/xssBonusChallenge_4.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/contractABIs.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/deliveries.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/i18n/ar_SA.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/i18n/az_AZ.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/i18n/bg_BG.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/i18n/bn_BD.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/i18n/ca_ES.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/i18n/cs_CZ.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/i18n/da_DK.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/i18n/de_CH.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/i18n/de_DE.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/i18n/el_GR.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/i18n/en.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/i18n/es_ES.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/i18n/et_EE.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/i18n/fa_IR.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/i18n/fi_FI.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/i18n/fr_FR.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/i18n/ga_IE.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/i18n/he_IL.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/i18n/hi_IN.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/i18n/hu_HU.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/i18n/id_ID.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/i18n/it_IT.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/i18n/ja_JP.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/i18n/ka_GE.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/i18n/ko_KR.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/i18n/lv_LV.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/i18n/my_MM.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/i18n/nl_NL.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/i18n/no_NO.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/i18n/pl_PL.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/i18n/pt_BR.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/i18n/pt_PT.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/i18n/ro_RO.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/i18n/ru_RU.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/i18n/si_LK.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/i18n/sv_SE.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/i18n/th_TH.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/i18n/tlh_AA.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/i18n/tr_TR.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/i18n/uk_UA.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/i18n/zh_CN.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/i18n/zh_HK.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/i18n/zh_TW.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/legal.md",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/locales.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/owasp_promo.vtt",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/securityQuestions.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/users.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/web3-snippets/BEEToken.sol",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/web3-snippets/BeeFaucet.sol",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/web3-snippets/ETHWalletBank.sol",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/web3-snippets/HoneyPotNFT.sol",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/static/web3-snippets/JuiceShopSBT.sol",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/staticData.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/data/types.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/docker-compose.test.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/encryptionkeys/jwt.pub",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/encryptionkeys/premium.key",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/.browserslistrc",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/.editorconfig",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/.gitignore",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/.npmrc",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/angular.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/eslint.config.js",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/package.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/Models/backup.model.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/Models/challenge.model.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/Models/deliveryMethod.model.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/Models/hint.model.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/Models/product.model.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/Models/review.model.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/Models/securityQuestion.model.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/Services/address.service.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/Services/address.service.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/Services/administration.service.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/Services/administration.service.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/Services/basket.service.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/Services/basket.service.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/Services/captcha.service.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/Services/captcha.service.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/Services/challenge.service.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/Services/challenge.service.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/Services/chatbot.service.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/Services/chatbot.service.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/Services/code-fixes.service.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/Services/code-fixes.service.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/Services/code-snippet.service.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/Services/code-snippet.service.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/Services/complaint.service.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/Services/complaint.service.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/Services/configuration.service.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/Services/configuration.service.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/Services/country-mapping.service.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/Services/country-mapping.service.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/Services/ctf-system-wide-notification.service.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/Services/data-subject.service.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/Services/data-subject.service.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/Services/delivery.service.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/Services/delivery.service.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/Services/feedback.service.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/Services/feedback.service.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/Services/form-submit.service.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/Services/form-submit.service.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/Services/hint.service.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/Services/hints.service.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/Services/image-captcha.service.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/Services/image-captcha.service.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/Services/keys.service.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/Services/languages.service.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/Services/languages.service.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/Services/local-backup.service.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/Services/local-backup.service.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/Services/order-history.service.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/Services/order-history.service.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/Services/payment.service.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/Services/payment.service.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/Services/photo-wall.service.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/Services/photo-wall.service.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/Services/product-review.service.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/Services/product-review.service.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/Services/product.service.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/Services/product.service.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/Services/quantity.service.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/Services/quantity.service.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/Services/recycle.service.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/Services/recycle.service.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/Services/request.interceptor.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/Services/security-answer.service.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/Services/security-answer.service.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/Services/security-question.service.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/Services/security-question.service.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/Services/snack-bar-helper.service.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/Services/snack-bar-helper.service.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/Services/socket-io.service.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/Services/socket-io.service.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/Services/track-order.service.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/Services/track-order.service.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/Services/two-factor-auth-service.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/Services/two-factor-auth-service.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/Services/user.service.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/Services/user.service.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/Services/vuln-lines.service.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/Services/vuln-lines.service.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/Services/wallet.service.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/Services/wallet.service.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/Services/window-ref.service.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/Services/window-ref.service.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/about/about.component.html",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/about/about.component.scss",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/about/about.component.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/about/about.component.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/accounting/accounting.component.html",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/accounting/accounting.component.scss",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/accounting/accounting.component.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/accounting/accounting.component.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/address/address.component.html",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/address/address.component.scss",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/address/address.component.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/address/address.component.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/address-create/address-create.component.html",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/address-create/address-create.component.scss",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/address-create/address-create.component.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/address-create/address-create.component.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/address-select/address-select.component.html",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/address-select/address-select.component.scss",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/address-select/address-select.component.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/address-select/address-select.component.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/administration/administration.component.html",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/administration/administration.component.scss",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/administration/administration.component.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/administration/administration.component.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/app.component.html",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/app.component.scss",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/app.component.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/app.component.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/app.guard.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/app.guard.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/app.routing.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/basket/basket.component.html",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/basket/basket.component.scss",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/basket/basket.component.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/basket/basket.component.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/challenge-solved-notification/challenge-solved-notification.component.html",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/challenge-solved-notification/challenge-solved-notification.component.scss",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/challenge-solved-notification/challenge-solved-notification.component.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/challenge-solved-notification/challenge-solved-notification.component.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/challenge-status-badge/challenge-status-badge.component.html",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/challenge-status-badge/challenge-status-badge.component.scss",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/challenge-status-badge/challenge-status-badge.component.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/challenge-status-badge/challenge-status-badge.component.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/change-password/change-password.component.html",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/change-password/change-password.component.scss",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/change-password/change-password.component.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/change-password/change-password.component.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/chatbot/chatbot.component.html",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/chatbot/chatbot.component.scss",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/chatbot/chatbot.component.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/chatbot/chatbot.component.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/code-area/code-area.component.html",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/code-area/code-area.component.scss",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/code-area/code-area.component.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/code-area/code-area.component.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/code-fixes/code-fixes.component.html",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/code-fixes/code-fixes.component.scss",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/code-fixes/code-fixes.component.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/code-fixes/code-fixes.component.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/code-snippet/code-snippet.component.html",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/code-snippet/code-snippet.component.scss",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/code-snippet/code-snippet.component.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/code-snippet/code-snippet.component.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/complaint/complaint.component.html",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/complaint/complaint.component.scss",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/complaint/complaint.component.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/complaint/complaint.component.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/contact/contact.component.html",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/contact/contact.component.scss",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/contact/contact.component.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/contact/contact.component.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/ctf-system-wide-notification/ctf-system-wide-notification.component.html",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/ctf-system-wide-notification/ctf-system-wide-notification.component.scss",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/ctf-system-wide-notification/ctf-system-wide-notification.component.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/ctf-system-wide-notification/ctf-system-wide-notification.component.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/data-export/data-export.component.html",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/data-export/data-export.component.scss",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/data-export/data-export.component.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/data-export/data-export.component.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/delivery-method/delivery-method.component.html",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/delivery-method/delivery-method.component.scss",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/delivery-method/delivery-method.component.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/delivery-method/delivery-method.component.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/deluxe-user/deluxe-user.component.html",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/deluxe-user/deluxe-user.component.scss",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/deluxe-user/deluxe-user.component.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/deluxe-user/deluxe-user.component.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/error-page/error-page.component.html",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/error-page/error-page.component.scss",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/error-page/error-page.component.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/error-page/error-page.component.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/faucet/faucet.component.html",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/faucet/faucet.component.scss",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/faucet/faucet.component.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/faucet/faucet.module.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/feedback-details/feedback-details.component.html",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/feedback-details/feedback-details.component.scss",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/feedback-details/feedback-details.component.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/feedback-details/feedback-details.component.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/forgot-password/forgot-password.component.html",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/forgot-password/forgot-password.component.scss",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/forgot-password/forgot-password.component.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/forgot-password/forgot-password.component.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/last-login-ip/last-login-ip.component.html",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/last-login-ip/last-login-ip.component.scss",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/last-login-ip/last-login-ip.component.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/last-login-ip/last-login-ip.component.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/login/login.component.html",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/login/login.component.scss",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/login/login.component.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/login/login.component.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/mat-search-bar/abstract-value-accessor.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/mat-search-bar/mat-search-bar.component.html",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/mat-search-bar/mat-search-bar.component.scss",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/mat-search-bar/mat-search-bar.component.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/mat-search-bar/mat-search-bar.component.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/navbar/navbar.component.html",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/navbar/navbar.component.scss",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/navbar/navbar.component.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/navbar/navbar.component.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/nft-unlock/nft-unlock.component.html",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/nft-unlock/nft-unlock.component.scss",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/nft-unlock/nft-unlock.component.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/nft-unlock/nft-unlock.component.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/oauth/oauth.component.html",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/oauth/oauth.component.scss",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/oauth/oauth.component.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/oauth/oauth.component.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/order-completion/order-completion.component.html",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/order-completion/order-completion.component.scss",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/order-completion/order-completion.component.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/order-completion/order-completion.component.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/order-history/order-history.component.html",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/order-history/order-history.component.scss",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/order-history/order-history.component.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/order-history/order-history.component.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/order-summary/order-summary.component.html",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/order-summary/order-summary.component.scss",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/order-summary/order-summary.component.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/order-summary/order-summary.component.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/password-strength/password-strength.component.html",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/password-strength/password-strength.component.scss",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/password-strength/password-strength.component.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/password-strength/password-strength.component.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/password-strength-info/password-strength-info.component.html",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/password-strength-info/password-strength-info.component.scss",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/password-strength-info/password-strength-info.component.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/password-strength-info/password-strength-info.component.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/payment/payment.component.html",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/payment/payment.component.scss",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/payment/payment.component.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/payment/payment.component.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/payment-method/payment-method.component.html",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/payment-method/payment-method.component.scss",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/payment-method/payment-method.component.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/payment-method/payment-method.component.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/photo-wall/mime-type.validator.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/photo-wall/photo-wall.component.html",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/photo-wall/photo-wall.component.scss",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/photo-wall/photo-wall.component.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/photo-wall/photo-wall.component.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/privacy-policy/privacy-policy.component.html",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/privacy-policy/privacy-policy.component.scss",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/privacy-policy/privacy-policy.component.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/privacy-policy/privacy-policy.component.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/privacy-security/privacy-security.component.html",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/privacy-security/privacy-security.component.scss",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/privacy-security/privacy-security.component.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/privacy-security/privacy-security.component.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/product-details/product-details.component.html",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/product-details/product-details.component.scss",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/product-details/product-details.component.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/product-details/product-details.component.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/product-review-edit/product-review-edit.component.html",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/product-review-edit/product-review-edit.component.scss",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/product-review-edit/product-review-edit.component.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/product-review-edit/product-review-edit.component.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/purchase-basket/purchase-basket.component.html",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/purchase-basket/purchase-basket.component.scss",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/purchase-basket/purchase-basket.component.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/purchase-basket/purchase-basket.component.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/qr-code/qr-code.component.html",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/qr-code/qr-code.component.scss",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/qr-code/qr-code.component.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/qr-code/qr-code.component.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/recycle/recycle.component.html",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/recycle/recycle.component.scss",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/recycle/recycle.component.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/recycle/recycle.component.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/register/register.component.html",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/register/register.component.scss",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/register/register.component.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/register/register.component.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/roles.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/saved-address/saved-address.component.html",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/saved-address/saved-address.component.scss",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/saved-address/saved-address.component.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/saved-address/saved-address.component.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/saved-payment-methods/saved-payment-methods.component.html",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/saved-payment-methods/saved-payment-methods.component.scss",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/saved-payment-methods/saved-payment-methods.component.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/saved-payment-methods/saved-payment-methods.component.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/score-board/components/challenge-card/challenge-card.component.html",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/score-board/components/challenge-card/challenge-card.component.scss",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/score-board/components/challenge-card/challenge-card.component.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/score-board/components/challenge-card/challenge-card.component.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/score-board/components/challenges-unavailable-warning/challenges-unavailable-warning.component.html",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/score-board/components/challenges-unavailable-warning/challenges-unavailable-warning.component.scss",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/score-board/components/challenges-unavailable-warning/challenges-unavailable-warning.component.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/score-board/components/challenges-unavailable-warning/challenges-unavailable-warning.component.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/score-board/components/coding-challenge-progress-score-card/coding-challenge-progress-score-card.component.html",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/score-board/components/coding-challenge-progress-score-card/coding-challenge-progress-score-card.component.scss",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/score-board/components/coding-challenge-progress-score-card/coding-challenge-progress-score-card.component.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/score-board/components/coding-challenge-progress-score-card/coding-challenge-progress-score-card.component.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/score-board/components/difficulty-overview-score-card/difficulty-overview-score-card.component.html",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/score-board/components/difficulty-overview-score-card/difficulty-overview-score-card.component.scss",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/score-board/components/difficulty-overview-score-card/difficulty-overview-score-card.component.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/score-board/components/difficulty-overview-score-card/difficulty-overview-score-card.component.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/score-board/components/difficulty-stars/difficulty-stars.component.html",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/score-board/components/difficulty-stars/difficulty-stars.component.scss",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/score-board/components/difficulty-stars/difficulty-stars.component.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/score-board/components/filter-settings/components/category-filter/category-filter.component.html",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/score-board/components/filter-settings/components/category-filter/category-filter.component.scss",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/score-board/components/filter-settings/components/category-filter/category-filter.component.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/score-board/components/filter-settings/components/category-filter/category-filter.component.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/score-board/components/filter-settings/components/score-board-additional-settings-dialog/score-board-additional-settings-dialog.component.html",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/score-board/components/filter-settings/components/score-board-additional-settings-dialog/score-board-additional-settings-dialog.component.scss",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/score-board/components/filter-settings/components/score-board-additional-settings-dialog/score-board-additional-settings-dialog.component.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/score-board/components/filter-settings/components/score-board-additional-settings-dialog/score-board-additional-settings-dialog.component.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/score-board/components/filter-settings/filter-settings.component.html",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/score-board/components/filter-settings/filter-settings.component.scss",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/score-board/components/filter-settings/filter-settings.component.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/score-board/components/filter-settings/filter-settings.component.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/score-board/components/filter-settings/pipes/difficulty-selection-summary.pipe.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/score-board/components/filter-settings/pipes/difficulty-selection-summary.pipe.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/score-board/components/hacking-challenge-progress-score-card/hacking-challenge-progress-score-card.component.html",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/score-board/components/hacking-challenge-progress-score-card/hacking-challenge-progress-score-card.component.scss",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/score-board/components/hacking-challenge-progress-score-card/hacking-challenge-progress-score-card.component.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/score-board/components/hacking-challenge-progress-score-card/hacking-challenge-progress-score-card.component.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/score-board/components/score-card/score-card.component.html",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/score-board/components/score-card/score-card.component.scss",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/score-board/components/score-card/score-card.component.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/score-board/components/score-card/score-card.component.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/score-board/components/tutorial-mode-warning/tutorial-mode-warning.component.html",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/score-board/components/tutorial-mode-warning/tutorial-mode-warning.component.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/score-board/components/tutorial-mode-warning/tutorial-mode-warning.component.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/score-board/components/warning-card/warning-card.component.html",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/score-board/components/warning-card/warning-card.component.scss",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/score-board/components/warning-card/warning-card.component.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/score-board/filter-settings/FilterSetting.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/score-board/filter-settings/query-params-converters.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/score-board/filter-settings/query-params-coverter.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/score-board/helpers/challenge-filtering.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/score-board/helpers/challenge-filtering.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/score-board/helpers/challenge-sorting.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/score-board/helpers/challenge-sorting.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/score-board/score-board.component.html",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/score-board/score-board.component.scss",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/score-board/score-board.component.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/score-board/score-board.component.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/score-board/types/EnrichedChallenge.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/search-result/search-result.component.html",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/search-result/search-result.component.scss",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/search-result/search-result.component.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/search-result/search-result.component.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/server-started-notification/server-started-notification.component.html",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/server-started-notification/server-started-notification.component.scss",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/server-started-notification/server-started-notification.component.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/server-started-notification/server-started-notification.component.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/sidenav/sidenav.component.html",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/sidenav/sidenav.component.scss",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/sidenav/sidenav.component.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/sidenav/sidenav.component.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/token-sale/token-sale.component.html",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/token-sale/token-sale.component.scss",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/token-sale/token-sale.component.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/token-sale/token-sale.component.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/track-result/track-result.component.html",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/track-result/track-result.component.scss",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/track-result/track-result.component.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/track-result/track-result.component.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/two-factor-auth/two-factor-auth.component.html",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/two-factor-auth/two-factor-auth.component.scss",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/two-factor-auth/two-factor-auth.component.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/two-factor-auth/two-factor-auth.component.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/two-factor-auth-enter/two-factor-auth-enter.component.html",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/two-factor-auth-enter/two-factor-auth-enter.component.scss",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/two-factor-auth-enter/two-factor-auth-enter.component.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/two-factor-auth-enter/two-factor-auth-enter.component.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/user-details/user-details.component.html",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/user-details/user-details.component.scss",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/user-details/user-details.component.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/user-details/user-details.component.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/wallet/wallet.component.html",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/wallet/wallet.component.scss",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/wallet/wallet.component.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/wallet/wallet.component.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/wallet-web3/wallet-web3.component.html",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/wallet-web3/wallet-web3.component.scss",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/wallet-web3/wallet-web3.component.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/wallet-web3/wallet-web3.module.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/web3-sandbox/web3-sandbox.component.html",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/web3-sandbox/web3-sandbox.component.scss",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/web3-sandbox/web3-sandbox.component.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/web3-sandbox/web3-sandbox.module.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/welcome/welcome.component.html",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/welcome/welcome.component.scss",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/welcome/welcome.component.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/welcome/welcome.component.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/welcome-banner/welcome-banner.component.html",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/welcome-banner/welcome-banner.component.scss",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/welcome-banner/welcome-banner.component.spec.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/app/welcome-banner/welcome-banner.component.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/i18n/ar_SA.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/i18n/az_AZ.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/i18n/bg_BG.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/i18n/bn_BD.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/i18n/ca_ES.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/i18n/cs_CZ.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/i18n/da_DK.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/i18n/de_CH.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/i18n/de_DE.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/i18n/el_GR.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/i18n/en.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/i18n/es_ES.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/i18n/et_EE.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/i18n/fa_IR.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/i18n/fi_FI.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/i18n/fr_FR.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/i18n/ga_IE.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/i18n/he_IL.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/i18n/hi_IN.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/i18n/hu_HU.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/i18n/id_ID.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/i18n/it_IT.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/i18n/ja_JP.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/i18n/ka_GE.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/i18n/ko_KR.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/i18n/lv_LV.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/i18n/my_MM.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/i18n/nl_NL.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/i18n/no_NO.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/i18n/pl_PL.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/i18n/pt_BR.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/i18n/pt_PT.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/i18n/ro_RO.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/i18n/ru_RU.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/i18n/si_LK.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/i18n/sv_SE.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/i18n/th_TH.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/i18n/tlh_AA.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/i18n/tr_TR.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/i18n/uk_UA.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/i18n/zh_CN.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/i18n/zh_HK.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/i18n/zh_TW.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/private/CopyShader.js",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/private/EffectComposer.js",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/private/JuiceShop_Wallpaper_1920x1080_VR.jpg",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/private/MaskPass.js",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/private/OrbitControls.js",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/private/RenderPass.js",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/private/ShaderPass.js",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/private/earthspec4k.jpg",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/private/orangemap2k.jpg",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/private/three.js",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/private/threejs-demo.html",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/ContractABIs.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/css/dataErasure.css",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/css/roboto.css",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/css/userProfile.css",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/favicon_ctf.ico",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/favicon_js.ico",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/BeeOwner.png",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/HoneyPot.png",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/JuiceShopCTF_Logo.png",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/JuiceShopCTF_Logo_400px.png",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/JuiceShop_Logo.ai",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/JuiceShop_Logo.png",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/JuiceShop_Logo.svg",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/JuiceShop_Logo_100px.png",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/JuiceShop_Logo_400px.png",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/JuiceShop_Logo_50px.png",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/JuicyBot.png",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/JuicyBot_MedicalMask.png",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/JuicyChatBot.png",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/Welcome_Banner.svg",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/carousel/1.jpg",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/carousel/2.jpg",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/carousel/3.jpg",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/carousel/4.jpg",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/carousel/5.png",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/carousel/6.jpg",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/carousel/7.jpg",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/deluxe/blankBoxes.png",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/juicyEvilWasp.png",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/padding/11px.png",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/padding/19px.png",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/padding/1px.png",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/padding/56px.png",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/padding/81px.png",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/products/3d_keychain.jpg",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/products/JuiceShop.stl",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/products/apple_juice.jpg",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/products/apple_pressings.jpg",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/products/artwork.jpg",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/products/artwork2.jpg",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/products/banana_juice.jpg",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/products/card_alpha.jpg",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/products/carrot_juice.jpeg",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/products/ccg_common.png",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/products/ccg_foil.png",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/products/coaster.jpg",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/products/cover_small.jpg",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/products/eggfruit_juice.jpg",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/products/fan_facemask.jpg",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/products/fan_girlie.jpg",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/products/fan_hoodie.jpg",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/products/fan_mug.jpg",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/products/fan_shirt.jpg",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/products/fruit_press.jpg",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/products/green_smoothie.jpg",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/products/holo_sticker.png",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/products/iron-on.jpg",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/products/juicy_chatbot.jpg",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/products/lego_case.jpg",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/products/lemon_juice.jpg",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/products/magnets.jpg",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/products/melon_bike.jpeg",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/products/no-results.png",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/products/orange_juice.jpg",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/products/permafrost.jpg",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/products/quince.jpg",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/products/raspberry_juice.jpg",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/products/snakes_ladders.jpg",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/products/snakes_ladders_m.jpg",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/products/squareBox1-40x40x40.stl",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/products/sticker.png",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/products/sticker_page.jpg",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/products/sticker_single.jpg",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/products/stickersheet_se.png",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/products/strawberry_juice.jpeg",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/products/tattoo.jpg",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/products/thingie1.jpg",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/products/undefined.png",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/products/user_day_ticket.png",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/products/velcro-patch.jpg",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/products/waspy.png",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/products/woodruff_syrup.jpg",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/uploads/12.png",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/uploads/13.jpg",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/uploads/20.jpg",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/uploads/BeeHaven.png",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/uploads/building-something-literally-bottom-up-1721152342603.jpg",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/uploads/default.svg",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/uploads/defaultAdmin.png",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/uploads/everything-up-and-running!-1721152385146.jpg",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/uploads/favorite-hiking-place.png",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/uploads/magn(et)ificent!-1571814229653.jpg",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/uploads/my-rare-collectors-item!-[\u0332\u0305$\u0332\u0305(\u0332\u0305-\u0361\u00b0-\u035c\u0296-\u0361\u00b0\u0332\u0305)\u0332\u0305$\u0332\u0305]-1572603645543.jpg",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/uploads/putting-in-the-hardware-1721152366854.jpg",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/uploads/sorted-the-pieces,-starting-assembly-process-1721152307290.jpg",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/public/images/uploads/\u14da\u160f\u15e2-#zatschi-#whoneedsfourlegs-1572600969477.jpg",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/confetti/index.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/environments/environment.prod.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/environments/environment.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/hacking-instructor/challenges/adminSection.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/hacking-instructor/challenges/bonusPayload.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/hacking-instructor/challenges/codingChallenges.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/hacking-instructor/challenges/domXss.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/hacking-instructor/challenges/exposedCredentials.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/hacking-instructor/challenges/forgedFeedback.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/hacking-instructor/challenges/loginAdmin.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/hacking-instructor/challenges/loginBender.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/hacking-instructor/challenges/loginJim.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/hacking-instructor/challenges/passwordStrength.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/hacking-instructor/challenges/privacyPolicy.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/hacking-instructor/challenges/reflectedXss.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/hacking-instructor/challenges/scoreBoard.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/hacking-instructor/challenges/viewBasket.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/hacking-instructor/hacking-instructor.scss",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/hacking-instructor/helpers/helpers.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/hacking-instructor/index.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/hacking-instructor/tutorialUnavailable.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/index.html",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/karma.conf.js",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/main.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/styles/_variables.scss",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/styles/theme.scss",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/styles.scss",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/test.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/tsconfig.app.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/tsconfig.spec.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/stylelint-plugin-spacing-fixer.mjs",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/stylelint.config.mjs",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/tsconfig.base.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/tsconfig.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/ftp/acquisitions.md",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/ftp/announcement_encrypted.md",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/ftp/coupons_2013.md.bak",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/ftp/eastere.gg",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/ftp/encrypt.pyc",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/ftp/incident-support.kdbx",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/ftp/package-lock.json.bak",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/ftp/package.json.bak",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/ftp/quarantine/juicy_malware_linux_amd_64.url",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/ftp/quarantine/juicy_malware_linux_arm_64.url",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/ftp/quarantine/juicy_malware_macos_64.url",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/ftp/quarantine/juicy_malware_windows_64.exe.url",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/ftp/suspicious_errors.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/i18n/.gitkeep",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/lib/accuracy.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/lib/antiCheat.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/lib/botUtils.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/lib/challengeUtils.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/lib/codingChallenges.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/lib/config.types.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/lib/insecurity.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/lib/is-docker.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/lib/is-heroku.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/lib/is-windows.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/lib/logger.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/lib/noUpdate.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/lib/startup/cleanupFtpFolder.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/lib/startup/customizeApplication.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/lib/startup/customizeEasterEgg.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/lib/startup/registerWebsocketEvents.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/lib/startup/restoreOverwrittenFilesWithOriginals.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/lib/startup/validateChatBot.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/lib/startup/validateConfig.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/lib/startup/validateDependencies.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/lib/startup/validateDependenciesBasic.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/lib/startup/validatePreconditions.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/lib/utils.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/lib/webhook.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/models/address.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/models/basket.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/models/basketitem.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/models/captcha.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/models/card.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/models/challenge.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/models/complaint.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/models/delivery.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/models/feedback.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/models/hint.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/models/imageCaptcha.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/models/index.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/models/memory.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/models/privacyRequests.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/models/product.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/models/quantity.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/models/recycle.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/models/relations.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/models/securityAnswer.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/models/securityQuestion.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/models/user.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/models/wallet.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/monitoring/grafana-dashboard.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/package.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/routes/2fa.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/routes/address.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/routes/angular.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/routes/appConfiguration.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/routes/appVersion.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/routes/authenticatedUsers.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/routes/b2bOrder.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/routes/basket.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/routes/basketItems.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/routes/captcha.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/routes/changePassword.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/routes/chatbot.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/routes/checkKeys.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/routes/continueCode.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/routes/countryMapping.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/routes/coupon.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/routes/createProductReviews.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/routes/currentUser.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/routes/dataErasure.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/routes/dataExport.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/routes/delivery.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/routes/deluxe.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/routes/easterEgg.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/routes/fileServer.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/routes/fileUpload.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/routes/imageCaptcha.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/routes/keyServer.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/routes/languages.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/routes/likeProductReviews.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/routes/logfileServer.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/routes/login.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/routes/memory.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/routes/metrics.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/routes/nftMint.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/routes/order.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/routes/orderHistory.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/routes/payment.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/routes/premiumReward.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/routes/privacyPolicyProof.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/routes/profileImageFileUpload.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/routes/profileImageUrlUpload.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/routes/quarantineServer.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/routes/recycles.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/routes/redirect.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/routes/repeatNotification.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/routes/resetPassword.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/routes/restoreProgress.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/routes/saveLoginIp.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/routes/search.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/routes/securityQuestion.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/routes/showProductReviews.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/routes/trackOrder.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/routes/updateProductReviews.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/routes/updateUserProfile.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/routes/userProfile.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/routes/verify.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/routes/videoHandler.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/routes/vulnCodeFixes.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/routes/vulnCodeSnippet.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/routes/wallet.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/routes/web3Wallet.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/rsn/cache.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/rsn/rsn-update.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/rsn/rsn-verbose.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/rsn/rsn.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/rsn/rsnUtil.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/screenshots/bundle-analysis.png",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/screenshots/git-stats.png",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/screenshots/screenshot00.png",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/screenshots/screenshot01.png",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/screenshots/screenshot02.png",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/screenshots/screenshot03.png",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/screenshots/screenshot04.png",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/screenshots/screenshot05.png",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/screenshots/screenshot06.png",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/screenshots/screenshot08.png",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/screenshots/screenshot09.png",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/screenshots/screenshot10.png",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/screenshots/screenshot11.png",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/screenshots/screenshot12.png",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/screenshots/screenshot13.png",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/server.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/swagger.yml",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/threat-model.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/tsconfig.json",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/uploads/complaints/.gitkeep",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/vagrant/Vagrantfile",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/vagrant/bootstrap.sh",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/vagrant/default.conf",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/views/dataErasureForm.hbs",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/views/dataErasureResult.hbs",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/views/promotionVideo.pug",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/views/themes/themes.ts",
      "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/views/userProfile.pug"
    ]
  },
  "time": {
    "rules": [],
    "rules_parse_time": 0.7711491584777832,
    "profiling_times": {
      "config_time": 2.688096046447754,
      "core_time": 19.931008100509644,
      "ignores_time": 0.0007779598236083984,
      "total_time": 22.628154754638672
    },
    "parsing_time": {
      "total_time": 0.0,
      "per_file_time": {
        "mean": 0.0,
        "std_dev": 0.0
      },
      "very_slow_stats": {
        "time_ratio": 0.0,
        "count_ratio": 0.0
      },
      "very_slow_files": []
    },
    "scanning_time": {
      "total_time": 41.183130502700806,
      "per_file_time": {
        "mean": 0.014319586405667889,
        "std_dev": 0.10129457489322533
      },
      "very_slow_stats": {
        "time_ratio": 0.4130126031692012,
        "count_ratio": 0.0003477051460361613
      },
      "very_slow_files": [
        {
          "fpath": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/private/three.js",
          "ftime": 17.009151935577393
        }
      ]
    },
    "matching_time": {
      "total_time": 0.0,
      "per_file_and_rule_time": {
        "mean": 0.0,
        "std_dev": 0.0
      },
      "very_slow_stats": {
        "time_ratio": 0.0,
        "count_ratio": 0.0
      },
      "very_slow_rules_on_files": []
    },
    "tainting_time": {
      "total_time": 0.0,
      "per_def_and_rule_time": {
        "mean": 0.0,
        "std_dev": 0.0
      },
      "very_slow_stats": {
        "time_ratio": 0.0,
        "count_ratio": 0.0
      },
      "very_slow_rules_on_defs": []
    },
    "fixpoint_timeouts": [
      {
        "error_type": "Fixpoint timeout",
        "severity": "warn",
        "message": "Fixpoint timeout while performing taint analysis at /var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/private/three.js:1:0 [rules: 7, first: javascript.express.security.injection.raw-html-format.raw-html-format]",
        "location": {
          "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/private/three.js",
          "start": {
            "line": 1,
            "col": 1,
            "offset": 0
          },
          "end": {
            "line": 1,
            "col": 1,
            "offset": 0
          }
        }
      },
      {
        "error_type": "Fixpoint timeout",
        "severity": "warn",
        "message": "Fixpoint timeout while performing taint analysis at /var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/private/three.js:22377:10 [rules: 2, first: javascript.lang.security.audit.unsafe-formatstring.unsafe-formatstring]",
        "location": {
          "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/frontend/src/assets/private/three.js",
          "start": {
            "line": 22377,
            "col": 11,
            "offset": 470984
          },
          "end": {
            "line": 22377,
            "col": 25,
            "offset": 470998
          }
        }
      },
      {
        "error_type": "Fixpoint timeout",
        "severity": "warn",
        "message": "Fixpoint timeout while performing taint analysis at /var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/server.ts:1:0 [rules: 2, first: javascript.express.security.x-frame-options-misconfiguration.x-frame-options-misconfiguration]",
        "location": {
          "path": "/var/folders/gx/x1b0jm6s0c549270j2lz67tw0000gn/T/tmp0p0mmx8f/server.ts",
          "start": {
            "line": 1,
            "col": 1,
            "offset": 0
          },
          "end": {
            "line": 1,
            "col": 1,
            "offset": 0
          }
        }
      }
    ],
    "prefiltering": {
      "project_level_time": 0.0,
      "file_level_time": 0.0,
      "rules_with_project_prefilters_ratio": 0.0,
      "rules_with_file_prefilters_ratio": 0.9659691706235907,
      "rules_selected_ratio": 0.08730115975712054,
      "rules_matched_ratio": 0.08730115975712054
    },
    "targets": [],
    "total_bytes": 0,
    "max_memory_bytes": 3658783552
  },
  "engine_requested": "OSS",
  "skipped_rules": [],
  "profiling_results": []
}
```
