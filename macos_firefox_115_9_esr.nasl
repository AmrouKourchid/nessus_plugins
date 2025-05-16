#%NASL_MIN_LEVEL 80900
## 
# (C) Tenable, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2024-13.
# The text itself is copyright (C) Mozilla Foundation.
##

include('compat.inc');

if (description)
{
  script_id(192239);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/02");

  script_cve_id(
    "CVE-2023-5388",
    "CVE-2024-0743",
    "CVE-2024-2605",
    "CVE-2024-2607",
    "CVE-2024-2608",
    "CVE-2024-2610",
    "CVE-2024-2611",
    "CVE-2024-2612",
    "CVE-2024-2614",
    "CVE-2024-2616"
  );
  script_xref(name:"IAVA", value:"2024-A-0053-S");
  script_xref(name:"IAVA", value:"2024-A-0174-S");
  script_xref(name:"IAVA", value:"2024-A-0245-S");

  script_name(english:"Mozilla Firefox ESR < 115.9");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS or Mac OS X host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox ESR installed on the remote macOS or Mac OS X host is prior to 115.9. It is, therefore, affected
by multiple vulnerabilities as referenced in the mfsa2024-13 advisory.

  - An unchecked return value in TLS handshake code could have caused a potentially exploitable crash.
    (CVE-2024-0743)

  - An attacker could have leveraged the Windows Error Reporter to run arbitrary code on the system escaping
    the sandbox. Note: This issue only affected Windows operating systems. Other operating systems are
    unaffected. (CVE-2024-2605)

  - Return registers were overwritten which could have allowed an attacker to execute arbitrary code. Note:
    This issue only affected Armv7-A systems. Other operating systems are unaffected. (CVE-2024-2607)

  - <code>AppendEncodedAttributeValue(), ExtraSpaceNeededForAttrEncoding()</code> and
    <code>AppendEncodedCharacters()</code> could have experienced integer overflows, causing underallocation
    of an output buffer leading to an out of bounds write. (CVE-2024-2608)

  - To harden ICU against exploitation, the behavior for out-of-memory conditions was changed to crash instead
    of attempt to continue. (CVE-2024-2616)

  - NSS was susceptible to a timing side-channel attack when performing RSA decryption. This attack could
    potentially allow an attacker to recover the private data. (CVE-2023-5388)

  - Using a markup injection an attacker could have stolen nonce values. This could have been used to bypass
    strict content security policies. (CVE-2024-2610)

  - A missing delay on when pointer lock was used could have allowed a malicious page to trick a user into
    granting permissions. (CVE-2024-2611)

  - If an attacker could find a way to trigger a particular code path in <code>SafeRefPtr</code>, it could
    have triggered a crash or potentially be leveraged to achieve code execution. (CVE-2024-2612)

  - Memory safety bugs present in Firefox 123, Firefox ESR 115.8, and Thunderbird 115.8. Some of these bugs
    showed evidence of memory corruption and we presume that with enough effort some of these could have been
    exploited to run arbitrary code. (CVE-2024-2614)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2024-13/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox ESR version 115.9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-2614");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox_esr");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_firefox_installed.nasl");
  script_require_keys("MacOSX/Firefox/Version");

  exit(0);
}

include('mozilla_version.inc');

var kb_base = 'MacOSX/Firefox';
get_kb_item_or_exit(kb_base+'/Installed');

var version = get_kb_item_or_exit(kb_base+'/Version', exit_code:1);
var path = get_kb_item_or_exit(kb_base+'/Path', exit_code:1);

var is_esr = get_kb_item(kb_base+'/is_esr');
if (isnull(is_esr)) audit(AUDIT_NOT_INST, 'Mozilla Firefox ESR');

mozilla_check_version(version:version, path:path, product:'firefox', esr:TRUE, fix:'115.9', min:'115.0.0', severity:SECURITY_HOLE);
