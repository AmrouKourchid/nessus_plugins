#%NASL_MIN_LEVEL 80900
## 
# (C) Tenable, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2024-04.
# The text itself is copyright (C) Mozilla Foundation.
##

include('compat.inc');

if (description)
{
  script_id(189365);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/18");

  script_cve_id(
    "CVE-2024-0741",
    "CVE-2024-0742",
    "CVE-2024-0746",
    "CVE-2024-0747",
    "CVE-2024-0749",
    "CVE-2024-0750",
    "CVE-2024-0751",
    "CVE-2024-0753",
    "CVE-2024-0755"
  );
  script_xref(name:"IAVA", value:"2024-A-0245-S");

  script_name(english:"Mozilla Thunderbird < 115.7");

  script_set_attribute(attribute:"synopsis", value:
"A mail client installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Thunderbird installed on the remote Windows host is prior to 115.7. It is, therefore, affected by
multiple vulnerabilities as referenced in the mfsa2024-04 advisory.

  - An out of bounds write in ANGLE could have allowed an attacker to corrupt memory leading to a potentially
    exploitable crash. (CVE-2024-0741)

  - It was possible for certain browser prompts and dialogs to be activated or dismissed unintentionally by
    the user due to an incorrect timestamp used to prevent input after page load. (CVE-2024-0742)

  - A Linux user opening the print preview dialog could have caused the browser to crash. (CVE-2024-0746)

  - When a parent page loaded a child in an iframe with <code>unsafe-inline</code>, the parent Content
    Security Policy could have overridden the child Content Security Policy. (CVE-2024-0747)

  - A phishing site could have repurposed an <code>about:</code> dialog to show phishing content with an
    incorrect origin in the address bar. (CVE-2024-0749)

  - A bug in popup notifications delay calculation could have made it possible for an attacker to trick a user
    into granting permissions. (CVE-2024-0750)

  - A malicious devtools extension could have been used to escalate privileges. (CVE-2024-0751)

  - In specific HSTS configurations an attacker could have bypassed HSTS on a subdomain. (CVE-2024-0753)

  - Memory safety bugs present in Firefox 121, Firefox ESR 115.6, and Thunderbird 115.6. Some of these bugs
    showed evidence of memory corruption and we presume that with enough effort some of these could have been
    exploited to run arbitrary code. (CVE-2024-0755)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2024-04/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Thunderbird version 115.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-0755");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Thunderbird/Version");

  exit(0);
}

include('mozilla_version.inc');

var port = get_kb_item('SMB/transport');
if (!port) port = 445;

var installs = get_kb_list('SMB/Mozilla/Thunderbird/*');
if (isnull(installs)) audit(AUDIT_NOT_INST, 'Thunderbird');

mozilla_check_version(installs:installs, product:'thunderbird', esr:FALSE, fix:'115.7', severity:SECURITY_HOLE);
