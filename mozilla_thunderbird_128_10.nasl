#%NASL_MIN_LEVEL 80900
## 
# (C) Tenable, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2025-32.
# The text itself is copyright (C) Mozilla Foundation.
## 

include('compat.inc');

if (description)
{
  script_id(235064);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/01");

  script_cve_id(
    "CVE-2025-2817",
    "CVE-2025-4082",
    "CVE-2025-4083",
    "CVE-2025-4084",
    "CVE-2025-4087",
    "CVE-2025-4091",
    "CVE-2025-4093"
  );
  script_xref(name:"IAVA", value:"2025-A-0308");

  script_name(english:"Mozilla Thunderbird < 128.10");

  script_set_attribute(attribute:"synopsis", value:
"A mail client installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Thunderbird installed on the remote Windows host is prior to 128.10. It is, therefore, affected by
multiple vulnerabilities as referenced in the mfsa2025-32 advisory.

  - A process isolation vulnerability in Thunderbird stemmed from improper handling of javascript: URIs, which
    could allow content to execute in the top-level document's process instead of the intended frame,
    potentially enabling a sandbox escape. (CVE-2025-4083)

  - Thunderbird's update mechanism allowed a medium-integrity user process to interfere with the SYSTEM-level
    updater by manipulating the file-locking behavior. By injecting code into the user-privileged process, an
    attacker could bypass intended access controls, allowing SYSTEM-level file operations on paths controlled
    by a non-privileged user and enabling privilege escalation. (CVE-2025-2817)

  - Modification of specific WebGL shader attributes could trigger an out-of-bounds read, which, when chained
    with other vulnerabilities, could be used to escalate privileges. This bug only affects Thunderbird for
    macOS. Other versions of Thunderbird are unaffected. (CVE-2025-4082)

  - Due to insufficient escaping of the special characters in the copy as cURL feature, an attacker could
    trick a user into using this command, potentially leading to local code execution on the user's system.
    This bug only affects Firefox for Windows. Other versions of Firefox are unaffected. (CVE-2025-4084)

  - A vulnerability was identified in Thunderbird where XPath parsing could trigger undefined behavior due to
    missing null checks during attribute access. This could lead to out-of-bounds read access and potentially,
    memory corruption. (CVE-2025-4087)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2025-32/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Thunderbird version 128.10 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-4083");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Thunderbird/Version");

  exit(0);
}

include('mozilla_version.inc');

var port = get_kb_item('SMB/transport');
if (!port) port = 445;

var installs = get_kb_list('SMB/Mozilla/Thunderbird/*');
if (isnull(installs)) audit(AUDIT_NOT_INST, 'Thunderbird');

mozilla_check_version(installs:installs, product:'thunderbird', esr:FALSE, fix:'128.10', severity:SECURITY_HOLE);
