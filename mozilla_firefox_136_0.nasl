#%NASL_MIN_LEVEL 80900
## 
# (C) Tenable, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2025-14.
# The text itself is copyright (C) Mozilla Foundation.
##

include('compat.inc');

if (description)
{
  script_id(221618);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/03");

  script_cve_id(
    "CVE-2024-9956",
    "CVE-2025-1930",
    "CVE-2025-1931",
    "CVE-2025-1932",
    "CVE-2025-1933",
    "CVE-2025-1934",
    "CVE-2025-1935",
    "CVE-2025-1936",
    "CVE-2025-1937",
    "CVE-2025-1938",
    "CVE-2025-1939",
    "CVE-2025-1940",
    "CVE-2025-1941",
    "CVE-2025-1942",
    "CVE-2025-1943"
  );
  script_xref(name:"IAVA", value:"2025-A-0146-S");

  script_name(english:"Mozilla Firefox < 136.0");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox installed on the remote Windows host is prior to 136.0. It is, therefore, affected by multiple
vulnerabilities as referenced in the mfsa2025-14 advisory.

  - Malicious pages could use Firefox for Android to pass FIDO: links to the OS and trigger the hybrid
    passkey transport. An attacker within Bluetooth range could have used this to trick the user into using
    their passkey to log the attacker's computer into the target account. (CVE-2024-9956)

  - On Windows, a compromised content process could use bad StreamData sent over AudioIPC to trigger a use-
    after-free in the Browser process. This could have led to a sandbox escape. (CVE-2025-1930)

  - Android apps can load web pages using the Custom Tabs feature. This feature supports a transition
    animation that could have been used to trick a user into granting sensitive permissions by hiding what the
    user was actually clicking. (CVE-2025-1939)

  - It was possible to cause a use-after-free in the content process side of a WebTransport connection,
    leading to a potentially exploitable crash. (CVE-2025-1931)

  - An inconsistent comparator in xslt/txNodeSorter could have resulted in potentially exploitable out-of-
    bounds access. Only affected version 122 and later. (CVE-2025-1932)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2025-14/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox version 136.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-9956");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");

  exit(0);
}

include('mozilla_version.inc');

var port = get_kb_item('SMB/transport');
if (!port) port = 445;

var installs = get_kb_list('SMB/Mozilla/Firefox/*');
if (isnull(installs)) audit(AUDIT_NOT_INST, 'Firefox');

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'136.0', severity:SECURITY_HOLE);
