#%NASL_MIN_LEVEL 80900
## 
# (C) Tenable, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2025-09.
# The text itself is copyright (C) Mozilla Foundation.
##

include('compat.inc');

if (description)
{
  script_id(214957);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/06");

  script_cve_id(
    "CVE-2024-11704",
    "CVE-2025-1009",
    "CVE-2025-1010",
    "CVE-2025-1011",
    "CVE-2025-1012",
    "CVE-2025-1013",
    "CVE-2025-1014",
    "CVE-2025-1016",
    "CVE-2025-1017"
  );
  script_xref(name:"IAVA", value:"2024-A-0769-S");
  script_xref(name:"IAVA", value:"2025-A-0079-S");

  script_name(english:"Mozilla Firefox ESR < 128.7");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox ESR installed on the remote Windows host is prior to 128.7. It is, therefore, affected by
multiple vulnerabilities as referenced in the mfsa2025-09 advisory.

  - Memory safety bugs present in Firefox 134, Thunderbird 134, Firefox ESR 115.19, Firefox ESR 128.6,
    Thunderbird 115.19, and Thunderbird 128.6. Some of these bugs showed evidence of memory corruption and we
    presume that with enough effort some of these could have been exploited to run arbitrary code.
    (CVE-2025-1016)

  - A double-free issue could have occurred in `secpkcs7decoderstartdecrypt()` when handling an error path.
    Under specific conditions, the same symmetric key could have been freed twice, potentially leading to
    memory corruption. (CVE-2024-11704)

  - An attacker could have caused a use-after-free via crafted XSLT data, leading to a potentially exploitable
    crash. (CVE-2025-1009)

  - An attacker could have caused a use-after-free via the Custom Highlight API, leading to a potentially
    exploitable crash. (CVE-2025-1010)

  - A bug in WebAssembly code generation could have lead to a crash. It may have been possible for an attacker
    to leverage this to achieve code execution. (CVE-2025-1011)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2025-09/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox ESR version 128.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-1017");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox_esr");
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

mozilla_check_version(installs:installs, product:'firefox', esr:TRUE, fix:'128.7', min:'128.0.0', severity:SECURITY_HOLE);
