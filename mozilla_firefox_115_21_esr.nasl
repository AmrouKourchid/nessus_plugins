#%NASL_MIN_LEVEL 80900
## 
# (C) Tenable, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2025-15.
# The text itself is copyright (C) Mozilla Foundation.
##

include('compat.inc');

if (description)
{
  script_id(221620);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/03");

  script_cve_id(
    "CVE-2024-43097",
    "CVE-2025-1930",
    "CVE-2025-1931",
    "CVE-2025-1933",
    "CVE-2025-1937"
  );
  script_xref(name:"IAVA", value:"2025-A-0146-S");

  script_name(english:"Mozilla Firefox ESR < 115.21");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox ESR installed on the remote Windows host is prior to 115.21. It is, therefore, affected by
multiple vulnerabilities as referenced in the mfsa2025-15 advisory.

  - Memory safety bugs present in Firefox 135, Thunderbird 135, Firefox ESR 115.20, Firefox ESR 128.7, and
    Thunderbird 128.7. Some of these bugs showed evidence of memory corruption and we presume that with enough
    effort some of these could have been exploited to run arbitrary code. (CVE-2025-1937)

  - On 64-bit CPUs, when the JIT compiles WASM i32 return values they can pick up bits from left over memory.
    This can potentially cause them to be treated as a different type. (CVE-2025-1933)

  - In resizeToAtLeast of SkRegion.cpp, there was a possible out of bounds write due to an integer overflow
    (CVE-2024-43097)

  - On Windows, a compromised content process could use bad StreamData sent over AudioIPC to trigger a use-
    after-free in the Browser process. This could have led to a sandbox escape. (CVE-2025-1930)

  - It was possible to cause a use-after-free in the content process side of a WebTransport connection,
    leading to a potentially exploitable crash. (CVE-2025-1931)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2025-15/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox ESR version 115.21 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-1937");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2025-1933");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/01/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/04");

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

mozilla_check_version(installs:installs, product:'firefox', esr:TRUE, fix:'115.21', min:'115.0.0', severity:SECURITY_WARNING);
