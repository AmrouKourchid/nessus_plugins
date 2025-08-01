#%NASL_MIN_LEVEL 80900
## 
# (C) Tenable, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2025-22.
# The text itself is copyright (C) Mozilla Foundation.
##

include('compat.inc');

if (description)
{
  script_id(233651);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/05");

  script_cve_id("CVE-2025-3028", "CVE-2025-3029", "CVE-2025-3030");
  script_xref(name:"IAVA", value:"2025-A-0211-S");

  script_name(english:"Mozilla Firefox ESR < 128.9");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox ESR installed on the remote Windows host is prior to 128.9. It is, therefore, affected by
multiple vulnerabilities as referenced in the mfsa2025-22 advisory.

  - Memory safety bugs present in Firefox 136, Thunderbird 136, Firefox ESR 128.8, and Thunderbird 128.8. Some
    of these bugs showed evidence of memory corruption and we presume that with enough effort some of these
    could have been exploited to run arbitrary code. (CVE-2025-3030)

  - JavaScript code running while transforming a document with the XSLTProcessor could lead to a use-after-
    free. (CVE-2025-3028)

  - A crafted URL containing specific Unicode characters could have hidden the true origin of the page,
    resulting in a potential spoofing attack. (CVE-2025-3029)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2025-22/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox ESR version 128.9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-3030");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/01");

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

mozilla_check_version(installs:installs, product:'firefox', esr:TRUE, fix:'128.9', min:'128.0.0', severity:SECURITY_HOLE);
