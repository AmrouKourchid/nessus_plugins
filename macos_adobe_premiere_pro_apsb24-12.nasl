#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(191907);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/20");

  script_cve_id("CVE-2024-20745", "CVE-2024-20746");
  script_xref(name:"IAVA", value:"2024-A-0159-S");

  script_name(english:"Adobe Premiere Pro < 23.6.4 / 24.0.0 < 24.2.1 Multiple Arbitrary code execution (APSB24-12) (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"The Adobe Premiere Pro instance installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Premiere Pro installed on the remote macOS host is prior to 23.6.4, 24.2.1. It is, therefore,
affected by multiple vulnerabilities as referenced in the APSB24-12 advisory.

  - Premiere Pro versions 24.1, 23.6.2 and earlier are affected by an out-of-bounds write vulnerability that
    could result in arbitrary code execution in the context of the current user. Exploitation of this issue
    requires user interaction in that a victim must open a malicious file. (CVE-2024-20746)

  - Premiere Pro versions 24.1, 23.6.2 and earlier are affected by a Heap-based Buffer Overflow vulnerability
    that could result in arbitrary code execution in the context of the current user. Exploitation of this
    issue requires user interaction in that a victim must open a malicious file. (CVE-2024-20745)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/premiere_pro/apsb24-12.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Premiere Pro version 23.6.4, 24.2.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20746");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(122, 787);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:premiere_pro");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:premiere_pro_cc");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_adobe_premiere_pro_installed.nbin");
  script_require_keys("installed_sw/Adobe Premiere Pro");

  exit(0);
}

include('vcf.inc');

if (!get_kb_item('Host/local_checks_enabled'))
  audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/MacOSX/Version'))
  audit(AUDIT_OS_NOT, 'macOS');

var app_info = vcf::get_app_info(app:'Adobe Premiere Pro');

var constraints = [
  { 'fixed_version' : '23.6.4' },
  { 'min_version' : '24.0.0', 'fixed_version' : '24.2.1' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
