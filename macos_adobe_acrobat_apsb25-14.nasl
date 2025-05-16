#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(232597);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/14");

  script_cve_id(
    "CVE-2025-24431",
    "CVE-2025-27158",
    "CVE-2025-27159",
    "CVE-2025-27160",
    "CVE-2025-27161",
    "CVE-2025-27162",
    "CVE-2025-27163",
    "CVE-2025-27164",
    "CVE-2025-27174"
  );
  script_xref(name:"IAVA", value:"2025-A-0150");

  script_name(english:"Adobe Acrobat < 20.005.30763 / 24.001.30235 / 25.001.20432 Multiple Vulnerabilities (APSB25-14) (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Acrobat installed on the remote macOS host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Acrobat installed on the remote macOS host is a version prior to 20.005.30763, 24.001.30235, or
25.001.20432. It is, therefore, affected by multiple vulnerabilities.

  - Access of Uninitialized Pointer (CWE-824) potentially leading to Arbitrary code execution (CVE-2025-27158,
    CVE-2025-27162)

  - Use After Free (CWE-416) potentially leading to Arbitrary code execution (CVE-2025-27159, CVE-2025-27160,
    CVE-2025-27174)

  - Out-of-bounds Read (CWE-125) potentially leading to Arbitrary code execution (CVE-2025-24431,
    CVE-2025-27161)

  - Out-of-bounds Read (CWE-125) potentially leading to Memory Leak (CVE-2025-27163, CVE-2025-27164)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/acrobat/apsb25-14.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Acrobat version 20.005.30763 / 24.001.30235 / 25.001.20432 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-27174");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2025-27162");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(125, 416, 824);

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/03/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_adobe_acrobat_installed.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/Adobe Acrobat");

  exit(0);
}

include('vcf_extras.inc');

get_kb_item_or_exit('Host/local_checks_enabled');
os = get_kb_item('Host/MacOSX/Version');
if (empty_or_null(os)) audit(AUDIT_OS_NOT, 'Mac OS X');

var app_info = vcf::get_app_info(app:'Adobe Acrobat');

# vcf::adobe_reader::check_version_and_report will
# properly separate tracks when checking constraints.
# x.y.30zzz = DC Classic
# x.y.20zzz = DC Continuous
var constraints = [
  { 'min_version' : '20.1', 'max_version' : '20.005.30748', 'fixed_version' : '20.005.30763', 'track' : 'DC Classic' },
  { 'min_version' : '24.1', 'max_version' : '24.001.30225', 'fixed_version' : '24.001.30235', 'track' : 'DC Classic' },
  { 'min_version' : '15.7', 'max_version' : '25.001.20428', 'fixed_version' : '25.001.20432', 'track' : 'DC Continuous' }
];
vcf::adobe_acrobat::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    max_segs:3,
    severity:SECURITY_HOLE
);
