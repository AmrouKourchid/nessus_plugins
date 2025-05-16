#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150340);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/20");

  script_cve_id(
    "CVE-2021-28551",
    "CVE-2021-28552",
    "CVE-2021-28554",
    "CVE-2021-28631",
    "CVE-2021-28632"
  );
  script_xref(name:"IAVA", value:"2021-A-0266-S");

  script_name(english:"Adobe Reader < 2017.011.30197 / 2020.004.30005 / 2021.005.20048 Multiple Vulnerabilities (APSB21-37) (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Reader installed on the remote macOS host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Reader installed on the remote macOS host is a version prior to 2017.011.30197, 2020.004.30005, or
2021.005.20048. It is, therefore, affected by multiple vulnerabilities.

  - Acrobat Reader DC versions versions 2021.001.20155 (and earlier), 2020.001.30025 (and earlier) and
    2017.011.30196 (and earlier) are affected by an Use After Free vulnerability. An unauthenticated attacker
    could leverage this vulnerability to achieve arbitrary code execution in the context of the current user.
    Exploitation of this issue requires user interaction in that a victim must open a malicious file.
    (CVE-2021-28552, CVE-2021-28631, CVE-2021-28632)

  - Acrobat Reader DC versions versions 2021.001.20155 (and earlier), 2020.001.30025 (and earlier) and
    2017.011.30196 (and earlier) are affected by an Out-of-bounds Read vulnerability. An unauthenticated
    attacker could leverage this vulnerability to achieve arbitrary code execution in the context of the
    current user. Exploitation of this issue requires user interaction in that a victim must open a malicious
    file. (CVE-2021-28554)

  - Acrobat Reader DC versions versions 2021.001.20155 (and earlier), 2020.001.30025 (and earlier) and
    2017.011.30196 (and earlier) are affected by an Out-of-bounds read vulnerability. An unauthenticated
    attacker could leverage this vulnerability to achieve arbitrary code execution in the context of the
    current user. Exploitation of this issue requires user interaction in that a victim must open a malicious
    file. (CVE-2021-28551)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/acrobat/apsb21-37.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Reader version 2017.011.30197 / 2020.004.30005 / 2021.005.20048 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-28632");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(125, 416);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat_reader");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_adobe_reader_installed.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/Adobe Reader");

  exit(0);
}

include('vcf_extras.inc');

get_kb_item_or_exit('Host/local_checks_enabled');
os = get_kb_item('Host/MacOSX/Version');
if (empty_or_null(os)) audit(AUDIT_OS_NOT, 'Mac OS X');

var app_info = vcf::get_app_info(app:'Adobe Reader');

# vcf::adobe_reader::check_version_and_report will
# properly separate tracks when checking constraints.
# x.y.30zzz = DC Classic
# x.y.20zzz = DC Continuous
var constraints = [
  { 'min_version' : '17.8', 'max_version' : '17.011.30196', 'fixed_version' : '17.011.30197', 'track' : 'DC Classic' },
  { 'min_version' : '20.1', 'max_version' : '20.001.30025', 'fixed_version' : '20.004.30005', 'track' : 'DC Classic' },
  { 'min_version' : '15.7', 'max_version' : '21.001.20155', 'fixed_version' : '21.005.20048', 'track' : 'DC Continuous' }
];
vcf::adobe_acrobat::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    max_segs:3,
    severity:SECURITY_WARNING
);
