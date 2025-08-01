#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151587);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/20");

  script_cve_id(
    "CVE-2021-28634",
    "CVE-2021-28635",
    "CVE-2021-28636",
    "CVE-2021-28637",
    "CVE-2021-28638",
    "CVE-2021-28639",
    "CVE-2021-28640",
    "CVE-2021-28641",
    "CVE-2021-28642",
    "CVE-2021-28643",
    "CVE-2021-28644",
    "CVE-2021-35980",
    "CVE-2021-35981",
    "CVE-2021-35983",
    "CVE-2021-35984",
    "CVE-2021-35985",
    "CVE-2021-35986",
    "CVE-2021-35987",
    "CVE-2021-35988"
  );
  script_xref(name:"IAVA", value:"2021-A-0301-S");

  script_name(english:"Adobe Acrobat < 2017.011.30199 / 2020.004.30006 / 2021.005.20058 Multiple Vulnerabilities (APSB21-51) (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Acrobat installed on the remote macOS host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Acrobat installed on the remote macOS host is a version prior to 2017.011.30199, 2020.004.30006, or
2021.005.20058. It is, therefore, affected by multiple vulnerabilities.

  - Acrobat Reader DC versions 2021.005.20054 (and earlier), 2020.004.30005 (and earlier) and 2017.011.30197
    (and earlier) are affected by an Improper Neutralization of Special Elements used in an OS Command. An
    authenticated attacker could leverage this vulnerability to achieve arbitrary code execution on the host
    machine in the context of the current user. Exploitation of this issue requires user interaction in that a
    victim must open a malicious file. (CVE-2021-28634)

  - Acrobat Reader DC versions 2021.005.20054 (and earlier), 2020.004.30005 (and earlier) and 2017.011.30197
    (and earlier) are affected by an Use-after-free vulnerability. An unauthenticated attacker could leverage
    this vulnerability to achieve arbitrary code execution in the context of the current user. Exploitation of
    this issue requires user interaction in that a victim must open a malicious file. (CVE-2021-28639,
    CVE-2021-28641, CVE-2021-35981, CVE-2021-35983)

  - Acrobat Reader DC versions 2021.005.20054 (and earlier), 2020.004.30005 (and earlier) and 2017.011.30197
    (and earlier) are affected by an Out-of-bounds Read vulnerability. An unauthenticated attacker could
    leverage this vulnerability to disclose arbitrary memory information in the context of the current user.
    Exploitation of this issue requires user interaction in that a victim must open a malicious file.
    (CVE-2021-35988)

  - Acrobat Reader DC versions 2021.005.20054 (and earlier), 2020.004.30005 (and earlier) and 2017.011.30197
    (and earlier) are affected by an out-of-bounds Read vulnerability. An unauthenticated attacker could
    leverage this vulnerability to disclose arbitrary memory information in the context of the current user.
    Exploitation of this issue requires user interaction in that a victim must open a malicious file.
    (CVE-2021-35987)

  - Acrobat Reader DC versions 2021.005.20054 (and earlier), 2020.004.30005 (and earlier) and 2017.011.30197
    (and earlier) are affected by a Path traversal vulnerability. An unauthenticated attacker could leverage
    this vulnerability to achieve arbitrary code execution in the context of the current user. Exploitation of
    this issue requires user interaction in that a victim must open a malicious file. (CVE-2021-28644,
    CVE-2021-35980)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/acrobat/apsb21-51.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Acrobat version 2017.011.30199 / 2020.004.30006 / 2021.005.20058 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-28639");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-28634");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(22, 78, 122, 125, 416, 427, 476, 787, 843);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'min_version' : '17.8', 'max_version' : '17.011.30197', 'fixed_version' : '17.011.30199', 'track' : 'DC Classic' },
  { 'min_version' : '20.1', 'max_version' : '20.004.30005', 'fixed_version' : '20.004.30006', 'track' : 'DC Classic' },
  { 'min_version' : '15.7', 'max_version' : '21.005.20054', 'fixed_version' : '21.005.20058', 'track' : 'DC Continuous' }
];
vcf::adobe_acrobat::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    max_segs:3,
    severity:SECURITY_HOLE
);
