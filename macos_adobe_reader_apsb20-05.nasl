#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(133671);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/20");

  script_cve_id(
    "CVE-2020-3742",
    "CVE-2020-3743",
    "CVE-2020-3744",
    "CVE-2020-3745",
    "CVE-2020-3746",
    "CVE-2020-3747",
    "CVE-2020-3748",
    "CVE-2020-3749",
    "CVE-2020-3750",
    "CVE-2020-3751",
    "CVE-2020-3752",
    "CVE-2020-3753",
    "CVE-2020-3754",
    "CVE-2020-3755",
    "CVE-2020-3756",
    "CVE-2020-3762",
    "CVE-2020-3763"
  );

  script_name(english:"Adobe Reader < 2015.006.30510 / 2017.011.30158 / 2020.006.20034 Multiple Vulnerabilities (APSB20-05) (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Reader installed on the remote macOS host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Reader installed on the remote macOS host is a version prior to 2015.006.30510, 2017.011.30158, or
2020.006.20034. It is, therefore, affected by multiple vulnerabilities.

  - Adobe Acrobat and Reader versions 2019.021.20061 and earlier, 2017.011.30156 and earlier, 2017.011.30156
    and earlier, and 2015.006.30508 and earlier have a privilege escalation vulnerability. Successful
    exploitation could lead to arbitrary file system write. (CVE-2020-3762, CVE-2020-3763)

  - Adobe Acrobat and Reader versions 2019.021.20061 and earlier, 2017.011.30156 and earlier, 2017.011.30156
    and earlier, and 2015.006.30508 and earlier have an out-of-bounds read vulnerability. Successful
    exploitation could lead to information disclosure . (CVE-2020-3744, CVE-2020-3747, CVE-2020-3755)

  - Adobe Acrobat and Reader versions, 2019.021.20061 and earlier, 2017.011.30156 and earlier, 2017.011.30156
    and earlier, and 2015.006.30508 and earlier have a heap overflow vulnerability. Successful exploitation
    could lead to arbitrary code execution . (CVE-2020-3742)

  - Adobe Acrobat and Reader versions 2019.021.20061 and earlier, 2017.011.30156 and earlier, 2017.011.30156
    and earlier, and 2015.006.30508 and earlier have a buffer error vulnerability. Successful exploitation
    could lead to arbitrary code execution . (CVE-2020-3752, CVE-2020-3754)

  - Adobe Acrobat and Reader versions 2019.021.20061 and earlier, 2017.011.30156 and earlier, 2017.011.30156
    and earlier, and 2015.006.30508 and earlier have an use after free vulnerability. Successful exploitation
    could lead to arbitrary code execution . (CVE-2020-3743, CVE-2020-3745, CVE-2020-3746, CVE-2020-3748,
    CVE-2020-3749, CVE-2020-3750, CVE-2020-3751)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/acrobat/apsb20-05.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Reader version 2015.006.30510 / 2017.011.30158 / 2020.006.20034 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3763");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat_reader");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'min_version' : '15.6', 'max_version' : '15.006.30508', 'fixed_version' : '15.006.30510', 'track' : 'DC Classic' },
  { 'min_version' : '17.8', 'max_version' : '17.011.30156', 'fixed_version' : '17.011.30158', 'track' : 'DC Classic' },
  { 'min_version' : '15.7', 'max_version' : '19.021.20061', 'fixed_version' : '20.006.20034', 'track' : 'DC Continuous' }
];
vcf::adobe_acrobat::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    max_segs:3,
    severity:SECURITY_HOLE
);
