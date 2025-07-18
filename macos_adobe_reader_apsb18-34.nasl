#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(207088);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/04");

  script_cve_id(
    "CVE-2018-12775",
    "CVE-2018-12778",
    "CVE-2018-12801",
    "CVE-2018-12840",
    "CVE-2018-12848",
    "CVE-2018-12849",
    "CVE-2018-12850",
    "CVE-2018-19721",
    "CVE-2018-19723"
  );

  script_name(english:"Adobe Reader < 2015.006.30452 / 2017.011.30102 / 2018.011.20063 Multiple Vulnerabilities (APSB18-34) (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Reader installed on the remote macOS host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Reader installed on the remote macOS host is a version prior to 2015.006.30452, 2017.011.30102, or
2018.011.20063. It is, therefore, affected by multiple vulnerabilities.

  - Adobe Acrobat and Reader versions 2018.011.20058 and earlier, 2017.011.30099 and earlier, and
    2015.006.30448 and earlier have an out-of-bounds write vulnerability. Successful exploitation could lead
    to arbitrary code execution. (CVE-2018-12848)

  - Adobe Acrobat and Reader versions 2018.011.20058 and earlier, 2017.011.30099 and earlier, and
    2015.006.30448 and earlier have an out-of-bounds read vulnerability. Successful exploitation could lead to
    information disclosure. (CVE-2018-12775, CVE-2018-12778, CVE-2018-12801, CVE-2018-12840, CVE-2018-12849,
    CVE-2018-12850)

  - Adobe Acrobat and Reader versions 2018.011.20058 and earlier, 2017.011.30099 and earlier, and
    2015.006.30448 and earlier have an out-of-bounds read vulnerability. Successful exploitation could lead to
    information disclosure. Note: A different vulnerability than CVE-2018-19723. (CVE-2018-19721)

  - Adobe Acrobat and Reader versions 2018.011.20058 and earlier, 2017.011.30099 and earlier, and
    2015.006.30448 and earlier have an out-of-bounds read vulnerability. Successful exploitation could lead to
    information disclosure. Note: A different vulnerability than CVE-2018-19721. (CVE-2018-19723)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/acrobat/apsb18-34.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Reader version 2015.006.30452 / 2017.011.30102 / 2018.011.20063 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-12848");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat_reader");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'min_version' : '15.6', 'max_version' : '15.006.30448', 'fixed_version' : '15.006.30452', 'track' : 'DC Classic' },
  { 'min_version' : '17.8', 'max_version' : '17.011.30099', 'fixed_version' : '17.011.30102', 'track' : 'DC Classic' },
  { 'min_version' : '15.7', 'max_version' : '18.011.20058', 'fixed_version' : '18.011.20063', 'track' : 'DC Continuous' }
];
vcf::adobe_acrobat::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    max_segs:3,
    severity:SECURITY_HOLE
);
