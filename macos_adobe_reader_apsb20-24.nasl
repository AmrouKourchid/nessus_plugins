#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(136561);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/21");

  script_cve_id(
    "CVE-2020-9592",
    "CVE-2020-9593",
    "CVE-2020-9594",
    "CVE-2020-9595",
    "CVE-2020-9596",
    "CVE-2020-9597",
    "CVE-2020-9598",
    "CVE-2020-9599",
    "CVE-2020-9600",
    "CVE-2020-9601",
    "CVE-2020-9602",
    "CVE-2020-9603",
    "CVE-2020-9604",
    "CVE-2020-9605",
    "CVE-2020-9606",
    "CVE-2020-9607",
    "CVE-2020-9608",
    "CVE-2020-9609",
    "CVE-2020-9610",
    "CVE-2020-9611",
    "CVE-2020-9612",
    "CVE-2020-9613",
    "CVE-2020-9614",
    "CVE-2020-9615"
  );
  script_xref(name:"IAVA", value:"2020-A-0211-S");

  script_name(english:"Adobe Reader < 2015.006.30523 / 2017.011.30171 / 2020.009.20063 Multiple Vulnerabilities (APSB20-24) (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Reader installed on the remote macOS host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Reader installed on the remote macOS host is a version prior to 2015.006.30523, 2017.011.30171, or
2020.009.20063. It is, therefore, affected by multiple vulnerabilities.

  - Adobe Acrobat and Reader versions 2020.006.20042 and earlier, 2017.011.30166 and earlier, 2017.011.30166
    and earlier, and 2015.006.30518 and earlier have a security bypass vulnerability. Successful exploitation
    could lead to security feature bypass. (CVE-2020-9592, CVE-2020-9596, CVE-2020-9613, CVE-2020-9614)

  - Adobe Acrobat and Reader versions 2020.006.20042 and earlier, 2017.011.30166 and earlier, 2017.011.30166
    and earlier, and 2015.006.30518 and earlier have a heap overflow vulnerability. Successful exploitation
    could lead to arbitrary code execution . (CVE-2020-9612)

  - Adobe Acrobat and Reader versions 2020.006.20042 and earlier, 2017.011.30166 and earlier, 2017.011.30166
    and earlier, and 2015.006.30518 and earlier have a null pointer vulnerability. Successful exploitation
    could lead to application denial-of-service. (CVE-2020-9610)

  - Adobe Acrobat and Reader versions 2020.006.20042 and earlier, 2017.011.30166 and earlier, 2017.011.30166
    and earlier, and 2015.006.30518 and earlier have a race condition vulnerability. Successful exploitation
    could lead to security feature bypass. (CVE-2020-9615)

  - Adobe Acrobat and Reader versions 2020.006.20042 and earlier, 2017.011.30166 and earlier, 2017.011.30166
    and earlier, and 2015.006.30518 and earlier have an out-of-bounds write vulnerability. Successful
    exploitation could lead to arbitrary code execution . (CVE-2020-9594, CVE-2020-9597)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/acrobat/apsb20-24.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Reader version 2015.006.30523 / 2017.011.30171 / 2020.009.20063 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-9614");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-9612");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat_reader");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
  { 'min_version' : '15.6', 'max_version' : '15.006.30518', 'fixed_version' : '15.006.30523', 'track' : 'DC Classic' },
  { 'min_version' : '17.8', 'max_version' : '17.011.30166', 'fixed_version' : '17.011.30171', 'track' : 'DC Classic' },
  { 'min_version' : '15.7', 'max_version' : '20.006.20042', 'fixed_version' : '20.009.20063', 'track' : 'DC Continuous' }
];
vcf::adobe_acrobat::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    max_segs:3,
    severity:SECURITY_WARNING
);
