#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(211677);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/22");

  script_cve_id(
    "CVE-2014-0566",
    "CVE-2014-8450",
    "CVE-2015-3095",
    "CVE-2015-4435",
    "CVE-2015-4438",
    "CVE-2015-4441",
    "CVE-2015-4443",
    "CVE-2015-4444",
    "CVE-2015-4445",
    "CVE-2015-4446",
    "CVE-2015-4447",
    "CVE-2015-4448",
    "CVE-2015-4449",
    "CVE-2015-4450",
    "CVE-2015-4451",
    "CVE-2015-4452",
    "CVE-2015-5085",
    "CVE-2015-5086",
    "CVE-2015-5087",
    "CVE-2015-5088",
    "CVE-2015-5089",
    "CVE-2015-5090",
    "CVE-2015-5091",
    "CVE-2015-5092",
    "CVE-2015-5093",
    "CVE-2015-5094",
    "CVE-2015-5095",
    "CVE-2015-5096",
    "CVE-2015-5097",
    "CVE-2015-5098",
    "CVE-2015-5099",
    "CVE-2015-5100",
    "CVE-2015-5101",
    "CVE-2015-5102",
    "CVE-2015-5103",
    "CVE-2015-5104",
    "CVE-2015-5105",
    "CVE-2015-5106",
    "CVE-2015-5107",
    "CVE-2015-5108",
    "CVE-2015-5109",
    "CVE-2015-5110",
    "CVE-2015-5111",
    "CVE-2015-5113",
    "CVE-2015-5114",
    "CVE-2015-5115"
  );

  script_name(english:"Adobe Acrobat < 10.1.15 / 11.0.12 / 2015.006.30060 / 2015.008.20082 Multiple Vulnerabilities (APSB15-15) (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Acrobat installed on the remote macOS host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Acrobat installed on the remote macOS host is a version prior to 10.1.15, 11.0.12, 2015.006.30060,
or 2015.008.20082. It is, therefore, affected by multiple vulnerabilities.

  - Adobe Reader and Acrobat 10.x before 10.1.15 and 11.x before 11.0.12, Acrobat and Acrobat Reader DC
    Classic before 2015.006.30060, and Acrobat and Acrobat Reader DC Continuous before 2015.008.20082 on
    Windows and OS X allow attackers to execute arbitrary code or cause a denial of service (memory
    corruption) via unspecified vectors, a different vulnerability than CVE-2015-3095, CVE-2015-5087,
    CVE-2015-5094, CVE-2015-5100, CVE-2015-5102, CVE-2015-5103, and CVE-2015-5104. (CVE-2015-5115)

  - Adobe Reader and Acrobat 10.x before 10.1.15 and 11.x before 11.0.12, Acrobat and Acrobat Reader DC
    Classic before 2015.006.30060, and Acrobat and Acrobat Reader DC Continuous before 2015.008.20082 on
    Windows and OS X allow attackers to execute arbitrary code or cause a denial of service (memory
    corruption) via unspecified vectors, a different vulnerability than CVE-2015-3095, CVE-2015-5087,
    CVE-2015-5094, CVE-2015-5100, CVE-2015-5102, CVE-2015-5103, and CVE-2015-5115. (CVE-2015-5104)

  - Adobe Reader and Acrobat 10.x before 10.1.15 and 11.x before 11.0.12, Acrobat and Acrobat Reader DC
    Classic before 2015.006.30060, and Acrobat and Acrobat Reader DC Continuous before 2015.008.20082 on
    Windows and OS X allow attackers to execute arbitrary code or cause a denial of service (memory
    corruption) via unspecified vectors, a different vulnerability than CVE-2015-3095, CVE-2015-5087,
    CVE-2015-5094, CVE-2015-5100, CVE-2015-5102, CVE-2015-5104, and CVE-2015-5115. (CVE-2015-5103)

  - Adobe Reader and Acrobat 10.x before 10.1.15 and 11.x before 11.0.12, Acrobat and Acrobat Reader DC
    Classic before 2015.006.30060, and Acrobat and Acrobat Reader DC Continuous before 2015.008.20082 on
    Windows and OS X allow attackers to execute arbitrary code or cause a denial of service (memory
    corruption) via unspecified vectors, a different vulnerability than CVE-2015-3095, CVE-2015-5087,
    CVE-2015-5094, CVE-2015-5100, CVE-2015-5103, CVE-2015-5104, and CVE-2015-5115. (CVE-2015-5102)

  - Adobe Reader and Acrobat 10.x before 10.1.15 and 11.x before 11.0.12, Acrobat and Acrobat Reader DC
    Classic before 2015.006.30060, and Acrobat and Acrobat Reader DC Continuous before 2015.008.20082 on
    Windows and OS X allow attackers to execute arbitrary code or cause a denial of service (memory
    corruption) via unspecified vectors, a different vulnerability than CVE-2015-3095, CVE-2015-5087,
    CVE-2015-5094, CVE-2015-5102, CVE-2015-5103, CVE-2015-5104, and CVE-2015-5115. (CVE-2015-5100)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/acrobat/apsb15-15.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Acrobat version 10.1.15 / 11.0.12 / 2015.006.30060 / 2015.008.20082 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-5115");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'max_version' : '10.1.14', 'fixed_version' : '10.1.15', 'track' : 'DC Continuous' },
  { 'min_version': '11.0.0', 'max_version' : '11.0.11', 'fixed_version' : '11.0.12', 'track' : 'DC Continuous' },
  { 'fixed_version' : '15.006.30060', 'equal' : '15.006.30033', 'track' : 'DC Classic' },
  { 'fixed_version' : '15.008.20082', 'equal' : '15.007.20033', 'track' : 'DC Continuous' }
];
vcf::adobe_acrobat::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    max_segs:3,
    severity:SECURITY_HOLE
);
