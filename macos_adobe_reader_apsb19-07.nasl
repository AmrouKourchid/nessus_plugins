#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(207084);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/20");

  script_cve_id(
    "CVE-2018-19725",
    "CVE-2019-7018",
    "CVE-2019-7019",
    "CVE-2019-7020",
    "CVE-2019-7021",
    "CVE-2019-7022",
    "CVE-2019-7023",
    "CVE-2019-7024",
    "CVE-2019-7025",
    "CVE-2019-7026",
    "CVE-2019-7027",
    "CVE-2019-7028",
    "CVE-2019-7029",
    "CVE-2019-7030",
    "CVE-2019-7031",
    "CVE-2019-7032",
    "CVE-2019-7033",
    "CVE-2019-7034",
    "CVE-2019-7035",
    "CVE-2019-7036",
    "CVE-2019-7037",
    "CVE-2019-7038",
    "CVE-2019-7039",
    "CVE-2019-7040",
    "CVE-2019-7041",
    "CVE-2019-7042",
    "CVE-2019-7043",
    "CVE-2019-7044",
    "CVE-2019-7045",
    "CVE-2019-7046",
    "CVE-2019-7047",
    "CVE-2019-7048",
    "CVE-2019-7049",
    "CVE-2019-7050",
    "CVE-2019-7051",
    "CVE-2019-7052",
    "CVE-2019-7053",
    "CVE-2019-7054",
    "CVE-2019-7055",
    "CVE-2019-7056",
    "CVE-2019-7057",
    "CVE-2019-7058",
    "CVE-2019-7059",
    "CVE-2019-7060",
    "CVE-2019-7062",
    "CVE-2019-7063",
    "CVE-2019-7064",
    "CVE-2019-7065",
    "CVE-2019-7066",
    "CVE-2019-7067",
    "CVE-2019-7068",
    "CVE-2019-7069",
    "CVE-2019-7070",
    "CVE-2019-7071",
    "CVE-2019-7072",
    "CVE-2019-7073",
    "CVE-2019-7074",
    "CVE-2019-7075",
    "CVE-2019-7076",
    "CVE-2019-7077",
    "CVE-2019-7078",
    "CVE-2019-7079",
    "CVE-2019-7080",
    "CVE-2019-7081",
    "CVE-2019-7082",
    "CVE-2019-7083",
    "CVE-2019-7084",
    "CVE-2019-7085",
    "CVE-2019-7086",
    "CVE-2019-7087",
    "CVE-2019-7089"
  );

  script_name(english:"Adobe Reader < 2015.006.30475 / 2017.011.30120 / 2019.010.20091 Multiple Vulnerabilities (APSB19-07) (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Reader installed on the remote macOS host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Reader installed on the remote macOS host is a version prior to 2015.006.30475, 2017.011.30120, or
2019.010.20091. It is, therefore, affected by multiple vulnerabilities.

  - Adobe Acrobat and Reader versions 2019.010.20069 and earlier, 2019.010.20069 and earlier, 2017.011.30113
    and earlier version, and 2015.006.30464 and earlier have a type confusion vulnerability. Successful
    exploitation could lead to arbitrary code execution . (CVE-2019-7069, CVE-2019-7086, CVE-2019-7087)

  - Adobe Acrobat and Reader versions 2019.010.20069 and earlier, 2019.010.20069 and earlier, 2017.011.30113
    and earlier version, and 2015.006.30464 and earlier have a buffer errors vulnerability. Successful
    exploitation could lead to arbitrary code execution . (CVE-2019-7020, CVE-2019-7085)

  - Adobe Acrobat and Reader versions 2019.010.20069 and earlier, 2019.010.20069 and earlier, 2017.011.30113
    and earlier version, and 2015.006.30464 and earlier have a data leakage (sensitive) vulnerability.
    Successful exploitation could lead to information disclosure. (CVE-2019-7089)

  - Adobe Acrobat and Reader versions 2019.010.20069 and earlier, 2019.010.20069 and earlier, 2017.011.30113
    and earlier version, and 2015.006.30464 and earlier have a double free vulnerability. Successful
    exploitation could lead to arbitrary code execution . (CVE-2019-7080)

  - Adobe Acrobat and Reader versions 2019.010.20069 and earlier, 2019.010.20069 and earlier, 2017.011.30113
    and earlier version, and 2015.006.30464 and earlier have an integer overflow vulnerability. Successful
    exploitation could lead to information disclosure. (CVE-2019-7030)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/acrobat/apsb19-07.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Reader version 2015.006.30475 / 2017.011.30120 / 2019.010.20091 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-7087");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/12");
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
  { 'min_version' : '15.6', 'max_version' : '15.006.30464', 'fixed_version' : '15.006.30475', 'track' : 'DC Classic' },
  { 'min_version' : '17.8', 'max_version' : '17.011.30113', 'fixed_version' : '17.011.30120', 'track' : 'DC Classic' },
  { 'min_version' : '15.7', 'max_version' : '19.010.20069', 'fixed_version' : '19.010.20091', 'track' : 'DC Continuous' }
];
vcf::adobe_acrobat::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    max_segs:3,
    severity:SECURITY_HOLE
);
