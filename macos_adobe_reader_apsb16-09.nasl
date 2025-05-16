#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(209366);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/20");

  script_cve_id("CVE-2016-1007", "CVE-2016-1008", "CVE-2016-1009");

  script_name(english:"Adobe Reader < 15.006.30121 / 15.010.20060 Multiple Vulnerabilities (APSB16-09) (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Reader installed on the remote macOS host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Reader installed on the remote macOS host is a version prior to 15.006.30121 or 15.010.20060. It
is, therefore, affected by multiple vulnerabilities.

  - Adobe Reader and Acrobat before 11.0.15, Acrobat and Acrobat Reader DC Classic before 15.006.30121, and
    Acrobat and Acrobat Reader DC Continuous before 15.010.20060 on Windows and OS X allow attackers to
    execute arbitrary code or cause a denial of service (memory corruption) via unspecified vectors, a
    different vulnerability than CVE-2016-1007. (CVE-2016-1009)

  - Adobe Reader and Acrobat before 11.0.15, Acrobat and Acrobat Reader DC Classic before 15.006.30121, and
    Acrobat and Acrobat Reader DC Continuous before 15.010.20060 on Windows and OS X allow attackers to
    execute arbitrary code or cause a denial of service (memory corruption) via unspecified vectors, a
    different vulnerability than CVE-2016-1009. (CVE-2016-1007)

  - Untrusted search path vulnerability in Adobe Reader and Acrobat before 11.0.15, Acrobat and Acrobat Reader
    DC Classic before 15.006.30121, and Acrobat and Acrobat Reader DC Continuous before 15.010.20060 on
    Windows and OS X allows local users to gain privileges via a Trojan horse DLL in an unspecified directory.
    (CVE-2016-1008)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/acrobat/apsb16-09.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Reader version 15.006.30121 / 15.010.20060 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-1009");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/21");

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
  { 'max_version' : '15.006.30119', 'fixed_version' : '15.006.30121', 'track' : 'DC Classic' },
  { 'min_version' : '15.7', 'max_version' : '15.010.20059', 'fixed_version' : '15.010.20060', 'track' : 'DC Continuous' }
];
vcf::adobe_acrobat::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    max_segs:3,
    severity:SECURITY_HOLE
);
