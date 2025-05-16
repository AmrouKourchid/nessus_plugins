#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(209344);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/21");

  script_cve_id(
    "CVE-2017-2939",
    "CVE-2017-2940",
    "CVE-2017-2941",
    "CVE-2017-2942",
    "CVE-2017-2943",
    "CVE-2017-2944",
    "CVE-2017-2945",
    "CVE-2017-2946",
    "CVE-2017-2947",
    "CVE-2017-2948",
    "CVE-2017-2949",
    "CVE-2017-2950",
    "CVE-2017-2951",
    "CVE-2017-2952",
    "CVE-2017-2953",
    "CVE-2017-2954",
    "CVE-2017-2955",
    "CVE-2017-2956",
    "CVE-2017-2957",
    "CVE-2017-2958",
    "CVE-2017-2959",
    "CVE-2017-2960",
    "CVE-2017-2961",
    "CVE-2017-2962",
    "CVE-2017-2963",
    "CVE-2017-2964",
    "CVE-2017-2965",
    "CVE-2017-2966",
    "CVE-2017-2967",
    "CVE-2017-2970",
    "CVE-2017-2971",
    "CVE-2017-2972",
    "CVE-2017-3009",
    "CVE-2017-3010"
  );

  script_name(english:"Adobe Reader < 15.006.30279 / 15.023.20053 Multiple Vulnerabilities (APSB17-01) (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Reader installed on the remote macOS host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Reader installed on the remote macOS host is a version prior to 15.006.30279 or 15.023.20053. It
is, therefore, affected by multiple vulnerabilities.

  - Adobe Acrobat Reader versions 15.020.20042 and earlier, 15.006.30244 and earlier, 11.0.18 and earlier have
    an exploitable memory corruption vulnerability in the rendering engine. Successful exploitation could lead
    to arbitrary code execution. (CVE-2017-3010)

  - Adobe Acrobat Reader versions 15.020.20042 and earlier, 15.006.30244 and earlier, 11.0.18 and earlier have
    an exploitable type confusion vulnerability in the XSLT engine related to localization functionality.
    Successful exploitation could lead to arbitrary code execution. (CVE-2017-2962)

  - Adobe Acrobat Reader versions 15.020.20042 and earlier, 15.006.30244 and earlier, 11.0.18 and earlier have
    an exploitable use after free vulnerability in the XFA engine, related to layout functionality. Successful
    exploitation could lead to arbitrary code execution. (CVE-2017-2950)

  - Adobe Acrobat Reader versions 15.020.20042 and earlier, 15.006.30244 and earlier, 11.0.18 and earlier have
    an exploitable use after free vulnerability in the XFA engine, related to sub-form functionality.
    Successful exploitation could lead to arbitrary code execution. (CVE-2017-2951)

  - Adobe Acrobat Reader versions 15.020.20042 and earlier, 15.006.30244 and earlier, 11.0.18 and earlier have
    an exploitable use after free vulnerability in the JavaScript engine. Successful exploitation could lead
    to arbitrary code execution. (CVE-2017-2955, CVE-2017-2958)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/acrobat/apsb17-01.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Reader version 15.006.30279 / 15.023.20053 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-3010");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/05");
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
  { 'max_version' : '15.006.30244', 'fixed_version' : '15.006.30279', 'track' : 'DC Classic' },
  { 'min_version' : '15.7', 'max_version' : '15.020.20042', 'fixed_version' : '15.023.20053', 'track' : 'DC Continuous' }
];
vcf::adobe_acrobat::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    max_segs:3,
    severity:SECURITY_HOLE
);
