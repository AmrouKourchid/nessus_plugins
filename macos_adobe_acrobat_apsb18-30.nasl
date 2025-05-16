#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(207081);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/20");

  script_cve_id(
    "CVE-2018-12759",
    "CVE-2018-12769",
    "CVE-2018-12831",
    "CVE-2018-12832",
    "CVE-2018-12833",
    "CVE-2018-12834",
    "CVE-2018-12835",
    "CVE-2018-12836",
    "CVE-2018-12837",
    "CVE-2018-12838",
    "CVE-2018-12839",
    "CVE-2018-12841",
    "CVE-2018-12842",
    "CVE-2018-12843",
    "CVE-2018-12844",
    "CVE-2018-12845",
    "CVE-2018-12846",
    "CVE-2018-12847",
    "CVE-2018-12851",
    "CVE-2018-12852",
    "CVE-2018-12853",
    "CVE-2018-12855",
    "CVE-2018-12856",
    "CVE-2018-12857",
    "CVE-2018-12858",
    "CVE-2018-12859",
    "CVE-2018-12860",
    "CVE-2018-12861",
    "CVE-2018-12862",
    "CVE-2018-12863",
    "CVE-2018-12864",
    "CVE-2018-12865",
    "CVE-2018-12866",
    "CVE-2018-12867",
    "CVE-2018-12868",
    "CVE-2018-12869",
    "CVE-2018-12870",
    "CVE-2018-12871",
    "CVE-2018-12872",
    "CVE-2018-12873",
    "CVE-2018-12874",
    "CVE-2018-12875",
    "CVE-2018-12876",
    "CVE-2018-12877",
    "CVE-2018-12878",
    "CVE-2018-12879",
    "CVE-2018-12880",
    "CVE-2018-12881",
    "CVE-2018-15920",
    "CVE-2018-15921",
    "CVE-2018-15922",
    "CVE-2018-15923",
    "CVE-2018-15924",
    "CVE-2018-15925",
    "CVE-2018-15926",
    "CVE-2018-15927",
    "CVE-2018-15928",
    "CVE-2018-15929",
    "CVE-2018-15930",
    "CVE-2018-15931",
    "CVE-2018-15932",
    "CVE-2018-15933",
    "CVE-2018-15934",
    "CVE-2018-15935",
    "CVE-2018-15936",
    "CVE-2018-15937",
    "CVE-2018-15938",
    "CVE-2018-15939",
    "CVE-2018-15940",
    "CVE-2018-15941",
    "CVE-2018-15942",
    "CVE-2018-15943",
    "CVE-2018-15944",
    "CVE-2018-15945",
    "CVE-2018-15946",
    "CVE-2018-15947",
    "CVE-2018-15948",
    "CVE-2018-15949",
    "CVE-2018-15950",
    "CVE-2018-15951",
    "CVE-2018-15952",
    "CVE-2018-15953",
    "CVE-2018-15954",
    "CVE-2018-15955",
    "CVE-2018-15956",
    "CVE-2018-15966",
    "CVE-2018-15968",
    "CVE-2018-15977",
    "CVE-2018-19722"
  );

  script_name(english:"Adobe Acrobat < 2015.006.30456 / 2017.011.30105 / 2019.008.20071 Multiple Vulnerabilities (APSB18-30) (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Acrobat installed on the remote macOS host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Acrobat installed on the remote macOS host is a version prior to 2015.006.30456, 2017.011.30105, or
2019.008.20071. It is, therefore, affected by multiple vulnerabilities.

  - Adobe Acrobat and Reader versions 2018.011.20063 and earlier, 2017.011.30102 and earlier, and
    2015.006.30452 and earlier have a security bypass vulnerability. Successful exploitation could lead to
    privilege escalation. (CVE-2018-15966)

  - Adobe Acrobat and Reader versions 2018.011.20063 and earlier, 2017.011.30102 and earlier, and
    2015.006.30452 and earlier have an out-of-bounds write vulnerability. Successful exploitation could lead
    to arbitrary code execution. (CVE-2018-12759, CVE-2018-12860, CVE-2018-12861, CVE-2018-12862,
    CVE-2018-12864, CVE-2018-12865, CVE-2018-12868, CVE-2018-15928, CVE-2018-15929, CVE-2018-15933,
    CVE-2018-15934, CVE-2018-15935, CVE-2018-15936, CVE-2018-15938, CVE-2018-15939, CVE-2018-15940,
    CVE-2018-15941, CVE-2018-15944, CVE-2018-15945, CVE-2018-15952, CVE-2018-15954, CVE-2018-15955)

  - Adobe Acrobat and Reader versions 2018.011.20063 and earlier, 2017.011.30102 and earlier, and
    2015.006.30452 and earlier have an out-of-bounds read vulnerability. Successful exploitation could lead to
    information disclosure. (CVE-2018-12834, CVE-2018-12839, CVE-2018-12843, CVE-2018-12844, CVE-2018-12845,
    CVE-2018-12856, CVE-2018-12857, CVE-2018-12859, CVE-2018-12866, CVE-2018-12867, CVE-2018-12869,
    CVE-2018-12870, CVE-2018-12871, CVE-2018-12872, CVE-2018-12873, CVE-2018-12874, CVE-2018-12875,
    CVE-2018-12878, CVE-2018-12879, CVE-2018-12880, CVE-2018-15922, CVE-2018-15923, CVE-2018-15925,
    CVE-2018-15926, CVE-2018-15927, CVE-2018-15932, CVE-2018-15942, CVE-2018-15943, CVE-2018-15946,
    CVE-2018-15947, CVE-2018-15948, CVE-2018-15949, CVE-2018-15950, CVE-2018-15953, CVE-2018-15956,
    CVE-2018-15968, CVE-2018-19722)

  - Rejected reason: DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason: The CNA or individual who
    requested this candidate did not associate it with any vulnerability during 2018. Notes: none
    (CVE-2018-15921, CVE-2018-15977)

  - Adobe Acrobat and Reader versions 2018.011.20063 and earlier, 2017.011.30102 and earlier, and
    2015.006.30452 and earlier have a heap overflow vulnerability. Successful exploitation could lead to
    arbitrary code execution. (CVE-2018-12832, CVE-2018-12833, CVE-2018-12836, CVE-2018-12837, CVE-2018-12846,
    CVE-2018-12847, CVE-2018-12851)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/acrobat/apsb18-30.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Acrobat version 2015.006.30456 / 2017.011.30105 / 2019.008.20071 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-15966");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/12");

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
  { 'min_version' : '15.6', 'max_version' : '15.006.30452', 'fixed_version' : '15.006.30456', 'track' : 'DC Classic' },
  { 'min_version' : '17.8', 'max_version' : '17.011.30102', 'fixed_version' : '17.011.30105', 'track' : 'DC Classic' },
  { 'min_version' : '15.7', 'max_version' : '18.011.20063', 'fixed_version' : '19.008.20071', 'track' : 'DC Continuous' }
];
vcf::adobe_acrobat::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    max_segs:3,
    severity:SECURITY_HOLE
);
