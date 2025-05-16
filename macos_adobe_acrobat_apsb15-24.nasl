#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(211676);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/21");

  script_cve_id(
    "CVE-2015-5583",
    "CVE-2015-5586",
    "CVE-2015-6683",
    "CVE-2015-6684",
    "CVE-2015-6685",
    "CVE-2015-6686",
    "CVE-2015-6687",
    "CVE-2015-6688",
    "CVE-2015-6689",
    "CVE-2015-6690",
    "CVE-2015-6691",
    "CVE-2015-6692",
    "CVE-2015-6693",
    "CVE-2015-6694",
    "CVE-2015-6695",
    "CVE-2015-6696",
    "CVE-2015-6697",
    "CVE-2015-6698",
    "CVE-2015-6699",
    "CVE-2015-6700",
    "CVE-2015-6701",
    "CVE-2015-6702",
    "CVE-2015-6703",
    "CVE-2015-6704",
    "CVE-2015-6705",
    "CVE-2015-6706",
    "CVE-2015-6707",
    "CVE-2015-6708",
    "CVE-2015-6709",
    "CVE-2015-6710",
    "CVE-2015-6711",
    "CVE-2015-6712",
    "CVE-2015-6713",
    "CVE-2015-6714",
    "CVE-2015-6715",
    "CVE-2015-6716",
    "CVE-2015-6717",
    "CVE-2015-6718",
    "CVE-2015-6719",
    "CVE-2015-6720",
    "CVE-2015-6721",
    "CVE-2015-6722",
    "CVE-2015-6723",
    "CVE-2015-6724",
    "CVE-2015-6725",
    "CVE-2015-7614",
    "CVE-2015-7615",
    "CVE-2015-7616",
    "CVE-2015-7617",
    "CVE-2015-7618",
    "CVE-2015-7619",
    "CVE-2015-7620",
    "CVE-2015-7621",
    "CVE-2015-7622",
    "CVE-2015-7623",
    "CVE-2015-7624",
    "CVE-2015-7650",
    "CVE-2015-8458"
  );

  script_name(english:"Adobe Acrobat < 10.1.16 / 11.0.13 / 2015.006.30094 / 2015.009.20069 Multiple Vulnerabilities (APSB15-24) (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Acrobat installed on the remote macOS host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Acrobat installed on the remote macOS host is a version prior to 10.1.16, 11.0.13, 2015.006.30094,
or 2015.009.20069. It is, therefore, affected by multiple vulnerabilities.

  - The ANAuthenticateResource method in Adobe Reader and Acrobat 10.x before 10.1.16 and 11.x before 11.0.13,
    Acrobat and Acrobat Reader DC Classic before 2015.006.30094, and Acrobat and Acrobat Reader DC Continuous
    before 2015.009.20069 on Windows and OS X allows attackers to bypass JavaScript API execution restrictions
    via unspecified vectors, a different vulnerability than CVE-2015-6707, CVE-2015-6708, CVE-2015-6709,
    CVE-2015-6710, CVE-2015-6711, CVE-2015-6712, CVE-2015-6713, CVE-2015-6714, CVE-2015-6715, CVE-2015-6716,
    CVE-2015-6717, CVE-2015-6718, CVE-2015-6719, CVE-2015-6720, CVE-2015-6721, CVE-2015-6722, CVE-2015-6723,
    CVE-2015-6724, CVE-2015-6725, CVE-2015-7614, CVE-2015-7616, CVE-2015-7618, CVE-2015-7619, and
    CVE-2015-7620. (CVE-2015-7623)

  - The ANSendForBrowserReview method in Adobe Reader and Acrobat 10.x before 10.1.16 and 11.x before 11.0.13,
    Acrobat and Acrobat Reader DC Classic before 2015.006.30094, and Acrobat and Acrobat Reader DC Continuous
    before 2015.009.20069 on Windows and OS X allows attackers to bypass JavaScript API execution restrictions
    via unspecified vectors, a different vulnerability than CVE-2015-6707, CVE-2015-6708, CVE-2015-6709,
    CVE-2015-6710, CVE-2015-6711, CVE-2015-6712, CVE-2015-6713, CVE-2015-6714, CVE-2015-6715, CVE-2015-6716,
    CVE-2015-6717, CVE-2015-6718, CVE-2015-6719, CVE-2015-6720, CVE-2015-6721, CVE-2015-6722, CVE-2015-6723,
    CVE-2015-6724, CVE-2015-6725, CVE-2015-7614, CVE-2015-7616, CVE-2015-7618, CVE-2015-7619, and
    CVE-2015-7623. (CVE-2015-7620)

  - The ANShareFile2 method in Adobe Reader and Acrobat 10.x before 10.1.16 and 11.x before 11.0.13, Acrobat
    and Acrobat Reader DC Classic before 2015.006.30094, and Acrobat and Acrobat Reader DC Continuous before
    2015.009.20069 on Windows and OS X allows attackers to bypass JavaScript API execution restrictions via
    unspecified vectors, a different vulnerability than CVE-2015-6707, CVE-2015-6708, CVE-2015-6709,
    CVE-2015-6710, CVE-2015-6711, CVE-2015-6712, CVE-2015-6713, CVE-2015-6714, CVE-2015-6715, CVE-2015-6716,
    CVE-2015-6717, CVE-2015-6718, CVE-2015-6719, CVE-2015-6720, CVE-2015-6721, CVE-2015-6722, CVE-2015-6723,
    CVE-2015-6724, CVE-2015-6725, CVE-2015-7614, CVE-2015-7616, CVE-2015-7618, CVE-2015-7620, and
    CVE-2015-7623. (CVE-2015-7619)

  - The CBAutoConfigCommentRepository method in Adobe Reader and Acrobat 10.x before 10.1.16 and 11.x before
    11.0.13, Acrobat and Acrobat Reader DC Classic before 2015.006.30094, and Acrobat and Acrobat Reader DC
    Continuous before 2015.009.20069 on Windows and OS X allows attackers to bypass JavaScript API execution
    restrictions via unspecified vectors, a different vulnerability than CVE-2015-6707, CVE-2015-6708,
    CVE-2015-6709, CVE-2015-6710, CVE-2015-6711, CVE-2015-6712, CVE-2015-6713, CVE-2015-6714, CVE-2015-6715,
    CVE-2015-6716, CVE-2015-6717, CVE-2015-6718, CVE-2015-6719, CVE-2015-6720, CVE-2015-6721, CVE-2015-6722,
    CVE-2015-6723, CVE-2015-6724, CVE-2015-6725, CVE-2015-7614, CVE-2015-7616, CVE-2015-7619, CVE-2015-7620,
    and CVE-2015-7623. (CVE-2015-7618)

  - The ANVerifyComments method in Adobe Reader and Acrobat 10.x before 10.1.16 and 11.x before 11.0.13,
    Acrobat and Acrobat Reader DC Classic before 2015.006.30094, and Acrobat and Acrobat Reader DC Continuous
    before 2015.009.20069 on Windows and OS X allows attackers to bypass JavaScript API execution restrictions
    via unspecified vectors, a different vulnerability than CVE-2015-6707, CVE-2015-6708, CVE-2015-6709,
    CVE-2015-6710, CVE-2015-6711, CVE-2015-6712, CVE-2015-6713, CVE-2015-6714, CVE-2015-6715, CVE-2015-6716,
    CVE-2015-6717, CVE-2015-6718, CVE-2015-6719, CVE-2015-6720, CVE-2015-6721, CVE-2015-6722, CVE-2015-6723,
    CVE-2015-6724, CVE-2015-6725, CVE-2015-7614, CVE-2015-7618, CVE-2015-7619, CVE-2015-7620, and
    CVE-2015-7623. (CVE-2015-7616)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/acrobat/apsb15-24.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Acrobat version 10.1.16 / 11.0.13 / 2015.006.30094 / 2015.009.20069 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-7622");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2015-7623");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/13");
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
  { 'max_version' : '10.1.15', 'fixed_version' : '10.1.16', 'track' : 'DC Continuous' },
  { 'min_version': '11.0.0', 'max_version' : '11.0.12', 'fixed_version' : '11.0.13', 'track' : 'DC Continuous' },
  { 'max_version' : '15.006.30060', 'fixed_version' : '15.006.30094', 'track' : 'DC Classic' },
  { 'min_version' : '15.7', 'max_version' : '15.008.20082', 'fixed_version' : '15.009.20069', 'track' : 'DC Continuous' }
];
vcf::adobe_acrobat::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    max_segs:3,
    severity:SECURITY_HOLE
);
