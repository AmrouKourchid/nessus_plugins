##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(142465);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/20");

  script_cve_id(
    "CVE-2020-24426",
    "CVE-2020-24427",
    "CVE-2020-24428",
    "CVE-2020-24429",
    "CVE-2020-24430",
    "CVE-2020-24431",
    "CVE-2020-24432",
    "CVE-2020-24433",
    "CVE-2020-24434",
    "CVE-2020-24435",
    "CVE-2020-24436",
    "CVE-2020-24437",
    "CVE-2020-24438",
    "CVE-2020-24439"
  );
  script_xref(name:"IAVA", value:"2020-A-0506-S");

  script_name(english:"Adobe Reader < 2017.011.30180 / 2020.001.30010 / 2020.013.20064 Multiple Vulnerabilities (APSB20-67) (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Reader installed on the remote macOS host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Reader installed on the remote macOS host is a version prior to 2017.011.30180, 2020.001.30010, or
2020.013.20064. It is, therefore, affected by multiple vulnerabilities.

  - Acrobat Reader DC versions 2020.012.20048 (and earlier), 2020.001.30005 (and earlier) and 2017.011.30175
    (and earlier) are affected by a use-after-free vulnerability in the processing of Format event actions
    that could result in arbitrary code execution in the context of the current user. Exploitation of this
    issue requires user interaction in that a victim must open a malicious file. (CVE-2020-24437)

  - Adobe Acrobat Reader DC versions 2020.012.20048 (and earlier), 2020.001.30005 (and earlier) and
    2017.011.30175 (and earlier) are affected by a local privilege escalation vulnerability that could enable
    a user without administrator privileges to delete arbitrary files and potentially execute arbitrary code
    as SYSTEM. Exploitation of this issue requires an attacker to socially engineer a victim, or the attacker
    must already have some access to the environment. (CVE-2020-24433)

  - Acrobat Reader DC versions 2020.012.20048 (and earlier), 2020.001.30005 (and earlier) and 2017.011.30175
    (and earlier) are affected by a heap-based buffer overflow vulnerability in the submitForm function,
    potentially resulting in arbitrary code execution in the context of the current user. Exploitation
    requires user interaction in that a victim must open a crafted .pdf file in Acrobat Reader.
    (CVE-2020-24435)

  - Acrobat Reader DC versions 2020.012.20048 (and earlier), 2020.001.30005 (and earlier) and 2017.011.30175
    (and earlier) and Adobe Acrobat Pro DC 2017.011.30175 (and earlier) are affected by an improper input
    validation vulnerability that could result in arbitrary JavaScript execution in the context of the current
    user. To exploit this issue, an attacker must acquire and then modify a certified PDF document that is
    trusted by the victim. The attacker then needs to convince the victim to open the document.
    (CVE-2020-24432)

  - Acrobat Reader DC for macOS versions 2020.012.20048 (and earlier), 2020.001.30005 (and earlier) and
    2017.011.30175 (and earlier) are affected by a security feature bypass. While the practical security
    impact is minimal, a defense-in-depth fix has been implemented to further harden the Adobe Reader update
    process. (CVE-2020-24439)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/acrobat/apsb20-67.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Reader version 2017.011.30180 / 2020.001.30010 / 2020.013.20064 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-24433");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-24437");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/05");

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
  { 'min_version' : '17.8', 'max_version' : '17.011.30175', 'fixed_version' : '17.011.30180', 'track' : 'DC Classic' },
  { 'min_version' : '20.1', 'max_version' : '20.001.30005', 'fixed_version' : '20.001.30010', 'track' : 'DC Classic' },
  { 'min_version' : '15.7', 'max_version' : '20.012.20048', 'fixed_version' : '20.013.20064', 'track' : 'DC Continuous' }
];
vcf::adobe_acrobat::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    max_segs:3,
    severity:SECURITY_HOLE
);
