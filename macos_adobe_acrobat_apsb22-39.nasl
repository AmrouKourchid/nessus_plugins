##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(163957);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/21");

  script_cve_id(
    "CVE-2022-35665",
    "CVE-2022-35666",
    "CVE-2022-35667",
    "CVE-2022-35668",
    "CVE-2022-35670",
    "CVE-2022-35671",
    "CVE-2022-35678"
  );
  script_xref(name:"IAVA", value:"2022-A-0323-S");

  script_name(english:"Adobe Acrobat < 17.012.30262 / 20.005.30381 / 22.002.20191 Multiple Vulnerabilities (APSB22-39) (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Acrobat installed on the remote macOS host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Acrobat installed on the remote macOS host is a version prior to 17.012.30262, 20.005.30381, or
22.002.20191. It is, therefore, affected by multiple vulnerabilities.

  - Adobe Acrobat Reader versions 22.001.20169 (and earlier), 20.005.30362 (and earlier) and 17.012.30249 (and
    earlier) are affected by an out-of-bounds write vulnerability that could result in arbitrary code
    execution in the context of the current user. Exploitation of this issue requires user interaction in that
    a victim must open a malicious file. (CVE-2022-35667)

  - Adobe Acrobat Reader versions 22.001.20169 (and earlier), 20.005.30362 (and earlier) and 17.012.30249 (and
    earlier) are affected by a Use After Free vulnerability that could result in arbitrary code execution in
    the context of the current user. Exploitation of this issue requires user interaction in that a victim
    must open a malicious file. (CVE-2022-35665)

  - Adobe Acrobat Reader versions 22.001.20169 (and earlier), 20.005.30362 (and earlier) and 17.012.30249 (and
    earlier) are affected by an Improper Input Validation vulnerability that could result in arbitrary code
    execution in the context of the current user. Exploitation of this issue requires user interaction in that
    a victim must open a malicious file. (CVE-2022-35666)

  - Adobe Acrobat Reader versions 22.001.20169 (and earlier), 20.005.30362 (and earlier) and 17.012.30249 (and
    earlier) are affected by an Improper Input Validation vulnerability that could lead to disclosure of
    sensitive memory. An attacker could leverage this vulnerability to bypass mitigations such as ASLR.
    Exploitation of this issue requires user interaction in that a victim must open a malicious file.
    (CVE-2022-35668)

  - Adobe Acrobat Reader versions 22.001.20169 (and earlier), 20.005.30362 (and earlier) and 17.012.30249 (and
    earlier) are affected by a Use After Free vulnerability that could lead to disclosure of sensitive memory.
    An attacker could leverage this vulnerability to bypass mitigations such as ASLR. Exploitation of this
    issue requires user interaction in that a victim must open a malicious file. (CVE-2022-35670)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/acrobat/apsb22-39.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Acrobat version 17.012.30262 / 20.005.30381 / 22.002.20191 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-35667");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 125, 416, 787);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'min_version' : '17.8', 'max_version' : '17.012.30249', 'fixed_version' : '17.012.30262', 'track' : 'DC Classic' },
  { 'min_version' : '20.1', 'max_version' : '20.005.30362', 'fixed_version' : '20.005.30381', 'track' : 'DC Classic' },
  { 'min_version' : '15.7', 'max_version' : '22.001.20169', 'fixed_version' : '22.002.20191', 'track' : 'DC Continuous' }
];
vcf::adobe_acrobat::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    max_segs:3,
    severity:SECURITY_HOLE
);
