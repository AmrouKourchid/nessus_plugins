#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(190455);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/10");

  script_cve_id(
    "CVE-2024-20726",
    "CVE-2024-20727",
    "CVE-2024-20728",
    "CVE-2024-20729",
    "CVE-2024-20730",
    "CVE-2024-20731",
    "CVE-2024-20733",
    "CVE-2024-20734",
    "CVE-2024-20735",
    "CVE-2024-20736",
    "CVE-2024-20747",
    "CVE-2024-20748",
    "CVE-2024-20749",
    "CVE-2024-20765",
    "CVE-2024-30301",
    "CVE-2024-30302",
    "CVE-2024-30303",
    "CVE-2024-30304",
    "CVE-2024-30305",
    "CVE-2024-30306"
  );
  script_xref(name:"IAVA", value:"2024-A-0087-S");

  script_name(english:"Adobe Reader < 20.005.30574 / 23.008.20533 Multiple Vulnerabilities (APSB24-07) (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Reader installed on the remote macOS host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Reader installed on the remote macOS host is a version prior to 20.005.30574 or 23.008.20533. It
is, therefore, affected by multiple vulnerabilities.

  - Acrobat Reader versions 20.005.30539, 23.008.20470 and earlier are affected by an out-of-bounds read
    vulnerability when parsing a crafted file, which could result in a read past the end of an allocated
    memory structure. An attacker could leverage this vulnerability to execute code in the context of the
    current user. Exploitation of this issue requires user interaction in that a victim must open a malicious
    file. (CVE-2024-30306)

  - Acrobat Reader versions 20.005.30539, 23.008.20470 and earlier are affected by an out-of-bounds write
    vulnerability that could result in arbitrary code execution in the context of the current user.
    Exploitation of this issue requires user interaction in that a victim must open a malicious file.
    (CVE-2024-20726, CVE-2024-20727, CVE-2024-20728)

  - Acrobat Reader versions 20.005.30539, 23.008.20470 and earlier are affected by a Use After Free
    vulnerability that could result in arbitrary code execution in the context of the current user.
    Exploitation of this issue requires user interaction in that a victim must open a malicious file.
    (CVE-2024-20729, CVE-2024-20731, CVE-2024-20765, CVE-2024-30301, CVE-2024-30303, CVE-2024-30304,
    CVE-2024-30305)

  - Acrobat Reader versions 20.005.30539, 23.008.20470 and earlier are affected by an Integer Overflow or
    Wraparound vulnerability that could result in arbitrary code execution in the context of the current user.
    Exploitation of this issue requires user interaction in that a victim must open a malicious file.
    (CVE-2024-20730)

  - Acrobat Reader versions 20.005.30539, 23.008.20470 and earlier are affected by a Use After Free
    vulnerability that could lead to disclosure of sensitive memory. An attacker could leverage this
    vulnerability to bypass mitigations such as ASLR. Exploitation of this issue requires user interaction in
    that a victim must open a malicious file. (CVE-2024-20734, CVE-2024-30302)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/acrobat/apsb24-07.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Reader version 20.005.30574 / 23.008.20533 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20731");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(125, 190, 20, 416, 787);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat_reader");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'min_version' : '20.1', 'max_version' : '20.005.30539', 'fixed_version' : '20.005.30574', 'track' : 'DC Classic' },
  { 'min_version' : '15.7', 'max_version' : '23.008.20470', 'fixed_version' : '23.008.20533', 'track' : 'DC Continuous' }
];
vcf::adobe_acrobat::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    max_segs:3,
    severity:SECURITY_HOLE
);
