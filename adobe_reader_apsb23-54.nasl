#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(185553);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/21");

  script_cve_id(
    "CVE-2023-44336",
    "CVE-2023-44337",
    "CVE-2023-44338",
    "CVE-2023-44339",
    "CVE-2023-44340",
    "CVE-2023-44348",
    "CVE-2023-44356",
    "CVE-2023-44357",
    "CVE-2023-44358",
    "CVE-2023-44359",
    "CVE-2023-44360",
    "CVE-2023-44361",
    "CVE-2023-44365",
    "CVE-2023-44366",
    "CVE-2023-44367",
    "CVE-2023-44371",
    "CVE-2023-44372"
  );
  script_xref(name:"IAVA", value:"2023-A-0626-S");

  script_name(english:"Adobe Reader < 20.005.30539 / 23.006.20380 Multiple Vulnerabilities (APSB23-54)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Reader installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Reader installed on the remote Windows host is a version prior to 20.005.30539 or 23.006.20380. It
is, therefore, affected by multiple vulnerabilities.

  - Adobe Acrobat Reader versions 23.006.20360 (and earlier) and 20.005.30524 (and earlier) are affected by a
    Use After Free vulnerability that could result in arbitrary code execution in the context of the current
    user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.
    (CVE-2023-44336, CVE-2023-44359, CVE-2023-44367, CVE-2023-44371, CVE-2023-44372)

  - Adobe Acrobat Reader versions 23.006.20360 (and earlier) and 20.005.30524 (and earlier) are affected by an
    out-of-bounds read vulnerability when parsing a crafted file, which could result in a read past the end of
    an allocated memory structure. An attacker could leverage this vulnerability to execute code in the
    context of the current user. Exploitation of this issue requires user interaction in that a victim must
    open a malicious file. (CVE-2023-44337, CVE-2023-44338)

  - Adobe Acrobat Reader versions 23.006.20360 (and earlier) and 20.005.30524 (and earlier) are affected by an
    Access of Uninitialized Pointer vulnerability that could result in arbitrary code execution in the context
    of the current user. Exploitation of this issue requires user interaction in that a victim must open a
    malicious file. (CVE-2023-44365)

  - Adobe Acrobat Reader versions 23.006.20360 (and earlier) and 20.005.30524 (and earlier) are affected by an
    out-of-bounds write vulnerability that could result in arbitrary code execution in the context of the
    current user. Exploitation of this issue requires user interaction in that a victim must open a malicious
    file. (CVE-2023-44366)

  - Adobe Acrobat Reader versions 23.006.20360 (and earlier) and 20.005.30524 (and earlier) are affected by an
    out-of-bounds read vulnerability that could lead to disclosure of sensitive memory. An attacker could
    leverage this vulnerability to bypass mitigations such as ASLR. Exploitation of this issue requires user
    interaction in that a victim must open a malicious file. (CVE-2023-44339, CVE-2023-44340, CVE-2023-44348,
    CVE-2023-44356, CVE-2023-44357, CVE-2023-44358, CVE-2023-44360)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/acrobat/apsb23-54.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Reader version 20.005.30539 / 23.006.20380 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-44372");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(125, 416, 787, 824);

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat_reader");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_reader_installed.nasl");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/Adobe Reader");

  exit(0);
}

include('vcf_extras.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');
var app_info = vcf::get_app_info(app:'Adobe Reader', win_local:TRUE);

# vcf::adobe_reader::check_version_and_report will
# properly separate tracks when checking constraints.
# x.y.30zzz = DC Classic
# x.y.20zzz = DC Continuous
var constraints = [
  { 'min_version' : '20.1', 'max_version' : '20.005.30524', 'fixed_version' : '20.005.30539', 'track' : 'DC Classic' },
  { 'min_version' : '15.7', 'max_version' : '23.006.20360', 'fixed_version' : '23.006.20380', 'track' : 'DC Continuous' }
];
vcf::adobe_acrobat::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    max_segs:3,
    severity:SECURITY_HOLE
);
