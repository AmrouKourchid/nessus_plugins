#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(197029);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/03");

  script_cve_id(
    "CVE-2024-30279",
    "CVE-2024-30280",
    "CVE-2024-30284",
    "CVE-2024-30310",
    "CVE-2024-30311",
    "CVE-2024-30312",
    "CVE-2024-34094",
    "CVE-2024-34095",
    "CVE-2024-34096",
    "CVE-2024-34097",
    "CVE-2024-34098",
    "CVE-2024-34099",
    "CVE-2024-34100",
    "CVE-2024-34101"
  );
  script_xref(name:"IAVA", value:"2024-A-0288-S");

  script_name(english:"Adobe Acrobat < 20.005.30635 / 24.002.20759 Multiple Vulnerabilities (APSB24-29)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Acrobat installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Acrobat installed on the remote Windows host is a version prior to 20.005.30635 or 24.002.20759. It
is, therefore, affected by multiple vulnerabilities.

  - Acrobat Reader versions 20.005.30574, 24.002.20736 and earlier are affected by a Use After Free
    vulnerability that could result in arbitrary code execution in the context of the current user.
    Exploitation of this issue requires user interaction in that a victim must open a malicious file.
    (CVE-2024-30284, CVE-2024-34094, CVE-2024-34095, CVE-2024-34096, CVE-2024-34097, CVE-2024-34100)

  - Acrobat Reader versions 20.005.30574, 24.002.20736 and earlier are affected by an out-of-bounds write
    vulnerability that could result in arbitrary code execution in the context of the current user.
    Exploitation of this issue requires user interaction in that a victim must open a malicious file.
    (CVE-2024-30279, CVE-2024-30310)

  - Acrobat Reader versions 20.005.30574, 24.002.20736 and earlier are affected by an out-of-bounds read
    vulnerability when parsing a crafted file, which could result in a read past the end of an allocated
    memory structure. An attacker could leverage this vulnerability to execute code in the context of the
    current user. Exploitation of this issue requires user interaction in that a victim must open a malicious
    file. (CVE-2024-30280)

  - Acrobat Reader versions 20.005.30574, 24.002.20736 and earlier are affected by an Improper Input
    Validation vulnerability that could result in arbitrary code execution in the context of the current user.
    Exploitation of this issue requires user interaction in that a victim must open a malicious file.
    (CVE-2024-34098)

  - Acrobat Reader versions 20.005.30574, 24.002.20736 and earlier are affected by an Improper Access Control
    vulnerability that could result in arbitrary code execution in the context of the current user.
    Exploitation of this issue requires user interaction in that a victim must open a malicious file.
    (CVE-2024-34099)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/acrobat/apsb24-29.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Acrobat version 20.005.30635 / 24.002.20759 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-34097");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(125, 20, 284, 416, 787);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_acrobat_installed.nasl");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/Adobe Acrobat");

  exit(0);
}

include('vcf_extras.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');
var app_info = vcf::get_app_info(app:'Adobe Acrobat', win_local:TRUE);

# vcf::adobe_reader::check_version_and_report will
# properly separate tracks when checking constraints.
# x.y.30zzz = DC Classic
# x.y.20zzz = DC Continuous
var constraints = [
  { 'min_version' : '20.1', 'max_version' : '20.005.30574', 'fixed_version' : '20.005.30635', 'fixed_display' : '20.005.30635 / 20.005.30636', 'track' : 'DC Classic' },
  { 'min_version' : '15.7', 'max_version' : '24.002.20736', 'fixed_version' : '24.002.20759', 'track' : 'DC Continuous' }
];
vcf::adobe_acrobat::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    max_segs:3,
    severity:SECURITY_HOLE
);
