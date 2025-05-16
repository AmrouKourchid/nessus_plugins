#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(179482);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/21");

  script_cve_id(
    "CVE-2023-29299",
    "CVE-2023-29303",
    "CVE-2023-29320",
    "CVE-2023-38222",
    "CVE-2023-38223",
    "CVE-2023-38224",
    "CVE-2023-38225",
    "CVE-2023-38226",
    "CVE-2023-38227",
    "CVE-2023-38228",
    "CVE-2023-38229",
    "CVE-2023-38230",
    "CVE-2023-38231",
    "CVE-2023-38232",
    "CVE-2023-38233",
    "CVE-2023-38234",
    "CVE-2023-38235",
    "CVE-2023-38236",
    "CVE-2023-38237",
    "CVE-2023-38238",
    "CVE-2023-38239",
    "CVE-2023-38240",
    "CVE-2023-38241",
    "CVE-2023-38242",
    "CVE-2023-38243",
    "CVE-2023-38244",
    "CVE-2023-38245",
    "CVE-2023-38246",
    "CVE-2023-38247",
    "CVE-2023-38248"
  );
  script_xref(name:"IAVA", value:"2023-A-0413-S");

  script_name(english:"Adobe Acrobat < 20.005.30514.10514 / 23.003.20269 Multiple Vulnerabilities (APSB23-30)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Acrobat installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Acrobat installed on the remote Windows host is a version prior to 20.005.30514.10514 or
23.003.20269. It is, therefore, affected by multiple vulnerabilities.

  - Adobe Acrobat Reader versions 23.003.20244 (and earlier) and 20.005.30467 (and earlier) are affected by an
    Access of Uninitialized Pointer vulnerability that could result in arbitrary code execution in the context
    of the current user. Exploitation of this issue requires user interaction in that a victim must open a
    malicious file. (CVE-2023-38226, CVE-2023-38234, CVE-2023-38246)

  - Adobe Acrobat Reader versions 23.003.20244 (and earlier) and 20.005.30467 (and earlier) are affected by an
    Violation of Secure Design Principles vulnerability that could result in arbitrary code execution in the
    context of the current user by bypassing the API blacklisting feature. Exploitation of this issue requires
    user interaction in that a victim must open a malicious file. (CVE-2023-29320)

  - Adobe Acrobat Reader versions 23.003.20244 (and earlier) and 20.005.30467 (and earlier) are affected by an
    Untrusted Search Path vulnerability that could lead to Application denial-of-service. An attacker could
    leverage this vulnerability if the default PowerShell Set-ExecutionPolicy is set to Unrestricted, making
    the attack complexity high. Exploitation of this issue requires user interaction in that a victim must
    open a malicious file. (CVE-2023-29299)

  - Adobe Acrobat Reader versions 23.003.20244 (and earlier) and 20.005.30467 (and earlier) are affected by a
    Use After Free vulnerability that could lead to disclosure of sensitive memory. An attacker could leverage
    this vulnerability to bypass mitigations such as ASLR. Exploitation of this issue requires user
    interaction in that a victim must open a malicious file. (CVE-2023-29303)

  - Adobe Acrobat Reader versions 23.003.20244 (and earlier) and 20.005.30467 (and earlier) are affected by a
    Use After Free vulnerability that could result in arbitrary code execution in the context of the current
    user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.
    (CVE-2023-38222, CVE-2023-38224, CVE-2023-38225, CVE-2023-38227, CVE-2023-38228)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/acrobat/apsb23-30.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Acrobat version 20.005.30514.10514 / 23.003.20269 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-38246");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(125, 20, 284, 416, 787, 824);

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'min_version' : '20.1', 'max_version' : '20.005.30467', 'fixed_version' : '20.005.30514', 'fixed_display' : '20.005.30514.10514 / 20.005.30516.10516', 'track' : 'DC Classic' },
  { 'min_version' : '15.7', 'max_version' : '23.003.20244', 'fixed_version' : '23.003.20269', 'track' : 'DC Continuous' }
];
vcf::adobe_acrobat::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    max_segs:3,
    severity:SECURITY_HOLE
);
