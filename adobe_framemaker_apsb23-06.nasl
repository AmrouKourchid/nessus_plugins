#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(171548);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/20");

  script_cve_id(
    "CVE-2023-21584",
    "CVE-2023-21619",
    "CVE-2023-21620",
    "CVE-2023-21621",
    "CVE-2023-21622"
  );
  script_xref(name:"IAVB", value:"2023-B-0010-S");

  script_name(english:"Adobe FrameMaker 2020 < 16.0.5 (2020.0.5) / Adobe FrameMaker 2022 < 17.0.1 (2022.0.1) Multiple Vulnerabilities (APSB23-06)");

  script_set_attribute(attribute:"synopsis", value:
"The remote install of Adobe FrameMaker has multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe FrameMaker installed on the remote Windows host is prior to Adobe FrameMaker 2020 16.0.5 / Adobe
FrameMaker 2022 17.0.1. It is, therefore, affected by multiple vulnerabilities as referenced in the apsb23-06 advisory.

  - FrameMaker 2020 Update 4 (and earlier), 2022 (and earlier) are affected by an out-of-bounds write
    vulnerability that could result in arbitrary code execution in the context of the current user.
    Exploitation of this issue requires user interaction in that a victim must open a malicious file.
    (CVE-2023-21619, CVE-2023-21622)

  - FrameMaker 2020 Update 4 (and earlier), 2022 (and earlier) are affected by a Use After Free vulnerability
    that could lead to disclosure of sensitive memory. An attacker could leverage this vulnerability to bypass
    mitigations such as ASLR. Exploitation of this issue requires user interaction in that a victim must open
    a malicious file. (CVE-2023-21584)

  - FrameMaker 2020 Update 4 (and earlier), 2022 (and earlier) are affected by an out-of-bounds read
    vulnerability that could lead to disclosure of sensitive memory. An attacker could leverage this
    vulnerability to bypass mitigations such as ASLR. Exploitation of this issue requires user interaction in
    that a victim must open a malicious file. (CVE-2023-21620)

  - FrameMaker 2020 Update 4 (and earlier), 2022 (and earlier) are affected by an Improper Input Validation
    vulnerability that could result in arbitrary code execution in the context of the current user.
    Exploitation of this issue requires user interaction in that a victim must open a malicious file.
    (CVE-2023-21621)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/framemaker/apsb23-06.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe FrameMaker FrameMaker 2020 Update 5, FrameMaker 2022 Update 1 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-21622");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 125, 416, 787);

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:framemaker");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_framemaker_installed.nbin");
  script_require_keys("installed_sw/Adobe FrameMaker", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Adobe FrameMaker', win_local:TRUE);

var constraints = [
  { 'fixed_version' : '16.0.5', 'fixed_display' : '16.0.5 / 2020.0.5 / FrameMaker 2020 Update 5' },
  { 'fixed_version' : '17.0.1', 'equal' : '17.0.0', 'fixed_display' : '17.0.1 / 2022.0.1 / FrameMaker 2022 Update 1' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
