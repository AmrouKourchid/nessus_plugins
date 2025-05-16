#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(216082);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/09");

  script_cve_id(
    "CVE-2025-21121",
    "CVE-2025-21123",
    "CVE-2025-21124",
    "CVE-2025-21125",
    "CVE-2025-21126",
    "CVE-2025-21157",
    "CVE-2025-21158"
  );
  script_xref(name:"IAVA", value:"2025-A-0089-S");

  script_name(english:"Adobe InDesign < 19.5.2 / 20.0 < 20.1.0 Multiple Vulnerabilities (APSB25-01)");

  script_set_attribute(attribute:"synopsis", value:
"The Adobe InDesign instance installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe InDesign installed on the remote Windows host is prior to 19.5.2, 20.1.0. It is, therefore,
affected by multiple vulnerabilities as referenced in the APSB25-01 advisory.

  - InDesign Desktop versions ID20.0, ID19.5.1 and earlier are affected by an Integer Underflow (Wrap or
    Wraparound) vulnerability that could result in arbitrary code execution in the context of the current
    user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.
    (CVE-2025-21158)

  - InDesign Desktop versions ID20.0, ID19.5.1 and earlier are affected by an out-of-bounds write
    vulnerability that could result in arbitrary code execution in the context of the current user.
    Exploitation of this issue requires user interaction in that a victim must open a malicious file.
    (CVE-2025-21121, CVE-2025-21157)

  - InDesign Desktop versions ID20.0, ID19.5.1 and earlier are affected by a Heap-based Buffer Overflow
    vulnerability that could result in arbitrary code execution in the context of the current user.
    Exploitation of this issue requires user interaction in that a victim must open a malicious file.
    (CVE-2025-21123)

  - InDesign Desktop versions ID20.0, ID19.5.1 and earlier are affected by an out-of-bounds read vulnerability
    that could lead to disclosure of sensitive memory. An attacker could leverage this vulnerability to bypass
    mitigations such as ASLR. Exploitation of this issue requires user interaction in that a victim must open
    a malicious file. (CVE-2025-21124)

  - InDesign Desktop versions ID20.0, ID19.5.1 and earlier are affected by a NULL Pointer Dereference
    vulnerability that could result in an application denial-of-service. An attacker could exploit this
    vulnerability to crash the application, leading to a denial-of-service condition. Exploitation of this
    issue requires user interaction in that a victim must open a malicious file. (CVE-2025-21125)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/indesign/apsb25-01.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe InDesign version 19.5.2, 20.1.0 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-21158");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(122, 125, 191, 20, 476, 787);

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/02/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:indesign");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_indesign_installed.nbin");
  script_require_keys("installed_sw/Adobe InDesign", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Adobe InDesign', win_local:TRUE);

var constraints = [
  { 'max_version' : '19.5.1', 'fixed_version' : '19.5.2', 'fixed_display' : 'ID19.5.2' },
  { 'min_version' : '20.0', 'fixed_version' : '20.1.0', 'fixed_display' : 'ID20.1' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
