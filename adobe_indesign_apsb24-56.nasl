#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(205432);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/11");

  script_cve_id(
    "CVE-2024-34127",
    "CVE-2024-39389",
    "CVE-2024-39390",
    "CVE-2024-39391",
    "CVE-2024-39393",
    "CVE-2024-39394",
    "CVE-2024-39395",
    "CVE-2024-41850",
    "CVE-2024-41851",
    "CVE-2024-41852",
    "CVE-2024-41853",
    "CVE-2024-41854",
    "CVE-2024-41866"
  );
  script_xref(name:"IAVA", value:"2024-A-0479-S");

  script_name(english:"Adobe InDesign < 18.5.3 / 19.0 < 19.5.0 Multiple Vulnerabilities (APSB24-56)");

  script_set_attribute(attribute:"synopsis", value:
"The Adobe InDesign instance installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe InDesign installed on the remote Windows host is prior to 18.5.3, 19.5.0. It is, therefore,
affected by multiple vulnerabilities as referenced in the APSB24-56 advisory.

  - InDesign Desktop versions ID19.4, ID18.5.2 and earlier are affected by a Stack-based Buffer Overflow
    vulnerability that could result in arbitrary code execution in the context of the current user.
    Exploitation of this issue requires user interaction in that a victim must open a malicious file.
    (CVE-2024-39389, CVE-2024-41852)

  - InDesign Desktop versions ID19.4, ID18.5.2 and earlier are affected by an out-of-bounds write
    vulnerability that could result in arbitrary code execution in the context of the current user.
    Exploitation of this issue requires user interaction in that a victim must open a malicious file.
    (CVE-2024-39390, CVE-2024-39391, CVE-2024-39394)

  - InDesign Desktop versions ID19.4, ID18.5.2 and earlier are affected by a Heap-based Buffer Overflow
    vulnerability that could result in arbitrary code execution in the context of the current user.
    Exploitation of this issue requires user interaction in that a victim must open a malicious file.
    (CVE-2024-41850, CVE-2024-41853)

  - InDesign Desktop versions ID19.4, ID18.5.2 and earlier are affected by an out-of-bounds read vulnerability
    when parsing a crafted file, which could result in a read past the end of an allocated memory structure.
    An attacker could leverage this vulnerability to execute code in the context of the current user.
    Exploitation of this issue requires user interaction in that a victim must open a malicious file.
    (CVE-2024-39393)

  - InDesign Desktop versions ID19.4, ID18.5.2 and earlier are affected by an Integer Overflow or Wraparound
    vulnerability that could result in arbitrary code execution in the context of the current user.
    Exploitation of this issue requires user interaction in that a victim must open a malicious file.
    (CVE-2024-41851)

  - InDesign Desktop versions ID19.4, ID18.5.2 and earlier are affected by a NULL Pointer Dereference
    vulnerability that could lead to an application denial-of-service (DoS). An attacker could exploit this
    vulnerability to crash the application, resulting in a DoS condition. Exploitation of this issue requires
    user interaction in that a victim must open a malicious file. (CVE-2024-39395)

  - InDesign Desktop versions ID19.4, ID18.5.2 and earlier are affected by an out-of-bounds read vulnerability
    that could lead to disclosure of sensitive memory. An attacker could leverage this vulnerability to bypass
    mitigations such as ASLR. Exploitation of this issue requires user interaction in that a victim must open
    a malicious file. (CVE-2024-34127, CVE-2024-41854)

  - InDesign Desktop versions ID19.4, ID18.5.2 and earlier are affected by a NULL Pointer Dereference
    vulnerability that could lead to an application denial-of-service (DoS). An attacker could exploit this
    vulnerability to crash the application, resulting in a denial of service condition. Exploitation of this
    issue requires user interaction in that a victim must open a malicious file. (CVE-2024-41866)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/indesign/apsb24-56.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe InDesign version 18.5.3, 19.5.0 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-41853");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(121, 122, 125, 190, 476, 787);

  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:indesign");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_indesign_installed.nbin");
  script_require_keys("installed_sw/Adobe InDesign", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Adobe InDesign', win_local:TRUE);

var constraints = [
  { 'max_version' : '18.5.2', 'fixed_version' : '18.5.3', 'fixed_display' : 'ID18.5.3' },
  { 'min_version' : '19.0', 'max_version' : '19.4', 'fixed_version' : '19.5.0', 'fixed_display' : 'ID19.5' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
