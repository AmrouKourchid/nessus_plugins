#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(197032);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/04");

  script_cve_id(
    "CVE-2024-30282",
    "CVE-2024-30293",
    "CVE-2024-30294",
    "CVE-2024-30295",
    "CVE-2024-30296",
    "CVE-2024-30297",
    "CVE-2024-30298"
  );
  script_xref(name:"IAVA", value:"2024-A-0290-S");

  script_name(english:"Adobe Animate 23.x < 23.0.6 / 24.x < 24.0.3 Multiple Vulnerabilities (APSB24-36)");

  script_set_attribute(attribute:"synopsis", value:
"Adobe Animate installed on remote Windows host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Animate installed on the remote Windows host is prior to 23.0.6 or 24.0.3. It is, therefore,
affected by multiple vulnerabilities as referenced in the apsb24-36 advisory.

  - Animate versions 24.0.2, 23.0.5 and earlier are affected by an out-of-bounds write vulnerability that
    could result in arbitrary code execution in the context of the current user. Exploitation of this issue
    requires user interaction in that a victim must open a malicious file. (CVE-2024-30282, CVE-2024-30296,
    CVE-2024-30297)

  - Animate versions 24.0.2, 23.0.5 and earlier are affected by a Stack-based Buffer Overflow vulnerability
    that could result in arbitrary code execution in the context of the current user. Exploitation of this
    issue requires user interaction in that a victim must open a malicious file. (CVE-2024-30293)

  - Animate versions 24.0.2, 23.0.5 and earlier are affected by a Heap-based Buffer Overflow vulnerability
    that could result in arbitrary code execution in the context of the current user. Exploitation of this
    issue requires user interaction in that a victim must open a malicious file. (CVE-2024-30294)

  - Animate versions 24.0.2, 23.0.5 and earlier are affected by a NULL Pointer Dereference vulnerability that
    could result in arbitrary code execution in the context of the current user. Exploitation of this issue
    requires user interaction in that a victim must open a malicious file. (CVE-2024-30295)

  - Animate versions 24.0.2, 23.0.5 and earlier Answer: are affected by an out-of-bounds read vulnerability
    that could lead to disclosure of sensitive memory. An attacker could leverage this vulnerability to bypass
    mitigations such as ASLR. Exploitation of this issue requires user interaction in that a victim must open
    a malicious file. (CVE-2024-30298)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/animate/apsb24-36.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Animate version 23.0.6 or 24.0.3 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-30297");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-30298");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(121, 122, 125, 476, 787);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:animate");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_animate_installed.nbin");
  script_require_keys("installed_sw/Adobe Animate", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Adobe Animate', win_local:TRUE);

var constraints = [
  { 'min_version' : '23.0.0', 'fixed_version' : '23.0.6' },
  { 'min_version' : '24.0.0', 'fixed_version' : '24.0.3' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
