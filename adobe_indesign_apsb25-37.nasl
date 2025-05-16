#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(235873);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/13");

  script_cve_id("CVE-2025-30318", "CVE-2025-30319", "CVE-2025-30320");

  script_name(english:"Adobe InDesign < 19.5.3 / 20.0 < 20.3.0 Multiple Vulnerabilities (APSB25-37)");

  script_set_attribute(attribute:"synopsis", value:
"The Adobe InDesign instance installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe InDesign installed on the remote Windows host is prior to 19.5.3, 20.3.0. It is, therefore,
affected by multiple vulnerabilities as referenced in the APSB25-37 advisory.

  - InDesign Desktop versions ID19.5.2, ID20.2 and earlier are affected by an out-of-bounds write
    vulnerability that could result in arbitrary code execution in the context of the current user.
    Exploitation of this issue requires user interaction in that a victim must open a malicious file.
    (CVE-2025-30318)

  - InDesign Desktop versions ID19.5.2, ID20.2 and earlier are affected by a NULL Pointer Dereference
    vulnerability that could lead to application denial-of-service. An attacker could exploit this
    vulnerability to crash the application, causing a disruption in service. Exploitation of this issue
    requires user interaction in that a victim must open a malicious file. (CVE-2025-30319)

  - InDesign Desktop versions ID19.5.2, ID20.2 and earlier are affected by a NULL Pointer Dereference
    vulnerability that could lead to application denial-of-service. An attacker could exploit this
    vulnerability to crash the application, causing disruption in service. Exploitation of this issue requires
    user interaction in that a victim must open a malicious file. (CVE-2025-30320)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/indesign/apsb25-37.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe InDesign version 19.5.3, 20.3.0 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-30318");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(476, 787);

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/05/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/05/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:indesign");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
  { 'max_version' : '19.5.2', 'fixed_version' : '19.5.3', 'fixed_display' : 'ID19.5.3' },
  { 'min_version' : '20.0', 'max_version' : '20.2', 'fixed_version' : '20.3.0', 'fixed_display' : 'ID20.3' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
