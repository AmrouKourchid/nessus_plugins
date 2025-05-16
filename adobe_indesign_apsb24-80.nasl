#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(208267);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/17");

  script_cve_id("CVE-2024-45137");
  script_xref(name:"IAVA", value:"2024-A-0622-S");
  script_xref(name:"IAVA", value:"2024-A-0629-S");

  script_name(english:"Adobe InDesign < 18.5.4 / 19.0 < 19.5.0 Arbitrary code execution (APSB24-80)");

  script_set_attribute(attribute:"synopsis", value:
"The Adobe InDesign instance installed on the remote host is affected by an arbitrary code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe InDesign installed on the remote Windows host is prior to 18.5.4, 19.5.0. It is, therefore,
affected by a vulnerability as referenced in the APSB24-80 advisory.

  - InDesign Desktop versions 19.4, 18.5.3 and earlier are affected by an Unrestricted Upload of File with
    Dangerous Type vulnerability that could result in arbitrary code execution. An attacker could exploit this
    vulnerability by uploading a malicious file which, when executed, could run arbitrary code in the context
    of the server. Exploitation of this issue requires user interaction. (CVE-2024-45137)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/indesign/apsb24-80.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe InDesign version 18.5.4, 19.5.0 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-45137");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(434);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:indesign");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_indesign_installed.nbin");
  script_require_keys("installed_sw/Adobe InDesign", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Adobe InDesign', win_local:TRUE);

var constraints = [
  { 'max_version' : '18.5.3', 'fixed_version' : '18.5.4', 'fixed_display' : 'ID18.5.4' },
  { 'min_version' : '19.0', 'max_version' : '19.4', 'fixed_version' : '19.5.0', 'fixed_display' : 'ID19.5' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
