#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(206924);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/20");

  script_cve_id(
    "CVE-2024-39380",
    "CVE-2024-39381",
    "CVE-2024-39382",
    "CVE-2024-41859",
    "CVE-2024-41867"
  );
  script_xref(name:"IAVA", value:"2024-A-0553-S");

  script_name(english:"Adobe After Effects < 23.6.9 / 24.0 < 24.6 Multiple Vulnerabilities (APSB24-55)");

  script_set_attribute(attribute:"synopsis", value:
"The Adobe After Effects instance installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe After Effects installed on the remote Windows host is prior to 23.6.9, 24.6. It is, therefore,
affected by multiple vulnerabilities as referenced in the APSB24-55 advisory.

  - After Effects versions 23.6.6, 24.5 and earlier are affected by an out-of-bounds write vulnerability that
    could result in arbitrary code execution in the context of the current user. Exploitation of this issue
    requires user interaction in that a victim must open a malicious file. (CVE-2024-39381, CVE-2024-41859)

  - After Effects versions 23.6.6, 24.5 and earlier are affected by a Heap-based Buffer Overflow vulnerability
    that could result in arbitrary code execution in the context of the current user. Exploitation of this
    issue requires user interaction in that a victim must open a malicious file. (CVE-2024-39380)

  - After Effects versions 23.6.6, 24.5 and earlier are affected by an out-of-bounds read vulnerability that
    could lead to disclosure of sensitive memory. An attacker could leverage this vulnerability to bypass
    mitigations such as ASLR. Exploitation of this issue requires user interaction in that a victim must open
    a malicious file. (CVE-2024-39382, CVE-2024-41867)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/after_effects/apsb24-55.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe After Effects version 23.6.9, 24.6 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-41859");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(121, 122, 125, 787);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:after_effects");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_after_effects_installed.nbin");
  script_require_keys("installed_sw/Adobe After Effects", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Adobe After Effects', win_local:TRUE);

var constraints = [
  { 'fixed_version' : '23.6.9' },
  { 'min_version' : '24.0', 'fixed_version' : '24.6' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
