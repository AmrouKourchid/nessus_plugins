#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234132);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/10");

  script_cve_id("CVE-2025-1658", "CVE-2025-1659", "CVE-2025-1660");
  script_xref(name:"IAVA", value:"2025-A-0223");

  script_name(english:"Autodesk Navisworks Manage 25.0.x < 2026.0 Multiple Vulnerabilities (adsk-sa-2025-0002)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The version of Autodesk Navisworks Manage installed on the remote host is 2025.0 prior to 2026.0. It is,
therefore, affected by multiple vulnerabilities as referenced in the adsk-sa-2025-0002 advisory.

  - A maliciously crafted DWFX file, when parsed through Autodesk Navisworks, can force an Out-of-Bounds Read 
    vulnerability. A malicious actor can leverage this vulnerability to cause a crash, read sensitive data, or 
    execute arbitrary code in the context of the current process. (CVE-2025-1658, CVE-2025-1659)

  - A maliciously crafted DWFX file, when parsed through Autodesk Navisworks, can force a Memory Corruption 
    vulnerability. A malicious actor can leverage this vulnerability to execute arbitrary code in the context 
    of the current process.(CVE-2025-1660)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.autodesk.com/trust/security-advisories/adsk-sa-2025-0002");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Autodesk Navisworks Simulate version 2026.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-1660");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:autodesk:navisworks_manage");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("autodesk_navisworks_manage_win_installed.nbin");
  script_require_keys("installed_sw/Autodesk Navisworks Manage", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf_extras_autodesk.inc');

var app_info = vcf::autodesk::navisworks::get_app_info(type:'Manage');

var constraints = [
  { 'min_version' : '2025', 'fixed_version' : '2026.0' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
