#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(213280);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/09");

  script_cve_id(
    "CVE-2024-11422",
    "CVE-2024-12178",
    "CVE-2024-12179",
    "CVE-2024-12191",
    "CVE-2024-12192",
    "CVE-2024-12193",
    "CVE-2024-12194",
    "CVE-2024-12197",
    "CVE-2024-12198",
    "CVE-2024-12199",
    "CVE-2024-12200",
    "CVE-2024-12669",
    "CVE-2024-12670",
    "CVE-2024-12671"
  );
  script_xref(name:"IAVA", value:"2024-A-0824-S");

  script_name(english:"Autodesk Navisworks Freedom 25.0.x < 2025.4 Multiple Vulnerabilities (adsk-sa-2024-0027)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The version of Autodesk Navisworks Freedom installed on the remote host is prior to 2025.4. It is,
therefore, affected by multiple vulnerabilities as referenced in the adsk-sa-2024-0027 advisory.

  - A maliciously crafted DWFX file, when parsed through Autodesk Navisworks, can force an Out-of-Bounds 
    Write vulnerability. A malicious actor can leverage this vulnerability to cause a crash, cause data 
    corruption, or execute arbitrary code in the context of the current process. 
    (CVE-2024-11422, CVE-2024-12191, CVE-2024-12193, CVE-2024-12197, CVE-2024-12198, CVE-2024-12199, 
    CVE-2024-12200, CVE-2024-12671)

  - A maliciously crafted DWFX file, when parsed through Autodesk Navisworks, can force a Memory Corruption 
    vulnerability. A malicious actor can leverage this vulnerability to execute arbitrary code in the context 
    of the current process. (CVE-2024-12178, CVE-2024-12194)

  - A maliciously crafted DWF file, when parsed through Autodesk Navisworks, can force an Out-of-Bounds 
    Write vulnerability. A malicious actor can leverage this vulnerability to cause a crash, cause data 
    corruption, or execute arbitrary code in the context of the current process. (CVE-2024-12192)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.autodesk.com/trust/security-advisories/adsk-sa-2024-0027");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Autodesk Navisworks Freedom version 2025.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-12671");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/12/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:autodesk:navisworks_freedom");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("autodesk_navisworks_freedom_win_installed.nbin");
  script_require_keys("installed_sw/Autodesk Navisworks Freedom");

  exit(0);
}

include('vcf_extras_autodesk.inc');

var app_info = vcf::autodesk::navisworks::get_app_info(type:'Freedom');

var constraints = [
  { 'min_version' : '2025', 'fixed_version' : '2025.4' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
