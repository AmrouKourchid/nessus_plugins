#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(232592);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/14");

  script_cve_id(
    "CVE-2025-24448",
    "CVE-2025-24449",
    "CVE-2025-27167",
    "CVE-2025-27168",
    "CVE-2025-27169",
    "CVE-2025-27170"
  );
  script_xref(name:"IAVA", value:"2025-A-0151");

  script_name(english:"Adobe Illustrator < 28.7.5 / 29.0.0 < 29.3.0 Multiple Vulnerabilities (APSB25-17) (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"The Adobe Illustrator instance installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Illustrator installed on the remote macOS host is prior to 28.7.5, 29.3.0. It is, therefore,
affected by multiple vulnerabilities as referenced in the APSB25-17 advisory.

  - Out-of-bounds Write (CWE-787) potentially leading to Arbitrary code execution (CVE-2025-27169)

  - Untrusted Search Path (CWE-426) potentially leading to Arbitrary code execution (CVE-2025-27167)

  - Stack-based Buffer Overflow (CWE-121) potentially leading to Arbitrary code execution (CVE-2025-27168)

  - Out-of-bounds Read (CWE-125) potentially leading to Memory Leak (CVE-2025-24448, CVE-2025-24449)

  - NULL Pointer Dereference (CWE-476) potentially leading to Application denial-of-service (CVE-2025-27170)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/illustrator/apsb25-17.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Illustrator version 28.7.5, 29.3.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-27169");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(121, 125, 426, 476, 787);

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/03/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:illustrator");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macos_adobe_illustrator_installed.nbin");
  script_require_keys("installed_sw/Adobe Illustrator", "Host/MacOSX/Version", "Host/local_checks_enabled");

  exit(0);
}

include('vcf.inc');

if (!get_kb_item('Host/local_checks_enabled'))
  audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/MacOSX/Version'))
  audit(AUDIT_OS_NOT, 'macOS');

var app_info = vcf::get_app_info(app:'Adobe Illustrator');

var constraints = [
  { 'fixed_version' : '28.7.5', 'fixed_display' : '28.7.5 and above' },
  { 'min_version' : '29.0.0', 'fixed_version' : '29.3.0', 'fixed_display' : '29.3 and above' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
