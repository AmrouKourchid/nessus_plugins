#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(209405);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/21");

  script_cve_id("CVE-2021-40743", "CVE-2021-42731", "CVE-2021-42732");

  script_name(english:"Adobe InDesign 16.0 < 17.0.0 Multiple Vulnerabilities (APSB21-107) (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"The Adobe InDesign instance installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe InDesign installed on the remote macOS host is prior to 17.0.0. It is, therefore, affected by
multiple vulnerabilities as referenced in the APSB21-107 advisory.

  - Adobe InDesign versions 16.4 (and earlier) are affected by a Buffer Overflow vulnerability when parsing a
    specially crafted file. An unauthenticated attacker could leverage this vulnerability to achieve arbitrary
    code execution in the context of the current user. Exploitation of this issue requires user interaction in
    that a victim must open a malicious file. (CVE-2021-42731)

  - Access of Memory Location After End of Buffer (CWE-788) (CVE-2021-42732)

  - NULL Pointer Dereference (CWE-476) potentially leading to Application denial-of-service (CVE-2021-40743)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/indesign/apsb21-107.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe InDesign version 17.0.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-42731");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-42732");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(120, 476, 788);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:indesign");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_adobe_indesign_installed.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/Adobe InDesign");

  exit(0);
}

include('vcf.inc');

if (!get_kb_item('Host/local_checks_enabled'))
  audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/MacOSX/Version'))
  audit(AUDIT_OS_NOT, 'macOS');

var app_info = vcf::get_app_info(app:'Adobe InDesign');

var constraints = [
  { 'min_version' : '16.0', 'max_version' : '16.4', 'fixed_version' : '17.0.0' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
