#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(216262);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/14");

  script_cve_id("CVE-2025-21155");
  script_xref(name:"IAVA", value:"2025-A-0091");

  script_name(english:"Adobe Substance 3D Stager 3.1.1 (APSB25-09)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Substance 3D Stager installed on the remote host is prior to 3.1.1. It is, therefore, affected by a
vulnerability as referenced in the APSB25-09 advisory.

  - Substance3D - Stager versions 3.1.0 and earlier are affected by a NULL Pointer Dereference vulnerability
    that could result in an application denial-of-service. An attacker could exploit this vulnerability to
    crash the application, leading to a denial-of-service condition. Exploitation of this issue requires user
    interaction in that a victim must open a malicious file. (CVE-2025-21155)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://helpx.adobe.com/security/products/substance3d_stager/apsb25-09.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f0762527");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Substance 3D Stager version 3.1.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-21155");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/02/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:adobe:substance_3d_stager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_substance_3d_stager_macos_installed.nbin");
  script_require_keys("installed_sw/Adobe Substance 3D Stager", "Host/MacOSX/Version", "Host/local_checks_enabled");

  exit(0);
}

include('vcf.inc');

if (!get_kb_item('Host/local_checks_enabled'))
  audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
  
if (!get_kb_item('Host/MacOSX/Version'))
  audit(AUDIT_OS_NOT, 'macOS');

var app_info = vcf::get_app_info(app:'Adobe Substance 3D Stager');

var constraints = [
  { 'fixed_version' : '3.1.1' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
