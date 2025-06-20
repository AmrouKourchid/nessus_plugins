#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(197182);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/05");

  script_cve_id("CVE-2024-30281");
  script_xref(name:"IAVB", value:"2024-B-0056-S");

  script_name(english:"Adobe Substance 3D Designer < 13.1.2 Memory Leak (APSB24-35) (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"The Adobe Substance 3D Designer application installed on the remote host is affected by a Remote Code Execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Substance 3D Designer installed on the remote macOS host is prior to 13.1.2. It is, therefore,
affected by a Remote Code Execution vulnerability as referenced in the APSB24-35 advisory.  Successful exploitation of these 
vulnerabilities could lead to memory leaks in the context of the current user.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://helpx.adobe.com/security/products/substance3d_designer/apsb24-35.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7adc6569");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Substance 3D Designer 13.1.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-30281");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:adobe:substance_3d_designer");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_substance_3d_designer_macos_installed.nbin");
  script_require_keys("installed_sw/Adobe Substance 3D Designer", "Host/MacOSX/Version", "Host/local_checks_enabled");

  exit(0);
}

include('vcf.inc');

if (!get_kb_item('Host/local_checks_enabled'))
  audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/MacOSX/Version'))
  audit(AUDIT_OS_NOT, 'macOS');

var app_info = vcf::get_app_info(app:'Adobe Substance 3D Designer');

var constraints = [
  { 'max_version': '13.1.1', 'fixed_version' : '13.1.2' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);