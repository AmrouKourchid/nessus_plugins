#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(211395);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/12");

  script_cve_id(
    "CVE-2024-47426",
    "CVE-2024-47427",
    "CVE-2024-47428",
    "CVE-2024-47429",
    "CVE-2024-47430",
    "CVE-2024-47431",
    "CVE-2024-47432",
    "CVE-2024-47433",
    "CVE-2024-47434",
    "CVE-2024-47435",
    "CVE-2024-47436",
    "CVE-2024-47437",
    "CVE-2024-47438",
    "CVE-2024-47439",
    "CVE-2024-47440",
    "CVE-2024-49515",
    "CVE-2024-49516",
    "CVE-2024-49517",
    "CVE-2024-49518",
    "CVE-2024-49519",
    "CVE-2024-49520",
    "CVE-2024-49525"
  );
  script_xref(name:"IAVB", value:"2024-B-0172-S");

  script_name(english:"Adobe Substance 3D Painter < 10.1.1 Multiple Vulnerabilities (APSB24-86) (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"The Adobe Substance 3D Painter application installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Substance 3D Painter installed on the remote macOS host is prior to 10.1.1. It is, therefore,
affected by multiple vulnerabilities:

  - Substance3D - Painter versions 10.1.0 and earlier are affected by an out-of-bounds write vulnerability that could
    result in arbitrary code execution in the context of the current user. 
    (CVE-2024-49519, CVE-2024-47427, CVE-2024-47428, CVE-2024-47429, CVE-2024-47430, CVE-2024-47432, CVE-2024-49516)

  - Substance3D - Painter versions 10.1.0 and earlier are affected by an out-of-bounds read vulnerability that could
    result in arbitrary code execution in the context of the current user. 
    (CVE-2024-47435, CVE-2024-47436, CVE-2024-47437, CVE-2024-47440)

  - Substance3D - Painter versions 10.1.0 and earlier are affected by an untrusted search path vulnerability that could
    result in arbitrary code execution. (CVE-2024-49515)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://helpx.adobe.com/security/products/substance3d_painter/apsb24-86.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0562c5e6");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Substance 3D Painter 10.1.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-49525");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:substance_3d_painter");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_substance_3d_painter_macos_installed.nbin");
  script_require_keys("installed_sw/Adobe Substance 3D Stager", "Host/MacOSX/Version", "Host/local_checks_enabled");

  exit(0);
}

include('vcf.inc');

if (!get_kb_item('Host/local_checks_enabled'))
  audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/MacOSX/Version'))
  audit(AUDIT_OS_NOT, 'macOS');

var app_info = vcf::get_app_info(app:'Adobe Substance 3D Painter');

var constraints = [
  { 'fixed_version' : '10.1.1' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
