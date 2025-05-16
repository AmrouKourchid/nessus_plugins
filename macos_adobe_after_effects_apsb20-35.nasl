#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(209348);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/20");

  script_cve_id(
    "CVE-2020-9637",
    "CVE-2020-9638",
    "CVE-2020-9660",
    "CVE-2020-9661",
    "CVE-2020-9662"
  );

  script_name(english:"Adobe After Effects < 17.1.1 Multiple Arbitrary Code Execution (APSB20-35) (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"The Adobe After Effects instance installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe After Effects installed on the remote macOS host is prior to 17.1.1. It is, therefore, affected by
multiple vulnerabilities as referenced in the APSB20-35 advisory.

  - Adobe After Effects versions 17.1 and earlier have an out-of-bounds write vulnerability. Successful
    exploitation could lead to arbitrary code execution . (CVE-2020-9660, CVE-2020-9662)

  - Adobe After Effects versions 17.1 and earlier have an out-of-bounds read vulnerability. Successful
    exploitation could lead to arbitrary code execution . (CVE-2020-9661)

  - Adobe After Effects versions 17.1 and earlier have a heap overflow vulnerability. Successful exploitation
    could lead to arbitrary code execution . (CVE-2020-9637, CVE-2020-9638)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/after_effects/apsb20-35.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe After Effects version 17.1.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-9662");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:after_effects");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_adobe_after_effects_installed.nbin");
  script_require_keys("installed_sw/Adobe After Effects", "Host/MacOSX/Version", "Host/local_checks_enabled");

  exit(0);
}

include('vcf.inc');

if (!get_kb_item('Host/local_checks_enabled'))
  audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/MacOSX/Version'))
  audit(AUDIT_OS_NOT, 'macOS');

var app_info = vcf::get_app_info(app:'Adobe After Effects');

var constraints = [
  { 'fixed_version' : '17.1.1' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
