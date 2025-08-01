#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(209466);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/21");

  script_cve_id("CVE-2016-7886");

  script_name(english:"Adobe InDesign < 12.0.0 (APSB16-43) (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"The Adobe InDesign instance installed on the remote host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe InDesign installed on the remote macOS host is prior to 12.0.0. It is, therefore, affected by a
vulnerability as referenced in the APSB16-43 advisory.

  - Adobe InDesign version 11.4.1 and earlier, Adobe InDesign Server 11.0.0 and earlier have an exploitable
    memory corruption vulnerability. Successful exploitation could lead to arbitrary code execution.
    (CVE-2016-7886)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/indesign/apsb16-43.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe InDesign version 12.0.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-7886");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/13");
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
  { 'max_version' : '11.0.0', 'fixed_version' : '12.0.0' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
