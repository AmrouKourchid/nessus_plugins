#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(209353);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/21");

  script_cve_id("CVE-2020-24423");

  script_name(english:"Adobe Media Encoder < 14.5 Arbitrary Code Execution (APSB20-65) (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"The Adobe Media Encoder instance installed on the remote host is affected by an arbitrary code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Media Encoder installed on the remote macOS host is prior to 14.5. It is, therefore, affected by a
vulnerability as referenced in the APSB20-65 advisory.

  - Adobe Media Encoder version 14.4 (and earlier) for Windows is affected by an uncontrolled search path
    vulnerability that could result in arbitrary code execution in the context of the current user.
    Exploitation of this issue requires user interaction in that a victim must open a malicious file.
    (CVE-2020-24423)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/media-encoder/apsb20-65.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Media Encoder version 14.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-24423");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:media_encoder");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_media_encoder_mac_installed.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/Adobe Media Encoder");

  exit(0);
}

include('vcf.inc');

if (!get_kb_item('Host/local_checks_enabled'))
  audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/MacOSX/Version'))
  audit(AUDIT_OS_NOT, 'macOS');

var app_info = vcf::get_app_info(app:'Adobe Media Encoder');

var constraints = [
  { 'fixed_version' : '14.5' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
