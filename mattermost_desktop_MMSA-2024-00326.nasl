#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(200817);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/20");

  script_cve_id("CVE-2024-36287");
  script_xref(name:"IAVA", value:"2024-A-0364-S");

  script_name(english:"Mattermost Desktop CVE-2024-36287 (macOS) (MMSA-2024-00326)");

  script_set_attribute(attribute:"synopsis", value:
"Mattermost Desktop running on the remote host is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to MMSA-2024-00326, Mattermost Desktop App versions <= 5.7.0 fail to disable certain Electron debug flags 
which allows for bypassing TCC restrictions on macOS.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://mattermost.com/security-updates/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mattermost Desktop 1.17.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-36287");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mattermost:mattermost_desktop");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macos_mattermost_desktop_installed.nbin");
  script_require_keys("installed_sw/Mattermost");

  exit(0);
}

include('vcf.inc');

if (!get_kb_item('Host/local_checks_enabled'))
  audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/MacOSX/Version'))
  audit(AUDIT_OS_NOT, 'macOS');

var app_info = vcf::get_app_info(app:'Mattermost');

var constraints = [
  { "fixed_version" : '5.8.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);
