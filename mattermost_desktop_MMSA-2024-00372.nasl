#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(207453);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/21");

  script_cve_id("CVE-2024-39772");
  script_xref(name:"IAVA", value:"2024-A-0583-S");

  script_name(english:"Mattermost Desktop < 5.9.0 (Windows / Unix) (MMSA-2024-00372)");

  script_set_attribute(attribute:"synopsis", value:
"Mattermost Desktop running on the remote host is affected by an Information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Mattermost Desktop installed on the remote host is prior to 5.9.0. It is,
therefore, affected by a vulnerability as referenced in the MMSA-2024-00372 advisory.

  - Mattermost versions  < 5.9.0 Mattermost Desktop app have a vulnerability in their screen capture 
    functionality, allowing attackers to potentially capture high-quality screenshots without user knowledge via 
    JavaScript APIs. This vulnerability poses a low confidentiality impact and can be exploited over a network 
    without requiring user interaction or elevated privileges

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://mattermost.com/security-updates/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mattermost Desktop version 5.9.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-39772");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mattermost:mattermost_desktop");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mattermost_desktop_win_installed.nbin", "mattermost_desktop_nix_installed.nbin");
  script_require_keys("installed_sw/Mattermost");

  exit(0);
}

include('vcf.inc');

if (!get_kb_item('Host/local_checks_enabled'))
  audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var win_local = FALSE;

var os = get_kb_item('Host/OS');
if ('windows' >< tolower(os))
  win_local = TRUE;

var app_info = vcf::get_app_info(app:'Mattermost Desktop', win_local:win_local);

var constraints = [
  { 'fixed_version' : '5.9.0' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
