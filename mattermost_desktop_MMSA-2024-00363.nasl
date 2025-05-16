#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(210009);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/01");

  script_cve_id("CVE-2024-10214");

  script_name(english:"Mattermost Desktop 9.5.x < 9.5.9 / 9.11.x < 9.11.1 (MMSA-2024-00363)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Mattermost Desktop installed on the remote host is prior to 9.5.9 or 9.11.1. It is, therefore, affected
by a vulnerability as referenced in the MMSA-2024-00363 advisory.

  - Mattermost versions 9.11.X <= 9.11.1, 9.5.x <= 9.5.9 icorrectly issues two sessions when using desktop SSO
    - one in the browser and one in desktop with incorrect settings. (CVE-2024-10214)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://mattermost.com/security-updates/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mattermost Desktop version 9.5.9 / 9.11.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-10214");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mattermost:mattermost_desktop");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"agent", value:"all");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mattermost_desktop_win_installed.nbin", "mattermost_desktop_nix_installed.nbin", "macos_mattermost_desktop_installed.nbin");
  script_require_ports("installed_sw/Mattermost Desktop", "installed_sw/Mattermost");

  exit(0);
}

include('vcf.inc');

var install_key, app_info;

install_key = get_kb_item('installed_sw/Mattermost Desktop');
if (install_key)
  app_info = vcf::get_app_info(app:'Mattermost Desktop');
else
  app_info = vcf::get_app_info(app:'Mattermost');


var constraints = [
  { 'min_version' : '9.5', 'fixed_version' : '9.5.9' },
  { 'min_version' : '9.11', 'fixed_version' : '9.11.1' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
