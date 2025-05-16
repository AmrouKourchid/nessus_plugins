#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(193254);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/16");

  script_cve_id("CVE-2024-2447", "CVE-2024-28949", "CVE-2024-29221");
  script_xref(name:"IAVA", value:"2024-A-0206-S");

  script_name(english:"Mattermost Server < 8.1.11 / 9.x < 9.3.3 / 9.4.x < 9.4.4 / 9.5.x < 9.5.2 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Mattermost Server installed on the remote host is prior to 8.1.11, 9.x prior to 9.3.3, 9.4.x prior to
9.4.4, or 9.5.x prior to 9.5.2. It is, therefore, affected by multiple vulnerabilities as referenced in the
MMSA-2024-00306, MMSA-2023-00274, and MMSA-2024-00311 advisories:

  - Mattermost Server fails to authenticate the source of certain types of post actions, allowing an authenticated
    attacker to create posts as other users via a crafted post action. (CVE-2024-2447)

  - Mattermost Server don't limit the number of user preferences which allows an attacker to send a large number of
    user preferences potentially causing denial of service. (CVE-2024-28949)
  
  - Mattermost Server lacked proper access control in the '/api/v4/users/me/teams' endpoint allowing a team admin to
    get the invite ID of their team, thus allowing them to invite users, even if the 'Add Members' permission was
    explicitly removed from team admins. (CVE-2024-29221)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://mattermost.com/security-updates/");
  script_set_attribute(attribute:"solution", value:
"Upgrade Mattermost Server to version 8.1.11, 9.3.3, 9.4.4, or 9.5.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-2447");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mattermost:mattermost_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mattermost_server_detect.nbin");
  script_require_keys("installed_sw/Mattermost Server");

  exit(0);
}

include('vcf.inc');
include('http.inc');

var port = get_http_port(default:80);

var app_info = vcf::get_app_info(app:'Mattermost Server', port:port, webapp:TRUE);

var constraints = [
  { 'fixed_version' : '8.1.11' },
  { 'min_version' : '9.0', 'fixed_version' : '9.3.3' },
  { 'min_version' : '9.4', 'fixed_version' : '9.4.4' },
  { 'min_version' : '9.5', 'fixed_version' : '9.5.2' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
