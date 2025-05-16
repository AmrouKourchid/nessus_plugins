#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(205389);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/13");

  script_cve_id("CVE-2024-21684");

  script_name(english:"Atlassian Bitbucket < 8.9.13 / 8.19.2 Open Redirect");

  script_set_attribute(attribute:"synopsis", value:
"The version of Atlassian Bitbucket installed on the remote host is affected by a open redirect vulnerability.");
  script_set_attribute(attribute:"description", value:
"There is a low severity open redirect vulnerability within affected versions of Bitbucket Data Center. Versions of
Bitbucket DC from 8.0.0 to 8.9.12 and 8.19.0 to 8.19.1 are affected by this vulnerability. It is patched in 8.9.13
and 8.19.2. This open redirect vulnerability allows an unauthenticated attacker to redirect a victim user upon login
to Bitbucket Data Center to any arbitrary site which can be utilized for further exploitation which has low impact to
confidentiality, no impact to integrity, no impact to availability, and requires user interaction. Atlassian recommends
that Bitbucket Data Center customers upgrade to the version. If you are unable to do so, upgrade your instance to one
of the supported fixed versions.

Note: Nessus has not tested for this issue but has instead relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/BSERV-19454");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 8.9.13, 8.19.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-21684");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:bitbucket");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("bitbucket_detect.nbin");
  script_require_keys("installed_sw/bitbucket");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 7990);

  exit(0);
}
include('http.inc');
include('vcf.inc');

var port = get_http_port(default:7990);

var app = 'bitbucket';

var app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
  { 'min_version' : '8.9.0', 'fixed_version' : '8.9.13' },
  { 'min_version' : '8.19.0', 'fixed_version' : '8.19.2' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);

