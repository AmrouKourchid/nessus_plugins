#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(179638);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/08/18");

  script_cve_id("CVE-2023-2783");
  script_xref(name:"IAVA", value:"2023-A-0394-S");

  script_name(english:"Mattermost Server < 7.8.5 / 7.9.x < 7.9.4 / 7.10.x < 7.10.1 Missing Authorization (MMSA-2023-00151)");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote server is affected by an missing authorization vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Mattermost Server running on the remote host is prior to 7.8.5, 7.9.x prior to 7.9.4 or 7.10.x prior to
7.10.1. It is, therefore, affected by a missing authorization vulnerability. Mattermost Apps Framework fails to verify
that a secret provided in the incoming webhook request allowing an attacker to modify the contents of the post sent by
the Apps.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://mattermost.com/security-updates/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mattermost Server version 7.8.5, 7.9.4, 7.10.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-2783");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mattermost:mattermost_server");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mattermost_server_detect.nbin");
  script_require_keys("installed_sw/Mattermost Server");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include('vcf.inc');
include('http.inc');

var port = get_http_port(default:80);

var app_info = vcf::get_app_info(app:'Mattermost Server', port:port, webapp:TRUE);

var constraints = [
  { 'fixed_version' : '7.8.5' },
  { 'min_version' : '7.9', 'fixed_version' : '7.9.4' },
  { 'min_version' : '7.10', 'fixed_version' : '7.10.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
