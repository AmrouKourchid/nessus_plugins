#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(187081);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/22");

  script_cve_id("CVE-2022-1471");

  script_name(english:"Atlassian Bitbucket < 7.21.16 / 8.8.7 / 8.9.4 / 8.10.3 / 8.11.3 / 8.12.2 RCE");

  script_set_attribute(attribute:"synopsis", value:
"The version of Atlassian Bitbucket installed on the remote host is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Atlassian Bitbucket installed on the remote host is affected by a remote code execution vulnerability 
as referenced in the vendor advisory.  A remote, unauthenticated attacker can explioit this exposure by sending a 
carefully crafted yaml payload to the remote server. 

Note: Nessus has not tested for this issue but has instead relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/JSDSERVER-14906");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/BSERV-14528");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 7.21.16, 8.8.7, 8.9.4, 8.10.4, 8.11.3, 8.12.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-1471");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/12/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:bitbucket");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("bitbucket_detect.nbin");
  script_require_keys("installed_sw/bitbucket");
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
  { 'min_version' : '7.0.0', 'fixed_version' : '7.21.16'},
  { 'min_version' : '8.0.0', 'fixed_version' : '8.8.7' },
  { 'min_version' : '8.9.0', 'fixed_version' : '8.9.4' },
  { 'min_version' : '8.10.0', 'fixed_version' : '8.10.4' },
  { 'min_version' : '8.11.0', 'fixed_version' : '8.11.3' },
  { 'min_version' : '8.12.0', 'fixed_version' : '8.12.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

