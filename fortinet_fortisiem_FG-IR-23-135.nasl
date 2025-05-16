#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(186425);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/30");

  script_cve_id("CVE-2023-36553");

  script_name(english:"Fortinet FortiSIEM OS Command Injection in Report Server (FG-IR-23-135)");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote server is affected by a command injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Fortinet FortiSIEM running on the remote server is 4.7.x, 4.9.x, 4.10.x, 5.0.x, 5.1.x, 5.2.x, 5.3.x,
or 5.4.x. It is, therefore, affected by an OS command injection vulnerability that can allow a remote unauthenticated
attacker to execute unauthorized commands via crafted API requests.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.fortiguard.com/psirt/FG-IR-23-135");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortinet FortiSIEM version 6.4.3, 6.5.2, 6.6.4, 6.7.6, 7.0.1, 7.1.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-36553");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:fortinet:fortisiem");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("fortinet_fortisiem_web_detect.nbin");
  script_require_keys("installed_sw/Fortinet FortiSIEM");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include('vcf.inc');
include('http.inc');

var port = get_http_port(default:443);

var app_info = vcf::get_app_info(app:'Fortinet FortiSIEM', port:port, webapp:TRUE);

var constraints = [
  { 'min_version' : '4.7.0', 'max_version':'4.7.9999', 'fixed_display' : '6.4.3, 6.5.2, 6.6.4, 6.7.6, 7.0.1, 7.1.0 or later'},
  { 'min_version' : '4.9.0', 'max_version':'4.9.9999', 'fixed_display' : '6.4.3, 6.5.2, 6.6.4, 6.7.6, 7.0.1, 7.1.0 or later'},
  { 'min_version' : '4.10.0', 'max_version':'4.10.9999', 'fixed_display' : '6.4.3, 6.5.2, 6.6.4, 6.7.6, 7.0.1, 7.1.0 or later'},
  { 'min_version' : '5.0.0', 'max_version':'5.0.9999', 'fixed_display' : '6.4.3, 6.5.2, 6.6.4, 6.7.6, 7.0.1, 7.1.0 or later'},
  { 'min_version' : '5.1.0', 'max_version':'5.1.9999', 'fixed_display' : '6.4.3, 6.5.2, 6.6.4, 6.7.6, 7.0.1, 7.1.0 or later'},
  { 'min_version' : '5.2.0', 'max_version':'5.2.9999', 'fixed_display' : '6.4.3, 6.5.2, 6.6.4, 6.7.6, 7.0.1, 7.1.0 or later'},
  { 'min_version' : '5.3.0', 'max_version':'5.3.9999', 'fixed_display' : '6.4.3, 6.5.2, 6.6.4, 6.7.6, 7.0.1, 7.1.0 or later'},
  { 'min_version' : '5.4.0', 'max_version':'5.4.9999', 'fixed_display' : '6.4.3, 6.5.2, 6.6.4, 6.7.6, 7.0.1, 7.1.0 or later'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
