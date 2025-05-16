#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(186469);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/31");

  script_cve_id("CVE-2024-23108", "CVE-2024-23109", "CVE-2023-34992");
  script_xref(name:"IAVB", value:"2024-B-0068");

  script_name(english:"Fortinet FortiSIEM Remote Unauthenticated OS Command Injection (FG-IR-23-130)");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote server is affected by a command injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Fortinet FortiSIEM running on the remote server is 6.4.x < 6.4.3, 6.5.x < 6.5.2, 6.6.x < 6.6.4,
6.7.x < 6.7.6, or 7.0.0. It is, therefore, affected by an OS command injection vulnerability that can allow a remote
unauthenticated attacker to execute unauthorized commands via crafted API requests.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.fortiguard.com/psirt/FG-IR-23-130");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortinet FortiSIEM version 6.4.3, 6.5.2, 6.6.4, 6.7.6, 7.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-23109");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:fortinet:fortisiem");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'min_version' : '6.4.0', 'fixed_version' : '6.4.4'},
  { 'min_version' : '6.5.0', 'fixed_version' : '6.5.3'},
  { 'min_version' : '6.6.0', 'fixed_version' : '6.6.5'},
  { 'min_version' : '6.7.0', 'fixed_version' : '6.7.9'},
  { 'min_version' : '7.0.0', 'fixed_version' : '7.0.3'},
  { 'min_version' : '7.1.0', 'fixed_version' : '7.1.2'},
  { 'min_version' : '7.2.0', 'fixed_version' : '7.2.0'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
