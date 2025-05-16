#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(205334);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/10");

  script_cve_id("CVE-2024-39713");
  script_xref(name:"IAVB", value:"2024-B-0107");

  script_name(english:"Rocket.Chat < 6.10.1 Server-Side Request Forgery");

  script_set_attribute(attribute:"synopsis", value:
"A chat application is affected by a server-side request forgery
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Rocket.Chat running on the remote host is prior
to 6.10.1. It is, therefore, is affected by a server-side request
forgery vulnerability.

Note that Nessus has not tested for this issue but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://hackerone.com/reports/1886954");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 6.10.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-39713");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:rocket.chat:rocket.chat");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("rocketchat_detect.nbin");
  script_require_keys("installed_sw/Rocket.Chat");

  exit(0);
}

include('vcf.inc');
include('webapp_func.inc');

var app = 'Rocket.Chat';
var port = get_http_port(default:3000);
var app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);

var constraints = [
  {'fixed_version':'6.10.1'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
