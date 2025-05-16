#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(205423);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/13");

  script_cve_id("CVE-2021-36380");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/03/26");

  script_name(english:"Sunhillo SureLine < 8.7.0.1.1 Unauthenticated OS Command Injection (CVE-2021-36380)");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote web server is affected by a command injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Sunhillo SureLine running on the remote host is prior to 8.7.0.1.1. It is, therefore, affected by an
unauthenticatd OS command injection vulnerability.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://research.nccgroup.com/2021/07/26/technical-advisory-sunhillo-sureline-unauthenticated-os-command-injection-cve-2021-36380/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c92d595b");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Sunhillo SureLine version 8.7.0.1.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-36380");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:sunhillo:sureline");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sunhillo_sureline_web_detect.nbin");
  script_require_keys("installed_sw/Sunhillo SureLine");
  script_require_ports("Services/www", 443);

  exit(0);
}

include('vcf.inc');
include('http.inc');

var app = 'Sunhillo SureLine';
get_install_count(app_name:app, exit_if_zero:TRUE);

var port = get_http_port(default:443);

var app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);

var constraints = [
  { 'fixed_version' : '8.7.0.1.1' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);