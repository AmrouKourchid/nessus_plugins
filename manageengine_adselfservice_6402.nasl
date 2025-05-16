#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(189178);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/22");

  script_cve_id("CVE-2024-0252");
  script_xref(name:"IAVA", value:"2024-A-0044");

  script_name(english:"ManageEngine ADSelfService Plus < build 6402 Authenticated RCE");

  script_set_attribute(attribute:"synopsis", value:
"A web application is affected by an authenticated remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the ManageEngine ADSelfService Plus application running on the remote host 
is prior to build 6402. It is, therefore, affected by an authenticated remote code execution vulnerability in the 
load balancer component of ADSelfService Plus. All ADSelfService Plus installations, regardless of load balancer 
configurations, are vulnerable.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported build
number.");
  # https://www.manageengine.com/products/self-service-password/advisory/CVE-2024-0252.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6e272cf3");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ManageEngine ADSelfService Plus build 6402 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-0252");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zohocorp:manageengine_adselfservice_plus");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("manageengine_adselfservice_detect.nasl");
  script_require_keys("installed_sw/ManageEngine ADSelfService Plus");
  script_require_ports("Services/www", 8888);

  exit(0);
}

include('vcf.inc');
include('vcf_extras_zoho.inc');
include('http.inc');

var app, app_info, constraints, port;

app = 'ManageEngine ADSelfService Plus';

port = get_http_port(default:8888);

app_info = vcf::zoho::fix_parse::get_app_info(
  app: app,
  port:  port,
  webapp: TRUE
);

constraints = [
  { 'fixed_version':'6402', 'fixed_display':'build 6402'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity: SECURITY_HOLE
);

