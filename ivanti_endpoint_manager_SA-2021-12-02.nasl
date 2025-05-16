#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(194479);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/30");

  script_cve_id("CVE-2021-44529");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/04/15");

  script_name(english:"Ivanti Endpoint Manager - Cloud Service Appliance Code Injection (SA-2021-12-02)");

  script_set_attribute(attribute:"synopsis", value:
"The instance of Ivanti Endpoint Manager Cloud Services Appliance running on the remote host is affected by an code 
injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Ivanti Endpoint Manager Cloud Services Appliance running on the remote host is prior to 4.6.0-512. 
It is, therefore, affected by an code injection vulnerability. An unauthenticated, remote user can execute arbitrary 
code with limited permissions (nobody).

Note that Nessus has not tested for these issues but has instead relied only on the service's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://forums.ivanti.com/s/article/SA-2021-12-02-CVE-2021-44529");
  script_set_attribute(attribute:"solution", value:
"Update to Ivanti Endpoint Manager Cloud Services Appliance 4.6.0-512 or later");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-44529");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Ivanti Cloud Services Appliance (CSA) Command Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ivanti:endpoint_manager_cloud_services_appliance");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ivanti_endpoint_manager_csa_web_detect.nbin");
  script_require_keys("installed_sw/Ivanti Endpoint Manager Cloud Services Appliance");
  script_require_ports("Services/www", 443);

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var port = get_http_port(default:443);
var app_info = vcf::ivanti_csa::get_app_info(app:'Ivanti Endpoint Manager Cloud Services Appliance', win_local:TRUE, port:port);

var constraints = [
  { 'fixed_version':'4.6.0.512', 'fixed_display':'4.6.0.512 / 4.6 patch 5'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
