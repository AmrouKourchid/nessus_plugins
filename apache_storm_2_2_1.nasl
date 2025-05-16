#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(181874);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/27");

  script_cve_id("CVE-2021-38294", "CVE-2021-40865");

  script_name(english:"Apache Storm 1.x < 1.2.4 / 2.1.x < 2.1.1 / 2.2.x < 2.2.1 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A distributed computation application running on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apache Storm running on the remote host is affected by multiple vulnerabilities, as follows:

  - An Unsafe Deserialization vulnerability exists in the worker services of the Apache Storm supervisor
    server allowing pre-auth Remote Code Execution (RCE). (CVE-2021-40865)

  - A Command Injection vulnerability exists in the getTopologyHistory service. A specially crafted thrift
    request to the Nimbus server allows Remote Code Execution (RCE) prior to authentication. (CVE-2021-38294)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://lists.apache.org/thread/ncwxn6s18pmrbklryjg7kxn3qx4wjtqr");
  script_set_attribute(attribute:"see_also", value:"https://lists.apache.org/thread/wt9f7lsz6xhyxotf0g099w3xbs9f1b1x");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Storm version 1.2.4, 2.1.1, 2.2.1, 2.3.0, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-40865");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache Storm Nimbus getTopologyHistory Unauthenticated Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/26");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("apache_storm_webui_detect.nbin");
  script_require_keys("installed_sw/Apache Storm WebUI", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

vcf::apache_storm::initialize();

var app, port, constraints;

# Since the web app is just a web app and version could be misreported.
if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

port = get_http_port(default:8080);
app = vcf::get_app_info(app:'Apache Storm WebUI', webapp:TRUE, port:port);

constraints =
[
  {'min_version' : '1.0', 'fixed_version' : '1.2.4'},
  {'min_version' : '2.1', 'fixed_version' : '2.1.1'},
  {'min_version' : '2.2', 'fixed_version' : '2.2.1', 'fixed_display' : '2.2.1 / 2.3.0'}
];

vcf::check_version_and_report(app_info:app, constraints:constraints, severity:SECURITY_HOLE);
