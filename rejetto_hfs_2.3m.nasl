#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(206652);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/06");

  script_cve_id("CVE-2024-23692");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/07/30");

  script_name(english:"Rejetto HTTP File Server 2.x <= 2.3m RCE (CVE-2024-23692)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Rejetto HTTP File Server installed on the remote host is 2.x up to 2.3m. It is, therefore, affected by a
vulnerability:

  - Rejetto HTTP File Server, up to and including version 2.3m, is vulnerable to a template injection
    vulnerability. This vulnerability allows a remote, unauthenticated attacker to execute arbitrary commands
    on the affected system by sending a specially crafted HTTP request. As of the CVE assignment date, Rejetto
    HFS 2.3m is no longer supported. (CVE-2024-23692)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://mohemiv.com/all/rejetto-http-file-server-2-3m-unauthenticated-rce/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fa512538");
  script_set_attribute(attribute:"solution", value:
"Rejetto HTTP File Server 2.x is unsupported. Upgrade to HFS3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-23692");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Rejetto HTTP File Server (HFS) Unauthenticated Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:rejetto:http_file_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("rejetto_http_file_server_detect.nbin");
  script_require_keys("installed_sw/Rejetto HTTP File Server");
  script_require_ports("Services/www", 80);

  exit(0);
}

include('vcf.inc');
include('http.inc');

var port = get_http_port(default:80, ignore_broken:TRUE);
var app_info = vcf::get_app_info(app:'Rejetto HTTP File Server', port:port, webapp:TRUE);

var constraints = [
  { 'min_version' : '2.0', 'max_version' : '2.3m', 'fixed_display' : 'Upgrade to HFS3' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
