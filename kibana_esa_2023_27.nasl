#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(187123);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/08");

  script_cve_id("CVE-2023-46675");
  script_xref(name:"IAVB", value:"2023-B-0101-S");

  script_name(english:"Elastic Kibana 7.13.0 < 7.17.16, 8.0 < 8.11.2 Information Disclosure (ESA-2023-27)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a Java application that is affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the Elastic Kibana instance on the remote host is 7.13.0 prior to 7.17.16 or 8.0 prior to 8.11.1. 
It is, therefore, affected by an information disclosure vulnerability. In the event of an infrequent error returned 
from an Elasticsearch cluster, in cases where there is user interaction and an unhealthy cluster, sensitive information 
may be recorded in Kibana logs within the error message. The error message may contain account credentials for the 
kibana_system 67 user, API Keys, and credentials of Kibana end-users. Note: It was found that the fix for ESA-2023-25 in 
Kibana 8.11.1 for a similar issue was incomplete. 

Note that Nessus has not tested for the issue but has instead relied only on the application's self-reported version 
number.");
  # https://discuss.elastic.co/t/kibana-8-11-2-7-17-16-security-update-esa-2023-27/349182
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eea73413");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Kibana version  7.17.16, 8.11.2, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-46675");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/12/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:elasticsearch:kibana");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("kibana_web_detect.nbin");
  script_require_keys("installed_sw/Kibana");
  script_require_ports("Services/www", 5601);

  exit(0);
}

include('http.inc');
include('vcf.inc');

var app = 'Kibana';

get_install_count(app_name: 'Kibana', exit_if_zero: TRUE);

var port = get_http_port(default:5601);

var app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);

constraints = [
  { "min_version" : "7.13.0", "fixed_version" : "7.17.16" },
  { "min_version" : "8.0.0", "fixed_version" : "8.11.2" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);