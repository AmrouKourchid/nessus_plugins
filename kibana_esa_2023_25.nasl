#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(186424);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/22");

  script_cve_id("CVE-2023-46671");
  script_xref(name:"IAVB", value:"2023-B-0093-S");

  script_name(english:"Elastic Kibana 8.x < 8.11.1 Information Disclosure (ESA-2023-25)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a Java application that is affected by an information disclosure vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of the Elastic Kibana instance on the remote host is 8.x prior to 8.11.1. It is, therefore, affected
by an information disclosure vulnerability. In the event of an infrequent error returned from an Elasticsearch cluster,
in cases where there is user interaction and an unhealthy cluster, sensitive information may be recorded in Kibana logs
within the error message. The error message may contain account credentials for the kibana_system 67 user, API Keys, and
credentials of Kibana end-users.  

Note that Nessus has not tested for the issue but has instead relied only on the application's self-reported version 
number.");
  # https://discuss.elastic.co/t/kibana-8-11-1-security-update-esa-2023-25/347149
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?361decf1");
  script_set_attribute(attribute:"solution", value:
"Users should upgrade to Kibana version 8.11.1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-46671");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:elasticsearch:kibana");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { "min_version" : "8.0.0", "fixed_version" : "8.11.1" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
