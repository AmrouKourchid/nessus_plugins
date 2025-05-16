#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(190362);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/21");

  script_cve_id("CVE-2024-23446");
  script_xref(name:"IAVB", value:"2024-B-0007-S");

  script_name(english:"Kibana 8.0.x < 8.12.1 (ESA-2024-01)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Kibana installed on the remote host is prior to 8.12.1. It is, therefore, affected by a vulnerability as
referenced in the ESA-2024-01 advisory.

  - An issue was discovered by Elastic, whereby the Detection Engine Search API does not respect Document-
    level security (DLS) or Field-level security (FLS) when querying the .alerts-security.alerts-{space_id}
    indices. Users who are authorized to call this API may obtain unauthorized access to documents if their
    roles are configured with DLS or FLS against the aforementioned index.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://discuss.elastic.co/t/kibana-8-12-1-security-update-esa-2024-01/352686
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8e7ba5c1");
  script_set_attribute(attribute:"solution", value:
"Upgrade Kibana based upon the guidance specified in ESA-2024-01.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-23446");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:elasticsearch:kibana");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("kibana_web_detect.nbin");
  script_require_keys("installed_sw/Kibana");
  script_require_ports("Services/www", 5601);

  exit(0);
}

include('http.inc');
include('vcf.inc');

get_install_count(app_name: 'Kibana', exit_if_zero: TRUE);

var port = get_http_port(default:5601);

var app_info = vcf::get_app_info(app:'Kibana', port:port, webapp:TRUE);

var constraints = [
  { 'min_version' : '8.0', 'fixed_version' : '8.12.1' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
