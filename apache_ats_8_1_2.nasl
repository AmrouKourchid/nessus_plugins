#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(184805);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/08");

  script_cve_id("CVE-2021-38161");

  script_name(english:"Apache Traffic Server 8.x < 8.1.3 Improper Authentication");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a improper authentication vulnerability.");
  script_set_attribute(attribute:"description", value:
"Improper Authentication vulnerability in TLS origin verification of Apache Traffic Server allows for man in the
middle attacks.

Note that Nessus did not actually test for these issues, but instead has relied on the version found in the
server's banner.");
  # https://lists.apache.org/thread/k01797hyncx53659wr3o72s5cvkc3164
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?db07235e");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Traffic Server version 8.1.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-38161");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:traffic_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("apache_traffic_server_version.nasl");
  script_require_keys("installed_sw/Apache Traffic Server");
  script_require_ports("Services/www", 80, 443, 8080);

  exit(0);
}

include('http.inc');
include('vcf.inc');

var port = get_http_port(default:8080);

var app_info = vcf::get_app_info(app:'Apache Traffic Server', port:port, webapp:TRUE);

var constraints = [
  { 'min_version':'8.0', 'fixed_version' : '8.1.3' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
