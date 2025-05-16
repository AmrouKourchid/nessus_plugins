#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(205310);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/13");

  script_cve_id("CVE-2023-38522", "CVE-2024-35161", "CVE-2024-35296");

  script_name(english:"Apache Traffic Server 8.x < 8.1.11 / 9.x < 9.2.5 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self reported version, the remote Apache Traffic Server install is affected by multiple vulnerabilities.

  - Apache Traffic Server forwards malformed HTTP chunked trailer section to origin servers. This can be utilized for 
    request smuggling and may also lead cache poisoning if the origin servers are vulnerable. (CVE-2024-35161)

  - Apache Traffic Server accepts characters that are not allowed for HTTP field names and forwards malformed requests 
    to origin servers. This can be utilized for request smuggling and may also lead cache poisoning if the origin 
    servers are vulnerable. (CVE-2023-38522)

  - Invalid Accept-Encoding header can cause Apache Traffic Server to fail cache lookup and force forwarding requests
    (CVE-2024-35296)

Note that Nessus did not actually test for these issues, but instead has relied on the version found in the
server's banner.");
  # https://lists.apache.org/thread/c4mcmpblgl8kkmyt56t23543gp8v56m0
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e24f11c1");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Traffic Server version 8.1.11, 9.2.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-35296");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:traffic_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'min_version':'8.0', 'fixed_version' : '8.1.11' },
  { 'min_version':'9.0', 'fixed_version' : '9.2.5' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
