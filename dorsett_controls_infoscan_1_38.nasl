#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(205602);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/30");

  script_cve_id("CVE-2024-39287", "CVE-2024-42408", "CVE-2024-42493");
  script_xref(name:"IAVB", value:"2024-B-0114");

  script_name(english:"Dorsett Controls InfoScan < 1.38 Multiple Vulnerabilities (July 2024)");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Dorsett Controls InfoScan running on the remote host is prior to 1.38. It is, therefore, affected by
multiple vulnerabilities:

  - Dorsett Controls Central Server update server has potential information leaks with an unprotected file that
    contains passwords and API keys. (CVE-2024-39287)

  - The InfoScan client download page can be intercepted with a proxy, to expose filenames located on the system, which
    could lead to additional information exposure. (CVE-2024-42408)

  - Dorsett Controls InfoScan is vulnerable due to a leak of possible sensitive information through the response
    headers and the rendered JavaScript prior to user login. (CVE-2024-42493)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://portal.dtscada.com/#/security-bulletins?bulletin=1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?04681f8f");
  # https://www.cisa.gov/news-events/ics-advisories/icsa-24-221-01
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?557647b9");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Dorsett Controls InfoScan version 1.38 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-39287");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:dorsettcontrols:infoscan");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("dorsett_controls_infoscan_web_detect.nbin");
  script_require_keys("installed_sw/Dorsett Controls InfoScan");
  script_require_ports("Services/www", 443);

  exit(0);
}

include('vcf.inc');
include('http.inc');

var app = 'Dorsett Controls InfoScan';
get_install_count(app_name:app, exit_if_zero:TRUE);

var port = get_http_port(default:443);

var app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);

var constraints = [
  { 'fixed_version' : '1.38' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);