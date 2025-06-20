#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(90024);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/06");

  script_cve_id("CVE-2016-0782");

  script_name(english:"Apache ActiveMQ 5.11.x < 5.11.4 / 5.12.x < 5.12.3 / 5.13.x < 5.13.1 Web Console Multiple XSS");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a web application that is affected by
multiple cross-site scripting vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apache ActiveMQ running on the remote host is 5.11.x
prior to 5.11.4, 5.12.x prior to 5.12.3, or 5.x prior to 5.13.1. It
is, therefore, affected by multiple cross-site scripting
vulnerabilities in the web-based administration console due to
improper validation of user-supplied input. A remote attacker can
exploit this, via a specially crafted request, to execute arbitrary
script code in a user's browser session.");
  # http://activemq.apache.org/security-advisories.data/CVE-2016-0782-announcement.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?41dd5ff8");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache ActiveMQ version 5.11.4 / 5.12.3 / 5.13.1 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-0782");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/18");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:activemq");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("activemq_web_console_detect.nasl", "apache_activemq_nix_installed.nbin", "activemq_listen_port_detect.nbin");
  script_require_keys("installed_sw/Apache ActiveMQ");

  exit(0);
}

include("vcf.inc");

var app = vcf::combined_get_app_info(app:'Apache ActiveMQ');

var constraints = [
  {"min_version" : "5.0", "fixed_version" : "5.11.4"},
  {"min_version" : "5.12", "fixed_version" : "5.12.3"},
  {"min_version" : "5.13", "fixed_version" : "5.13.1"}
  ];

vcf::check_version_and_report(app_info:app, constraints:constraints, severity:SECURITY_NOTE, strict:FALSE, flags: {'xss':TRUE});
