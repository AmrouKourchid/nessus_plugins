#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(194951);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/08");

  script_cve_id("CVE-2024-32114");
  script_xref(name:"IAVB", value:"2024-B-0049-S");

  script_name(english:"Apache ActiveMQ 6.x < 6.1.2 Insecure Web API Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a web application that is affected by a Insecure Web API.");
  script_set_attribute(attribute:"description", value:
"The version of Apache ActiveMQ running on the remote host is 6.x prior to 6.1.2. It is, therefore, affected by an 
insecure the API web that a attacker can use without any required authentication.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://activemq.apache.org/security-advisories.data/CVE-2024-32114-announcement.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?38ac765a");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache ActiveMQ version 6.1.2 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-32114");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/03");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:activemq");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("activemq_web_console_detect.nasl", "apache_activemq_nix_installed.nbin", "activemq_listen_port_detect.nbin");
  script_require_keys("installed_sw/Apache ActiveMQ");

  exit(0);
}
include('vcf.inc');

var app = vcf::combined_get_app_info(app:'Apache ActiveMQ');

var constraints = [
  {'min_version' : '6.0', 'fixed_version' : '6.1.2'}
];

vcf::check_version_and_report(
  app_info:app, 
  constraints:constraints, 
  severity:SECURITY_HOLE
);
