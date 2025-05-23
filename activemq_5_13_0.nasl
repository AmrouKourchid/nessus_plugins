#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(87410);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/06");

  script_cve_id("CVE-2015-5254");
  script_xref(name:"CERT", value:"576313");

  script_name(english:"Apache ActiveMQ 5.x < 5.13.0 Java Object Deserialization RCE");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a web application that is affected by a
remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Apache ActiveMQ running on the remote host is 5.x prior
to 5.13.0. It is, therefore, affected by a remote code execution
vulnerability in the broker due to unsafe deserialize calls of
unauthenticated Java objects to the Apache Commons Collections (ACC)
library. An unauthenticated, remote attacker can exploit this to
execute arbitrary code on the target host.");
  # http://activemq.apache.org/security-advisories.data/CVE-2015-5254-announcement.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?863a18c3");
  # https://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9c6d83db");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache ActiveMQ version 5.13.0 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-5254");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/16");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:activemq");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("activemq_web_console_detect.nasl", "apache_activemq_nix_installed.nbin", "activemq_listen_port_detect.nbin");
  script_require_keys("installed_sw/Apache ActiveMQ");

  exit(0);
}

include("vcf.inc");

var app = vcf::combined_get_app_info(app:'Apache ActiveMQ');

var constraints = [
  {"min_version" : "5.0", "fixed_version" : "5.11.3"},
  {"min_version" : "5.12", "fixed_version" : "5.12.1"}
  ];

vcf::check_version_and_report(app_info:app, constraints:constraints, severity:SECURITY_HOLE, strict:FALSE);
