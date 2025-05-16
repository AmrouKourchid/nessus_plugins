#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(184189);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/31");

  script_cve_id("CVE-2023-46604");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/11/23");
  script_xref(name:"IAVB", value:"2023-B-0086-S");

  script_name(english:"Apache ActiveMQ < 5.15.16 / 5.16.x < 5.16.7 / 5.17.x < 5.17.6 / 5.18.x < 5.18.3 RCE");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a web application that is affected by remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"Apache ActiveMQ is vulnerable to remote code execution. The vulnerability may allow a remote attacker with network 
access to a broker to run arbitrary shell commands by manipulating serialized class types in the OpenWire protocol to 
cause the broker to instantiate any class on the classpath. Users are recommended to upgrade to versions 5.15.16, 
5.16.7, 5.17.6 or 5.18.3, which address this issue.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://activemq.apache.org/security-advisories.data/CVE-2023-46604-announcement.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?023610ba");
  script_set_attribute(attribute:"see_also", value:"https://issues.apache.org/jira/browse/AMQ-9370");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache ActiveMQ version 5.15.16, 5.16.7, 5.17.6, 5.18.3 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-46604");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache ActiveMQ Unauthenticated Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/02");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:activemq");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("activemq_web_console_detect.nasl", "apache_activemq_nix_installed.nbin", "activemq_listen_port_detect.nbin");
  script_require_keys("installed_sw/Apache ActiveMQ");

  exit(0);
}

include('vcf.inc');

var app = vcf::combined_get_app_info(app:'Apache ActiveMQ');

var constraints = [
  {'min_version' : '0.0', 'fixed_version' : '5.15.16'},
  {'min_version' : '5.16', 'fixed_version' : '5.16.7'},
  {'min_version' : '5.17', 'fixed_version' : '5.17.6'},
  {'min_version' : '5.18', 'fixed_version' : '5.18.3'}
];

vcf::check_version_and_report(
  app_info:app, 
  constraints:constraints, 
  severity:SECURITY_HOLE
);
