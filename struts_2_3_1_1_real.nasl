#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(143125);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/24");

  script_cve_id("CVE-2012-0392", "CVE-2012-0393");

  script_name(english:"Apache Struts 2.x < 2.3.1.1 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host uses a Java framework that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apache Struts running on the remote host is prior to 2.3.1.1. It, therefore, affected by multiple
vulnerabilities:

  - The CookieInterceptor component in Apache Struts before 2.3.1.1 does not use the parameter-name whitelist, which
    allows remote attackers to execute arbitrary commands via a crafted HTTP Cookie header that triggers Java code
    execution through a static method. (CVE-2012-0392)

  - The ParameterInterceptor component in Apache Struts before 2.3.1.1 does not prevent access to public constructors, 
    which allows remote attackers to create or overwrite arbitrary files via a crafted parameter that triggers the 
    creation of a Java object. (CVE-2012-0393)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://cwiki.apache.org/confluence/display/WW/S2-008");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Struts version 2.3.1.1 or later");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-0392");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Apache-Struts ParameterInterceptor < 2.3.1.2 RCE Windows");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache Struts ParametersInterceptor Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"White_Phosphorus");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/01/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:struts");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("os_fingerprint.nasl", "struts_detect_win.nbin", "struts_detect_nix.nbin", "struts_config_browser_detect.nbin");
  script_require_ports("installed_sw/Apache Struts", "installed_sw/Struts");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'Apache Struts');

vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
  { 'min_version' : '2.0.0', 'fixed_version' : '2.3.1.1' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
