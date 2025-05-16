#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124058);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/11");

  script_cve_id("CVE-2019-0232");
  script_bugtraq_id(107906);

  script_name(english:"Apache Tomcat 9.0.0.M1 < 9.0.18");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Tomcat installed on the remote host is prior to 9.0.18. It is, therefore, affected by a vulnerability as
referenced in the fixed_in_apache_tomcat_9.0.18_security-9 advisory.

  - When running on Windows with enableCmdLineArguments enabled, the CGI Servlet in Apache Tomcat 9.0.0.M1 to
    9.0.17, 8.5.0 to 8.5.39 and 7.0.0 to 7.0.93 is vulnerable to Remote Code Execution due to a bug in the way
    the JRE passes command line arguments to Windows. The CGI Servlet is disabled by default. The CGI option
    enableCmdLineArguments is disable by default in Tomcat 9.0.x (and will be disabled by default in all
    versions in response to this vulnerability). For a detailed explanation of the JRE behaviour, see Markus
    Wulftange's blog (https://codewhitesec.blogspot.com/2016/02/java-and-command-line-injections-in-
    windows.html) and this archived MSDN blog (https://web.archive.org/web/20161228144344/https://blogs.msdn.m
    icrosoft.com/twistylittlepassagesallalike/2011/04/23/everyone-quotes-command-line-arguments-the-wrong-
    way/). (CVE-2019-0232)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://codewhitesec.blogspot.com/2016/02/java-and-command-line-injections-in-windows.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3ba5edc6");
  # https://web.archive.org/web/20161228144344/https://blogs.msdn.microsoft.com/twistylittlepassagesallalike/2011/04/23/everyone-quotes-command-line-arguments-the-wrong-way/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?20cc80d0");
  # https://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.18
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4a563f9f");
  script_set_attribute(attribute:"see_also", value:"https://github.com/apache/tomcat/commit/4b244d8");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 9.0.18 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0232");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache Tomcat CGIServlet enableCmdLineArguments Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/15");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat:9");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2019-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("apache_tomcat_nix_installed.nbin", "os_fingerprint.nasl", "tomcat_error_version.nasl", "tomcat_win_installed.nbin");
  script_require_keys("installed_sw/Apache Tomcat");

  exit(0);
}

include('vcf_extras.inc');

vcf::tomcat::initialize();
var app_info = vcf::combined_get_app_info(app:'Apache Tomcat');

var constraints = [
  { 'min_version' : '9.0.0.M1', 'max_version' : '9.0.17', 'fixed_version' : '9.0.18' }
];

vcf::check_all_backporting(app_info:app_info);
vcf::check_granularity(app_info:app_info, sig_segments:3);
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
