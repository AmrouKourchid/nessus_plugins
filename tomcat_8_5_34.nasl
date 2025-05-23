#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(118036);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/23");

  script_cve_id("CVE-2018-11784");

  script_name(english:"Apache Tomcat 8.5.0 < 8.5.34");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Tomcat installed on the remote host is prior to 8.5.34. It is, therefore, affected by a vulnerability as
referenced in the fixed_in_apache_tomcat_8.5.34_security-8 advisory.

  - When the default servlet in Apache Tomcat versions 9.0.0.M1 to 9.0.11, 8.5.0 to 8.5.33 and 7.0.23 to
    7.0.90 returned a redirect to a directory (e.g. redirecting to '/foo/' when the user requested '/foo') a
    specially crafted URL could be used to cause the redirect to be generated to any URI of the attackers
    choice. (CVE-2018-11784)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tomcat.apache.org/security-8.html#Fixed_in_Apache_Tomcat_8.5.34
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?618585df");
  script_set_attribute(attribute:"see_also", value:"https://svn.apache.org/viewvc?view=rev&rev=1840056");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 8.5.34 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-11784");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/10");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat:8");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2018-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tomcat_error_version.nasl", "tomcat_win_installed.nbin", "apache_tomcat_nix_installed.nbin", "os_fingerprint.nasl");
  script_require_keys("installed_sw/Apache Tomcat");

  exit(0);
}

include('vcf_extras.inc');

vcf::tomcat::initialize();
var app_info = vcf::combined_get_app_info(app:'Apache Tomcat');

var constraints = [
  { 'min_version' : '8.5.0', 'max_version' : '8.5.33', 'fixed_version' : '8.5.34' }
];

vcf::check_all_backporting(app_info:app_info);
vcf::check_granularity(app_info:app_info, sig_segments:3);
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
