#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(66428);
  script_version("1.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/23");

  script_cve_id("CVE-2013-2071", "CVE-2013-4444");
  script_bugtraq_id(59798, 69728);

  script_name(english:"Apache Tomcat 7.0.0 < 7.0.40 multiple vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Tomcat installed on the remote host is prior to 7.0.40. It is, therefore, affected by multiple
vulnerabilities as referenced in the fixed_in_apache_tomcat_7.0.40_security-7 advisory.

  - java/org/apache/catalina/core/AsyncContextImpl.java in Apache Tomcat 7.x before 7.0.40 does not properly
    handle the throwing of a RuntimeException in an AsyncListener in an application, which allows context-
    dependent attackers to obtain sensitive request information intended for other applications in
    opportunistic circumstances via an application that records the requests that it processes.
    (CVE-2013-2071)

  - Unrestricted file upload vulnerability in Apache Tomcat 7.x before 7.0.40, in certain situations involving
    outdated java.io.File code and a custom JMX configuration, allows remote attackers to execute arbitrary
    code by uploading and accessing a JSP file. (CVE-2013-4444)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://tomcat.apache.org/security-7.html#Fixed_in_Apache_Tomcat_7.0.40
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3535dbbb");
  script_set_attribute(attribute:"see_also", value:"https://bz.apache.org/bugzilla/show_bug.cgi?id=54178");
  script_set_attribute(attribute:"see_also", value:"https://svn.apache.org/viewvc?view=rev&rev=1470437");
  script_set_attribute(attribute:"see_also", value:"https://svn.apache.org/viewvc?view=rev&rev=1471372");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 7.0.40 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-4444");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/05/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/15");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2013-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tomcat_error_version.nasl", "tomcat_win_installed.nbin", "apache_tomcat_nix_installed.nbin", "os_fingerprint.nasl");
  script_require_keys("installed_sw/Apache Tomcat");

  exit(0);
}

include('vcf_extras.inc');

vcf::tomcat::initialize();
var app_info = vcf::combined_get_app_info(app:'Apache Tomcat');

var constraints = [
  { 'min_version' : '7.0.0', 'max_version' : '7.0.39', 'fixed_version' : '7.0.40' }
];

vcf::check_all_backporting(app_info:app_info);
vcf::check_granularity(app_info:app_info, sig_segments:3);
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
