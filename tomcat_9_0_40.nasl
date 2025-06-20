#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(144050);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/23");

  script_cve_id("CVE-2020-17527", "CVE-2021-24122");
  script_xref(name:"IAVA", value:"2020-A-0570-S");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Apache Tomcat 9.0.0.M1 < 9.0.40 multiple vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Tomcat installed on the remote host is prior to 9.0.40. It is, therefore, affected by multiple
vulnerabilities as referenced in the fixed_in_apache_tomcat_9.0.40_security-9 advisory.

  - When serving resources from a network location using the NTFS file system, Apache Tomcat versions
    10.0.0-M1 to 10.0.0-M9, 9.0.0.M1 to 9.0.39, 8.5.0 to 8.5.59 and 7.0.0 to 7.0.106 were susceptible to JSP
    source code disclosure in some configurations. The root cause was the unexpected behaviour of the JRE API
    File.getCanonicalPath() which in turn was caused by the inconsistent behaviour of the Windows API
    (FindFirstFileW) in some circumstances. (CVE-2021-24122)

  - While investigating bug 64830 it was discovered that Apache Tomcat 10.0.0-M1 to 10.0.0-M9, 9.0.0-M1 to
    9.0.39 and 8.5.0 to 8.5.59 could re-use an HTTP request header value from the previous stream received on
    an HTTP/2 connection for the request associated with the subsequent stream. While this would most likely
    lead to an error and the closure of the HTTP/2 connection, it is possible that information could leak
    between requests. (CVE-2020-17527)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.40
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?13c2f9e9");
  # https://github.com/apache/tomcat/commit/d56293f816d6dc9e2b47107f208fa9e95db58c65
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?145171fc");
  # https://github.com/apache/tomcat/commit/935fc5582dc25ae10bab6f9d5629ff8d996cb533
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2a924804");
  script_set_attribute(attribute:"see_also", value:"https://bz.apache.org/bugzilla/show_bug.cgi?id=64830");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 9.0.40 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-17527");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/10");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat:9");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tomcat_error_version.nasl", "tomcat_win_installed.nbin", "apache_tomcat_nix_installed.nbin", "os_fingerprint.nasl");
  script_require_keys("installed_sw/Apache Tomcat");

  exit(0);
}

include('vcf_extras.inc');

vcf::tomcat::initialize();
var app_info = vcf::combined_get_app_info(app:'Apache Tomcat');

var constraints = [
  { 'min_version' : '9.0.0.M1', 'max_version' : '9.0.39', 'fixed_version' : '9.0.40' }
];

vcf::check_all_backporting(app_info:app_info);
vcf::check_granularity(app_info:app_info, sig_segments:3);
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
