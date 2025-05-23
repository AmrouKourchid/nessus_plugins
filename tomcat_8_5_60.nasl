#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(144054);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/23");

  script_cve_id("CVE-2020-17527", "CVE-2021-24122");
  script_xref(name:"IAVA", value:"2020-A-0570-S");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Apache Tomcat 8.5.0 < 8.5.60 multiple vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Tomcat installed on the remote host is prior to 8.5.60. It is, therefore, affected by multiple
vulnerabilities as referenced in the fixed_in_apache_tomcat_8.5.60_security-8 advisory.

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
  # https://tomcat.apache.org/security-8.html#Fixed_in_Apache_Tomcat_8.5.60
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?05c4b1e2");
  # https://github.com/apache/tomcat/commit/920dddbdb981f92e8d5872a4bb126a10af5ca8a9
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?25cb06ee");
  # https://github.com/apache/tomcat/commit/21e3408671aac7e0d7e264e720cac8b1b189eb29
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f848fd00");
  script_set_attribute(attribute:"see_also", value:"https://bz.apache.org/bugzilla/show_bug.cgi?id=64830");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 8.5.60 or later.");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat:8");
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
  { 'min_version' : '8.5.0', 'max_version' : '8.5.59', 'fixed_version' : '8.5.60' }
];

vcf::check_all_backporting(app_info:app_info);
vcf::check_granularity(app_info:app_info, sig_segments:3);
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
