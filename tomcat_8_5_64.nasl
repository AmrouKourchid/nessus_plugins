#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(194472);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/23");

  script_cve_id("CVE-2021-41079", "CVE-2024-21733");

  script_name(english:"Apache Tomcat 8.5.0 < 8.5.64 multiple vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Tomcat installed on the remote host is prior to 8.5.64. It is, therefore, affected by multiple
vulnerabilities as referenced in the fixed_in_apache_tomcat_8.5.64_security-8 advisory.

  - Apache Tomcat 8.5.0 to 8.5.63, 9.0.0-M1 to 9.0.43 and 10.0.0-M1 to 10.0.2 did not properly validate
    incoming TLS packets. When Tomcat was configured to use NIO+OpenSSL or NIO2+OpenSSL for TLS, a specially
    crafted packet could be used to trigger an infinite loop resulting in a denial of service.
    (CVE-2021-41079)

  - Generation of Error Message Containing Sensitive Information vulnerability in Apache Tomcat.This issue
    affects Apache Tomcat: from 8.5.7 through 8.5.63, from 9.0.0-M11 through 9.0.43. Users are recommended to
    upgrade to version 8.5.64 onwards or 9.0.44 onwards, which contain a fix for the issue. (CVE-2024-21733)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://github.com/apache/tomcat/commit/b90d4fc1ff44f30e4b3aba622ba6677e3f003822
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d59ef87c");
  # https://github.com/apache/tomcat/commit/ce4b154e7b48f66bd98858626347747cd2514311
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ee2b85c9");
  # https://tomcat.apache.org/security-8.html#Fixed_in_Apache_Tomcat_8.5.64
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8a84b9d3");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 8.5.64 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-41079");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-21733");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/29");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat:8");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tomcat_error_version.nasl", "tomcat_win_installed.nbin", "apache_tomcat_nix_installed.nbin", "os_fingerprint.nasl");
  script_require_keys("installed_sw/Apache Tomcat");

  exit(0);
}

include('vcf_extras.inc');

vcf::tomcat::initialize();
var app_info = vcf::combined_get_app_info(app:'Apache Tomcat');

var constraints = [
  { 'min_version' : '8.5.0', 'max_version' : '8.5.63', 'fixed_version' : '8.5.64' }
];

vcf::check_all_backporting(app_info:app_info);
vcf::check_granularity(app_info:app_info, sig_segments:3);
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
