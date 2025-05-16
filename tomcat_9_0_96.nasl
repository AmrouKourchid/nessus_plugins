#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(211503);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/19");

  script_cve_id("CVE-2024-52316", "CVE-2024-52317");
  script_xref(name:"IAVA", value:"2024-A-0754-S");

  script_name(english:"Apache Tomcat 9.0.92 < 9.0.96 multiple vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Tomcat installed on the remote host is prior to 9.0.96. It is, therefore, affected by multiple
vulnerabilities as referenced in the fixed_in_apache_tomcat_9.0.96_security-9 advisory.

  - Incorrect object re-cycling and re-use vulnerability in Apache Tomcat. Incorrect recycling of the request
    and response used by HTTP/2 requests could lead to request and/or response mix-up between users. This
    issue affects Apache Tomcat: from 11.0.0-M23 through 11.0.0-M26, from 10.1.27 through 10.1.30, from 9.0.92
    through 9.0.95. Users are recommended to upgrade to version 11.0.0, 10.1.31 or 9.0.96, which fixes the
    issue. (CVE-2024-52317)

  - Unchecked Error Condition vulnerability in Apache Tomcat. If Tomcat is configured to use a custom Jakarta
    Authentication (formerly JASPIC) ServerAuthContext component which may throw an exception during the
    authentication process without explicitly setting an HTTP status to indicate failure, the authentication
    may not fail, allowing the user to bypass the authentication process. There are no known Jakarta
    Authentication components that behave in this way. This issue affects Apache Tomcat: from 11.0.0-M1
    through 11.0.0-M26, from 10.1.0-M1 through 10.1.30, from 9.0.0-M1 through 9.0.95. Users are recommended to
    upgrade to version 11.0.0, 10.1.31 or 9.0.96, which fix the issue. (CVE-2024-52316)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://github.com/apache/tomcat/commit/47307ee27abcdea2ee40e33897aca760083de46a
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b59e0a8f");
  # https://github.com/apache/tomcat/commit/7532f9dc4a8c37ec958f79dc82c4924a6c539223
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?518ab8d8");
  # https://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.96
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f9ad966a");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 9.0.96 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-52316");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/18");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat:9");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("os_fingerprint.nasl", "tomcat_error_version.nasl", "tomcat_win_installed.nbin", "apache_tomcat_nix_installed.nbin");
  script_require_keys("installed_sw/Apache Tomcat");

  exit(0);
}

include('vcf_extras.inc');

vcf::tomcat::initialize();
var app_info = vcf::combined_get_app_info(app:'Apache Tomcat');

var constraints = [
  { 'min_version' : '9.0.92', 'max_version' : '9.0.95', 'fixed_version' : '9.0.96' }
];

vcf::check_all_backporting(app_info:app_info);
vcf::check_granularity(app_info:app_info, sig_segments:3);
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
