#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(192042);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/19");

  script_cve_id("CVE-2024-23672", "CVE-2024-24549");
  script_xref(name:"IAVA", value:"2024-A-0144-S");

  script_name(english:"Apache Tomcat 9.0.0.M1 < 9.0.86 multiple vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Tomcat installed on the remote host is prior to 9.0.86. It is, therefore, affected by multiple
vulnerabilities as referenced in the fixed_in_apache_tomcat_9.0.86_security-9 advisory.

  - Denial of Service via incomplete cleanup vulnerability in Apache Tomcat. It was possible for WebSocket
    clients to keep WebSocket connections open leading to increased resource consumption.This issue affects
    Apache Tomcat: from 11.0.0-M1 through 11.0.0-M16, from 10.1.0-M1 through 10.1.18, from 9.0.0-M1 through
    9.0.85, from 8.5.0 through 8.5.98. Users are recommended to upgrade to version 11.0.0-M17, 10.1.19, 9.0.86
    or 8.5.99 which fix the issue. (CVE-2024-23672)

  - Denial of Service due to improper input validation vulnerability for HTTP/2 requests in Apache Tomcat.
    When processing an HTTP/2 request, if the request exceeded any of the configured limits for headers, the
    associated HTTP/2 stream was not reset until after all of the headers had been processed.This issue
    affects Apache Tomcat: from 11.0.0-M1 through 11.0.0-M16, from 10.1.0-M1 through 10.1.18, from 9.0.0-M1
    through 9.0.85, from 8.5.0 through 8.5.98. Users are recommended to upgrade to version 11.0.0-M17,
    10.1.19, 9.0.86 or 8.5.99 which fix the issue. (CVE-2024-24549)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://github.com/apache/tomcat/commit/52d6650e062d880704898d7d8c1b2b7a3efe8068
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cffd87b0");
  # https://github.com/apache/tomcat/commit/8e03be9f2698f2da9027d40b9e9c0c9429b74dc0
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?77b8126b");
  # https://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.86
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d3d2aa27");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 9.0.86 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-24549");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-23672");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/13");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat:9");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
  { 'min_version' : '9.0.0.M1', 'max_version' : '9.0.85', 'fixed_version' : '9.0.86' }
];

vcf::check_all_backporting(app_info:app_info);
vcf::check_granularity(app_info:app_info, sig_segments:3);
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
