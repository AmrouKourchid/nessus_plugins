#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(133845);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/23");

  script_cve_id("CVE-2019-17569", "CVE-2020-1935", "CVE-2020-1938");
  script_xref(name:"IAVB", value:"2020-B-0010-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/17");
  script_xref(name:"CEA-ID", value:"CEA-2020-0021");

  script_name(english:"Apache Tomcat 9.0.0.M1 < 9.0.31 multiple vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Tomcat installed on the remote host is prior to 9.0.31. It is, therefore, affected by multiple
vulnerabilities as referenced in the fixed_in_apache_tomcat_9.0.31_security-9 advisory.

  - When using the Apache JServ Protocol (AJP), care must be taken when trusting incoming connections to
    Apache Tomcat. Tomcat treats AJP connections as having higher trust than, for example, a similar HTTP
    connection. If such connections are available to an attacker, they can be exploited in ways that may be
    surprising. In Apache Tomcat 9.0.0.M1 to 9.0.0.30, 8.5.0 to 8.5.50 and 7.0.0 to 7.0.99, Tomcat shipped
    with an AJP Connector enabled by default that listened on all configured IP addresses. It was expected
    (and recommended in the security guide) that this Connector would be disabled if not required. This
    vulnerability report identified a mechanism that allowed: - returning arbitrary files from anywhere in the
    web application - processing any file in the web application as a JSP Further, if the web application
    allowed file upload and stored those files within the web application (or the attacker was able to control
    the content of the web application by some other means) then this, along with the ability to process a
    file as a JSP, made remote code execution possible. It is important to note that mitigation is only
    required if an AJP port is accessible to untrusted users. Users wishing to take a defence-in-depth
    approach and block the vector that permits returning arbitrary files and execution as JSP may upgrade to
    Apache Tomcat 9.0.31, 8.5.51 or 7.0.100 or later. A number of changes were made to the default AJP
    Connector configuration in 9.0.31 to harden the default configuration. It is likely that users upgrading
    to 9.0.31, 8.5.51 or 7.0.100 or later will need to make small changes to their configurations.
    (CVE-2020-1938)

  - In Apache Tomcat 9.0.0.M1 to 9.0.30, 8.5.0 to 8.5.50 and 7.0.0 to 7.0.99 the HTTP header parsing code used
    an approach to end-of-line parsing that allowed some invalid HTTP headers to be parsed as valid. This led
    to a possibility of HTTP Request Smuggling if Tomcat was located behind a reverse proxy that incorrectly
    handled the invalid Transfer-Encoding header in a particular manner. Such a reverse proxy is considered
    unlikely. (CVE-2020-1935)

  - The refactoring present in Apache Tomcat 9.0.28 to 9.0.30, 8.5.48 to 8.5.50 and 7.0.98 to 7.0.99
    introduced a regression. The result of the regression was that invalid Transfer-Encoding headers were
    incorrectly processed leading to a possibility of HTTP Request Smuggling if Tomcat was located behind a
    reverse proxy that incorrectly handled the invalid Transfer-Encoding header in a particular manner. Such a
    reverse proxy is considered unlikely. (CVE-2019-17569)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://github.com/apache/tomcat/commit/9ac90532e9a7d239f90952edb229b07c80a9a3eb
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?03d0b614");
  # https://github.com/apache/tomcat/commit/8bfb0ff7f25fe7555a5eb2f7984f73546c11aa26
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2280d951");
  # https://github.com/apache/tomcat/commit/49ad3f954f69c6e838c8cd112ad79aa5fa8e7153
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3b723448");
  # https://github.com/apache/tomcat/commit/7a1406a3cd20fdd90656add6cd8f27ef8f24e957
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?401ca5f1");
  # https://github.com/apache/tomcat/commit/64fa5b99442589ef0bf2a7fcd71ad2bc68b35fad
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a4e13da6");
  # https://github.com/apache/tomcat/commit/060ecc5eb839208687b7fcc9e35287ac8eb46998
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8e640f05");
  # https://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.31
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cbc3d54e");
  # https://github.com/apache/tomcat/commit/0e8a50f0a5958744bea1fd6768c862e04d3b7e75
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ebdb0ad0");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 9.0.31 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1938");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/21");

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
  { 'min_version' : '9.0.0.M1', 'max_version' : '9.0.30', 'fixed_version' : '9.0.31' }
];

vcf::check_all_backporting(app_info:app_info);
vcf::check_granularity(app_info:app_info, sig_segments:3);
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
