#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(197827);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/24");

  script_cve_id("CVE-2019-17569", "CVE-2020-1935", "CVE-2020-1938");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/17");
  script_xref(name:"CEA-ID", value:"CEA-2020-0021");

  script_name(english:"Apache Tomcat 8.5.0 < 8.5.51 multiple vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Tomcat installed on the remote host is prior to 8.5.51. It is, therefore, affected by multiple
vulnerabilities as referenced in the fixed_in_apache_tomcat_8.5.51_security-8 advisory.

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
  # https://github.com/apache/tomcat/commit/69c56080fb3355507e1b55d014ec0ee6767a6150
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?64bc5f04");
  # https://github.com/apache/tomcat/commit/b962835f98b905286b78c414d5aaec2d0e711f75
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?857a5018");
  # https://github.com/apache/tomcat/commit/5a5494f023e81aa353e262fb14fff4cd0338a67c
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e0bd6a50");
  # https://github.com/apache/tomcat/commit/9be57601efb8a81e3832feb0dd60b1eb9d2b61d5
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e3254ac7");
  # https://github.com/apache/tomcat/commit/64159aa1d7cdc2c118fcb5eac098e70129d54a19
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?05dc4b1e");
  # https://github.com/apache/tomcat/commit/03c436126db6794db5277a3b3d871016fb9a3f23
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1639365c");
  # https://github.com/apache/tomcat/commit/8fbe2e962f0ea138d92361921643fe5abe0c4f56
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1e470cde");
  # https://github.com/apache/tomcat/commit/959f1dfd767bf3cb64776b44f7395d1d8d8f7ab3
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fff5133c");
  # https://tomcat.apache.org/security-8.html#Fixed_in_Apache_Tomcat_8.5.51
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4e287adb");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 8.5.51 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1938");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/23");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat:8");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
  { 'min_version' : '8.5.0', 'max_version' : '8.5.50', 'fixed_version' : '8.5.51' }
];

vcf::check_all_backporting(app_info:app_info);
vcf::check_granularity(app_info:app_info, sig_segments:3);
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
