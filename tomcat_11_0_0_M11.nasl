#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(180195);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/23");

  script_cve_id("CVE-2023-41080", "CVE-2023-46589");
  script_xref(name:"IAVA", value:"2023-A-0443-S");

  script_name(english:"Apache Tomcat 11.0.0.M1 < 11.0.0.M11 multiple vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Tomcat installed on the remote host is prior to 11.0.0.M11. It is, therefore, affected by multiple
vulnerabilities as referenced in the fixed_in_apache_tomcat_11.0.0-m11_security-11 advisory.

  - URL Redirection to Untrusted Site ('Open Redirect') vulnerability in FORM authentication feature Apache
    Tomcat.This issue affects Apache Tomcat: from 11.0.0-M1 through 11.0.0-M10, from 10.1.0-M1 through
    10.0.12, from 9.0.0-M1 through 9.0.79 and from 8.5.0 through 8.5.92. The vulnerability is limited to the
    ROOT (default) web application. (CVE-2023-41080)

  - Improper Input Validation vulnerability in Apache Tomcat.Tomcat from 11.0.0-M1 through 11.0.0-M10, from
    10.1.0-M1 through 10.1.15, from 9.0.0-M1 through 9.0.82 and from 8.5.0 through 8.5.95 did not correctly
    parse HTTP trailer headers. A trailer header that exceeded the header size limit could cause Tomcat to
    treat a single request as multiple requests leading to the possibility of request smuggling when behind a
    reverse proxy. Users are recommended to upgrade to version 11.0.0-M11 onwards, 10.1.16 onwards, 9.0.83
    onwards or 8.5.96 onwards, which fix the issue. (CVE-2023-46589)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://github.com/apache/tomcat/commit/e3703c9abb8fe0d5602f6ba8a8f11d4b6940815a
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8a3883bd");
  # https://tomcat.apache.org/security-11.html#Fixed_in_Apache_Tomcat_11.0.0-M11
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?43f1864b");
  # https://github.com/apache/tomcat/commit/6f181e1062a472bc5f0234980f66cbde42c1041b
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?551b6a91");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 11.0.0.M11 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-46589");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/25");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat:11");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tomcat_error_version.nasl", "tomcat_win_installed.nbin", "apache_tomcat_nix_installed.nbin", "os_fingerprint.nasl");
  script_require_keys("installed_sw/Apache Tomcat");

  exit(0);
}

include('vcf_extras.inc');

vcf::tomcat::initialize();
var app_info = vcf::combined_get_app_info(app:'Apache Tomcat');

var constraints = [
  { 'min_version' : '11.0.0.M1', 'max_version' : '11.0.0.M10', 'fixed_version' : '11.0.0.M11' }
];

vcf::check_all_backporting(app_info:app_info);
vcf::check_granularity(app_info:app_info, sig_segments:3);
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
