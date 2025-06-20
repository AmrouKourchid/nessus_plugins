#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151502);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/23");

  script_cve_id("CVE-2021-30640");

  script_name(english:"Apache Tomcat 10.0.0.M1 < 10.0.6");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Tomcat installed on the remote host is prior to 10.0.6. It is, therefore, affected by a vulnerability as
referenced in the fixed_in_apache_tomcat_10.0.6_security-10 advisory.

  - A vulnerability in the JNDI Realm of Apache Tomcat allows an attacker to authenticate using variations of
    a valid user name and/or to bypass some of the protection provided by the LockOut Realm. This issue
    affects Apache Tomcat 10.0.0-M1 to 10.0.5; 9.0.0.M1 to 9.0.45; 8.5.0 to 8.5.65. (CVE-2021-30640)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://github.com/apache/tomcat/commit/f4d9bdef53ec009b7717620d890465fa273721a6
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d3fb2d8e");
  # https://github.com/apache/tomcat/commit/4e61e1d625a4a64d6b775e3a03c77a0b100d56d7
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0fb6f5ab");
  # https://github.com/apache/tomcat/commit/d5303a506c7533803d2b3bc46e6120ce673a6667
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0d761c19");
  # https://github.com/apache/tomcat/commit/b930d0b3161d9ec78d5fa57f886ed2de4680518b
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ddfa2b5e");
  # https://github.com/apache/tomcat/commit/17208c645d68d2af1444ee8c64f36a9b8f0ba76f
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?95156892");
  # https://github.com/apache/tomcat/commit/bd4d1fbe9146dff4714130594afd668406a6a5ef
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ed08487c");
  # https://github.com/apache/tomcat/commit/81f16b0a7186ed02efbfac336589d6cff28d1e89
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?806274b5");
  # https://github.com/apache/tomcat/commit/eeb7351219bd8803c0053e1e80444664a7cf5b51
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f104a57d");
  script_set_attribute(attribute:"see_also", value:"https://bz.apache.org/bugzilla/show_bug.cgi?id=65224");
  # https://tomcat.apache.org/security-10.html#Fixed_in_Apache_Tomcat_10.0.6
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?837a9443");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 10.0.6 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-30640");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/12");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat:10");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tomcat_error_version.nasl", "tomcat_win_installed.nbin", "apache_tomcat_nix_installed.nbin", "os_fingerprint.nasl");
  script_require_keys("installed_sw/Apache Tomcat");

  exit(0);
}

include('vcf_extras.inc');

vcf::tomcat::initialize();
var app_info = vcf::combined_get_app_info(app:'Apache Tomcat');

var constraints = [
  { 'min_version' : '10.0.0.M1', 'max_version' : '10.0.5', 'fixed_version' : '10.0.6' }
];

vcf::check_all_backporting(app_info:app_info);
vcf::check_granularity(app_info:app_info, sig_segments:3);
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
