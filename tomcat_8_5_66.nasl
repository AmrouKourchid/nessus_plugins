#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(197847);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/23");

  script_cve_id("CVE-2021-30640");

  script_name(english:"Apache Tomcat 8.5.0 < 8.5.66");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Tomcat installed on the remote host is prior to 8.5.66. It is, therefore, affected by a vulnerability as
referenced in the fixed_in_apache_tomcat_8.5.66_security-8 advisory.

  - A vulnerability in the JNDI Realm of Apache Tomcat allows an attacker to authenticate using variations of
    a valid user name and/or to bypass some of the protection provided by the LockOut Realm. This issue
    affects Apache Tomcat 10.0.0-M1 to 10.0.5; 9.0.0.M1 to 9.0.45; 8.5.0 to 8.5.65. (CVE-2021-30640)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://github.com/apache/tomcat/commit/24dfb30076997b640e5123e92c4b8d7f206f609c
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7d775100");
  # https://github.com/apache/tomcat/commit/0a272b00aed57526dbfc8b881ab253c23c61f100
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e7e8c21e");
  # https://github.com/apache/tomcat/commit/c9f21a2a7908c7c4ecd4f9bb495d3ee36a2bd822
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b1496d99");
  # https://github.com/apache/tomcat/commit/4e86b4ea0d1a9b00fa93971c31b93ad1bd49c7fe
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1614ff57");
  # https://github.com/apache/tomcat/commit/79580e7f70a07c083be07307376511bb864d5a7b
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?55d830e8");
  # https://github.com/apache/tomcat/commit/d3407672774e372fae8b5898d55f85d16f22b972
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a8ec1993");
  # https://github.com/apache/tomcat/commit/6a9129ac9bd06555ce04bb564a76fc3987311f38
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?de77eacf");
  # https://github.com/apache/tomcat/commit/ad22db641dcd61c2e8078f658fa709897b5da375
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ce1334ab");
  script_set_attribute(attribute:"see_also", value:"https://bz.apache.org/bugzilla/show_bug.cgi?id=65224");
  # https://tomcat.apache.org/security-8.html#Fixed_in_Apache_Tomcat_8.5.66
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6687ab08");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 8.5.66 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-30640");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/12");
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
  { 'min_version' : '8.5.0', 'max_version' : '8.5.65', 'fixed_version' : '8.5.66' }
];

vcf::check_all_backporting(app_info:app_info);
vcf::check_granularity(app_info:app_info, sig_segments:3);
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
