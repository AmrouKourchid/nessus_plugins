#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(211519);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/19");

  script_cve_id("CVE-2024-52318");
  script_xref(name:"IAVA", value:"2024-A-0754-S");

  script_name(english:"Apache Tomcat 11.0.0 < 11.0.1");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Tomcat installed on the remote host is prior to 11.0.1. It is, therefore, affected by a vulnerability as
referenced in the fixed_in_apache_tomcat_11.0.1_security-11 advisory.

  - Incorrect object recycling and reuse vulnerability in Apache Tomcat. This issue affects Apache Tomcat:
    11.0.0, 10.1.31, 9.0.96. Users are recommended to upgrade to version 11.0.1, 10.1.32 or 9.0.97, which
    fixes the issue. (CVE-2024-52318)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bz.apache.org/bugzilla/show_bug.cgi?id=69333");
  # https://github.com/apache/tomcat/commit/8d1fc4733a06d1a03b9d644c57010f2ec5f0df38
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2e6dd4ac");
  # https://tomcat.apache.org/security-11.html#Fixed_in_Apache_Tomcat_11.0.1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0a9ea8f3");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 11.0.1 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-52318");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/18");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat:11");
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
  { 'equal' : '11.0.0', 'fixed_display' : '11.0.1' }
];

vcf::check_all_backporting(app_info:app_info);
vcf::check_granularity(app_info:app_info, sig_segments:3);
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
