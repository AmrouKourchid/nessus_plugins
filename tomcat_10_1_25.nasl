#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(201843);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/12");

  script_cve_id("CVE-2024-34750", "CVE-2024-38286");
  script_xref(name:"IAVA", value:"2024-A-0393-S");
  script_xref(name:"IAVA", value:"2024-A-0589-S");

  script_name(english:"Apache Tomcat 10.1.0.M1 < 10.1.25");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Tomcat installed on the remote host is prior to 10.1.25. It is, therefore, affected by multiple 
vulnerabilities as referenced in the fixed_in_apache_tomcat_10.1.25_security-10 advisory.

  - Improper Handling of Exceptional Conditions, Uncontrolled Resource Consumption vulnerability in Apache
    Tomcat. When processing an HTTP/2 stream, Tomcat did not handle some cases of excessive HTTP headers
    correctly. This led to a miscounting of active HTTP/2 streams which in turn led to the use of an incorrect
    infinite timeout which allowed connections to remain open which should have been closed. This issue
    affects Apache Tomcat: from 11.0.0-M1 through 11.0.0-M20, from 10.1.0-M1 through 10.1.24, from 9.0.0-M1
    through 9.0.89. Users are recommended to upgrade to version 11.0.0-M21, 10.1.25 or 9.0.90, which fixes the
    issue. (CVE-2024-34750)

  - Tomcat, under certain configurations on any platform, allows an attacker to cause an OutOfMemoryError 
    by abusing the TLS handshake process, leading to a DoS vulnerability (CVE-2024-38286)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://github.com/apache/tomcat/commit/2afae300c9ac9c0e516e2e9de580847d925365c3
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?579ff3c5");
  # https://tomcat.apache.org/security-10.html#Fixed_in_Apache_Tomcat_10.1.25
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?34e8fd2b");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 10.1.25 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-38286");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/06/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/03");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat:10");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("os_fingerprint.nasl", "tomcat_error_version.nasl", "tomcat_win_installed.nbin", "apache_tomcat_nix_installed.nbin");
  script_require_keys("installed_sw/Apache Tomcat");

  exit(0);
}

include('vcf_extras.inc');

vcf::tomcat::initialize();
var app_info = vcf::combined_get_app_info(app:'Apache Tomcat');

var constraints = [
  { 'min_version' : '10.1.0.M1', 'max_version' : '10.1.24', 'fixed_version' : '10.1.25' }
];

vcf::check_all_backporting(app_info:app_info);
vcf::check_granularity(app_info:app_info, sig_segments:3);
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
