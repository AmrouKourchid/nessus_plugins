#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(235032);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/09");

  script_cve_id("CVE-2025-31650", "CVE-2025-31651");
  script_xref(name:"IAVA", value:"2025-A-0313");

  script_name(english:"Apache Tomcat 11.0.0.M1 < 11.0.6 multiple vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Tomcat installed on the remote host is prior to 11.0.6. It is, therefore, affected by multiple
vulnerabilities as referenced in the fixed_in_apache_tomcat_11.0.6_security-11 advisory.

  - Improper Input Validation vulnerability in Apache Tomcat. Incorrect error handling for some invalid HTTP
    priority headers resulted in incomplete clean-up of the failed request which created a memory leak. A
    large number of such requests could trigger an OutOfMemoryException resulting in a denial of service. This
    issue affects Apache Tomcat: from 9.0.76 through 9.0.102, from 10.1.10 through 10.1.39, from 11.0.0-M2
    through 11.0.5. Users are recommended to upgrade to version 9.0.104, 10.1.40 or 11.0.6 which fix the
    issue. (CVE-2025-31650)

  - Improper Neutralization of Escape, Meta, or Control Sequences vulnerability in Apache Tomcat. For a subset
    of unlikely rewrite rule configurations, it was possible for a specially crafted request to bypass some
    rewrite rules. If those rewrite rules effectively enforced security constraints, those constraints could
    be bypassed. This issue affects Apache Tomcat: from 11.0.0-M1 through 11.0.5, from 10.1.0-M1 through
    10.1.39, from 9.0.0.M1 through 9.0.102. Users are recommended to upgrade to version [FIXED_VERSION], which
    fixes the issue. (CVE-2025-31651)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://github.com/apache/tomcat/commit/fbecc915a10c5a3d634c5e2c6ced4ff479ce9953
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5dc9e1c9");
  # https://github.com/apache/tomcat/commit/75554da2fc5574862510ae6f0d7b3d78937f1d40
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3d387401");
  # https://github.com/apache/tomcat/commit/f619e6a05029538886d5a9d987925d573b5bb8c2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?68653258");
  # https://github.com/apache/tomcat/commit/ded0285b96b4d3f5560dfc8856ad5ec4a9b50ba9
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f29ac18d");
  # https://tomcat.apache.org/security-11.html#Fixed_in_Apache_Tomcat_11.0.6
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2ddba474");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 11.0.6 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:P");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-31650");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/30");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat:11");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("os_fingerprint.nasl", "tomcat_error_version.nasl", "tomcat_win_installed.nbin", "apache_tomcat_nix_installed.nbin");
  script_require_keys("installed_sw/Apache Tomcat");

  exit(0);
}

include('vcf_extras.inc');

vcf::tomcat::initialize();
var app_info = vcf::combined_get_app_info(app:'Apache Tomcat');

var constraints = [
  { 'min_version' : '11.0.0.M1', 'max_version' : '11.0.5', 'fixed_version' : '11.0.6' }
];

vcf::check_all_backporting(app_info:app_info);
vcf::check_granularity(app_info:app_info, sig_segments:3);
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
