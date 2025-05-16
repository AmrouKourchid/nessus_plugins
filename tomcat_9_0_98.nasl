#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(213078);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/13");

  script_cve_id("CVE-2024-50379", "CVE-2024-54677", "CVE-2024-56337");
  script_xref(name:"IAVA", value:"2024-A-0822-S");

  script_name(english:"Apache Tomcat 9.0.0.M1 < 9.0.98 multiple vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Tomcat installed on the remote host is prior to 9.0.98. It is, therefore, affected by multiple
vulnerabilities as referenced in the fixed_in_apache_tomcat_9.0.98_security-9 advisory.

  - Time-of-check Time-of-use (TOCTOU) Race Condition vulnerability during JSP compilation in Apache Tomcat
    permits an RCE on case insensitive file systems when the default servlet is enabled for write (non-default
    configuration). This issue affects Apache Tomcat: from 11.0.0-M1 through 11.0.1, from 10.1.0-M1 through
    10.1.33, from 9.0.0.M1 through 9.0.97. Users are recommended to upgrade to version 11.0.2, 10.1.34 or
    9.0.98, which fixes the issue. (CVE-2024-50379)

  - Time-of-check Time-of-use (TOCTOU) Race Condition vulnerability in Apache Tomcat. This issue affects
    Apache Tomcat: from 11.0.0-M1 through 11.0.1, from 10.1.0-M1 through 10.1.33, from 9.0.0.M1 through
    9.0.97. The mitigation for CVE-2024-50379 was incomplete. Users running Tomcat on a case insensitive file
    system with the default servlet write enabled (readonly initialisation parameter set to the non-default
    value of false) may need additional configuration to fully mitigate CVE-2024-50379 depending on which
    version of Java they are using with Tomcat: - running on Java 8 or Java 11: the system property
    sun.io.useCanonCaches must be explicitly set to false (it defaults to true) - running on Java 17: the
    system property sun.io.useCanonCaches, if set, must be set to false (it defaults to false) - running on
    Java 21 onwards: no further configuration is required (the system property and the problematic cache have
    been removed) Tomcat 11.0.3, 10.1.35 and 9.0.99 onwards will include checks that sun.io.useCanonCaches is
    set appropriately before allowing the default servlet to be write enabled on a case insensitive file
    system. Tomcat will also set sun.io.useCanonCaches to false by default where it can. (CVE-2024-56337)

  - Uncontrolled Resource Consumption vulnerability in the examples web application provided with Apache
    Tomcat leads to denial of service. This issue affects Apache Tomcat: from 11.0.0-M1 through 11.0.1, from
    10.1.0-M1 through 10.1.33, from 9.0.0.M1 through 9.9.97. Users are recommended to upgrade to version
    11.0.2, 10.1.34 or 9.0.98, which fixes the issue. (CVE-2024-54677)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://github.com/apache/tomcat/commit/1d88dd3ffaed76188dd4ee32ce77709ce6e153cd
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b71f671e");
  # https://github.com/apache/tomcat/commit/721544ea28e92549824b106be954a9f411867a1c
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?42a6a3c7");
  # https://github.com/apache/tomcat/commit/84065e26ca4555e63a922bb29b13b0a1c86b7654
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?999c40ad");
  # https://github.com/apache/tomcat/commit/3315a9027a7eaab18f42625b97b569940ff1365d
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6a662d7a");
  # https://github.com/apache/tomcat/commit/c2f7ce21c3fb12caefee87c517a8bb4f80700044
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ad9dfd59");
  # https://github.com/apache/tomcat/commit/75ff7e8622edcc024b268677aa789ee8f0880ecc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1af35800");
  # https://github.com/apache/tomcat/commit/4d5cc6538d91386f950373ac8120e98c2c78ed3a
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f04ad8eb");
  # https://github.com/apache/tomcat/commit/84c4af76e7a10fc7f8630ce62e6a46632ea4a90e
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?03f2aecc");
  # https://github.com/apache/tomcat/commit/9ffd23fc27f5d1fc95bf97e5cea175c8968f4533
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2241b5ec");
  # https://github.com/apache/tomcat/commit/43b507ebac9d268b1ea3d908e296cc6e46795c00
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?916874db");
  # https://github.com/apache/tomcat/commit/631500b0c9b2a2a2abb707e3de2e10a5936e5d41
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?74eed683");
  # https://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.98
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9dc52384");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 9.0.98 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-50379");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-56337");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/12/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/17");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat:9");
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
  { 'min_version' : '9.0.0.M1', 'max_version' : '9.0.97', 'fixed_version' : '9.0.98' }
];

vcf::check_all_backporting(app_info:app_info);
vcf::check_granularity(app_info:app_info, sig_segments:3);
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
