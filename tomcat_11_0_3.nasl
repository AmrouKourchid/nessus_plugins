#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(232530);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/15");

  script_cve_id("CVE-2025-24813");
  script_xref(name:"IAVA", value:"2025-A-0156");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/04/22");

  script_name(english:"Apache Tomcat 11.0.0.M1 < 11.0.3");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Tomcat installed on the remote host is prior to 11.0.3. It is, therefore, affected by a vulnerability as
referenced in the fixed_in_apache_tomcat_11.0.3_security-11 advisory.

  - Path Equivalence: 'file.Name' (Internal Dot) leading to Remote Code Execution and/or Information
    disclosure and/or malicious content added to uploaded files via write enabled Default Servlet in Apache
    Tomcat. This issue affects Apache Tomcat: from 11.0.0-M1 through 11.0.2, from 10.1.0-M1 through 10.1.34,
    from 9.0.0.M1 through 9.0.98. If all of the following were true, a malicious user was able to view
    security sensitive files and/or inject content into those files: - writes enabled for the default servlet
    (disabled by default) - support for partial PUT (enabled by default) - a target URL for security sensitive
    uploads that was a sub-directory of a target URL for public uploads - attacker knowledge of the names of
    security sensitive files being uploaded - the security sensitive files also being uploaded via partial PUT
    If all of the following were true, a malicious user was able to perform remote code execution: - writes
    enabled for the default servlet (disabled by default) - support for partial PUT (enabled by default) -
    application was using Tomcat's file based session persistence with the default storage location -
    application included a library that may be leveraged in a deserialization attack Users are recommended to
    upgrade to version 11.0.3, 10.1.35 or 9.0.99, which fixes the issue. (CVE-2025-24813)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://github.com/apache/tomcat/commit/0a668e0c27f2b7ca0cc7c6eea32253b9b5ecb29c
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0b00670a");
  # https://tomcat.apache.org/security-11.html#Fixed_in_Apache_Tomcat_11.0.3
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9f1fc303");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 11.0.3 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-24813");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/03/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/10");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat:11");
  script_set_attribute(attribute:"generated_plugin", value:"former");
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
  { 'min_version' : '11.0.0.M1', 'max_version' : '11.0.2', 'fixed_version' : '11.0.3' }
];

vcf::check_all_backporting(app_info:app_info);
vcf::check_granularity(app_info:app_info, sig_segments:3);
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
