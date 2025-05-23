#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(138851);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/23");

  script_cve_id("CVE-2020-13935");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"Apache Tomcat 7.0.27 < 7.0.105");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Tomcat installed on the remote host is prior to 7.0.105. It is, therefore, affected by a vulnerability as
referenced in the fixed_in_apache_tomcat_7.0.105_security-7 advisory.

  - The payload length in a WebSocket frame was not correctly validated in Apache Tomcat 10.0.0-M1 to
    10.0.0-M6, 9.0.0.M1 to 9.0.36, 8.5.0 to 8.5.56 and 7.0.27 to 7.0.104. Invalid payload lengths could
    trigger an infinite loop. Multiple requests with invalid payload lengths could lead to a denial of
    service. (CVE-2020-13935)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://github.com/apache/tomcat/commit/f9f75c14678b68633f79030ddf4ff827f014cc84
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dd4dee09");
  # https://github.com/apache/tomcat/commit/4c04982870d6e730c38e21e58fb653b7cf723784
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?81ec7286");
  # https://tomcat.apache.org/security-7.html#Fixed_in_Apache_Tomcat_7.0.105
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?58ae3a4f");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 7.0.105 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-13935");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/23");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tomcat_error_version.nasl", "apache_tomcat_nix_installed.nbin", "os_fingerprint.nasl", "tomcat_win_installed.nbin");
  script_require_keys("installed_sw/Apache Tomcat");

  exit(0);
}

include('vcf_extras.inc');

vcf::tomcat::initialize();
var app_info = vcf::combined_get_app_info(app:'Apache Tomcat');

var constraints = [
  { 'min_version' : '7.0.27', 'max_version' : '7.0.104', 'fixed_version' : '7.0.105' }
];

vcf::check_all_backporting(app_info:app_info);
vcf::check_granularity(app_info:app_info, sig_segments:3);
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
