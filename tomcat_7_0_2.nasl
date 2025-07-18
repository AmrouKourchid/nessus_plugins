#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(121115);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/23");

  script_cve_id("CVE-2010-2227");

  script_name(english:"Apache Tomcat 7.0.0 < 7.0.2");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Tomcat installed on the remote host is prior to 7.0.2. It is, therefore, affected by a vulnerability as
referenced in the fixed_in_apache_tomcat_7.0.2_security-7 advisory.

  - Apache Tomcat 5.5.0 through 5.5.29, 6.0.0 through 6.0.27, and 7.0.0 beta does not properly handle an
    invalid Transfer-Encoding header, which allows remote attackers to cause a denial of service (application
    outage) or obtain sensitive information via a crafted header that interferes with recycling of a buffer.
    (CVE-2010-2227)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://svn.apache.org/viewvc?view=rev&rev=958911");
  script_set_attribute(attribute:"see_also", value:"https://tomcat.apache.org/security-7.html#Fixed_in_Apache_Tomcat_7.0.2");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 7.0.2 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2010-2227");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/07/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/11");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat:7");
  script_set_attribute(attribute:"generated_plugin", value:"former");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tomcat_error_version.nasl", "tomcat_win_installed.nbin", "apache_tomcat_nix_installed.nbin", "os_fingerprint.nasl");
  script_require_keys("installed_sw/Apache Tomcat");

  exit(0);
}

include('vcf_extras.inc');

vcf::tomcat::initialize();
var app_info = vcf::combined_get_app_info(app:'Apache Tomcat');

var constraints = [
  { 'fixed_version' : '7.0.2', 'equal' : '7.0.0' }
];

vcf::check_all_backporting(app_info:app_info);
vcf::check_granularity(app_info:app_info, sig_segments:3);
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
