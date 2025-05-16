#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(197840);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/23");

  script_cve_id("CVE-2021-30639");

  script_name(english:"Apache Tomcat 9.0.0 < 9.0.45");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Tomcat installed on the remote host is prior to 9.0.45. It is, therefore, affected by a vulnerability as
referenced in the fixed_in_apache_tomcat_9.0.45_security-9 advisory.

  - A vulnerability in Apache Tomcat allows an attacker to remotely trigger a denial of service. An error
    introduced as part of a change to improve error handling during non-blocking I/O meant that the error flag
    associated with the Request object was not reset between requests. This meant that once a non-blocking I/O
    error occurred, all future requests handled by that request object would fail. Users were able to trigger
    non-blocking I/O errors, e.g. by dropping a connection, thereby creating the possibility of triggering a
    DoS. Applications that do not use non-blocking I/O are not exposed to this vulnerability. This issue
    affects Apache Tomcat 10.0.3 to 10.0.4; 9.0.44; 8.5.64. (CVE-2021-30639)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://github.com/apache/tomcat/commit/8ece47c4a9fb9349e8862c84358a4dd23c643a24
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d1ea9e0f");
  script_set_attribute(attribute:"see_also", value:"https://bz.apache.org/bugzilla/show_bug.cgi?id=65203");
  # https://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.45
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3b234e64");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 9.0.45 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-30639");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/23");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat:9");
  script_set_attribute(attribute:"generated_plugin", value:"former");
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
  { 'fixed_version' : '9.0.45', 'equal' : '9.0.44' }
];

vcf::check_all_backporting(app_info:app_info);
vcf::check_granularity(app_info:app_info, sig_segments:3);
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
