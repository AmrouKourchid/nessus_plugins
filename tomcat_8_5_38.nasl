#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(197817);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/24");

  script_cve_id("CVE-2019-0199");

  script_name(english:"Apache Tomcat 8.5.0 < 8.5.38");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Tomcat installed on the remote host is prior to 8.5.38. It is, therefore, affected by a vulnerability as
referenced in the fixed_in_apache_tomcat_8.5.38_security-8 advisory.

  - The HTTP/2 implementation in Apache Tomcat 9.0.0.M1 to 9.0.14 and 8.5.0 to 8.5.37 accepted streams with
    excessive numbers of SETTINGS frames and also permitted clients to keep streams open without
    reading/writing request/response data. By keeping streams open for requests that utilised the Servlet
    API's blocking I/O, clients were able to cause server-side threads to block eventually leading to thread
    exhaustion and a DoS. (CVE-2019-0199)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://svn.apache.org/viewvc?view=rev&rev=1852707");
  script_set_attribute(attribute:"see_also", value:"https://svn.apache.org/viewvc?view=rev&rev=1852711");
  script_set_attribute(attribute:"see_also", value:"https://svn.apache.org/viewvc?view=rev&rev=1852712");
  script_set_attribute(attribute:"see_also", value:"https://svn.apache.org/viewvc?view=rev&rev=1852713");
  script_set_attribute(attribute:"see_also", value:"https://svn.apache.org/viewvc?view=rev&rev=1852714");
  script_set_attribute(attribute:"see_also", value:"https://svn.apache.org/viewvc?view=rev&rev=1852715");
  script_set_attribute(attribute:"see_also", value:"https://svn.apache.org/viewvc?view=rev&rev=1852717");
  script_set_attribute(attribute:"see_also", value:"https://svn.apache.org/viewvc?view=rev&rev=1852718");
  script_set_attribute(attribute:"see_also", value:"https://svn.apache.org/viewvc?view=rev&rev=1852719");
  script_set_attribute(attribute:"see_also", value:"https://svn.apache.org/viewvc?view=rev&rev=1852722");
  script_set_attribute(attribute:"see_also", value:"https://svn.apache.org/viewvc?view=rev&rev=1852723");
  script_set_attribute(attribute:"see_also", value:"https://svn.apache.org/viewvc?view=rev&rev=1852724");
  # https://github.com/apache/tomcat/commit/60a3af1738879ec06fac1ecb8a149608782f7cc9
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?883f4b5d");
  # https://tomcat.apache.org/security-8.html#Fixed_in_Apache_Tomcat_8.5.38
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0aec9c0b");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 8.5.38 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0199");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/08");
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
  { 'min_version' : '8.5.0', 'max_version' : '8.5.37', 'fixed_version' : '8.5.38' }
];

vcf::check_all_backporting(app_info:app_info);
vcf::check_granularity(app_info:app_info, sig_segments:3);
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
