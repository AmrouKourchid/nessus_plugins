#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(178943);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/06");

  script_name(english:"Apache Tomcat SEoL (8.5.x)");

  script_set_attribute(attribute:"synopsis", value:
"An unsupported version of Apache Tomcat is installed on the remote host.");
  script_set_attribute(attribute:"description", value:
"According to its version, Apache Tomcat is 8.5.x. It is, therefore, no longer maintained by its vendor or provider.

Lack of support implies that no new security patches for the product will be released by the vendor. As a result, it may
contain security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://tomcat.apache.org/tomcat-85-eol.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Apache Tomcat that is currently supported.");
  script_set_attribute(attribute:"risk_factor", value:"Low");

  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/27");
  script_set_attribute(attribute:"seol_date", value:"2024/03/31");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat:8");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tomcat_error_version.nasl", "tomcat_win_installed.nbin", "apache_tomcat_nix_installed.nbin");
  script_require_keys("installed_sw/Apache Tomcat");

  exit(0);
}

include('ucf.inc');

var app = 'Apache Tomcat';

var app_info = vcf::combined_get_app_info(app:app);

vcf::check_all_backporting(app_info:app_info);

vcf::check_granularity(app_info:app_info, sig_segments:2);

var constraints = [
  { max_branch : '8.5', min_branch : '8.5', seol : 20240331 }
];

ucf::check_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);
