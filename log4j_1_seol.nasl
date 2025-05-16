#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(182252);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/02");

  script_name(english:"Apache Log4j SEoL (<= 1.x)");

  script_set_attribute(attribute:"synopsis", value:
"An unsupported version of Apache Log4j is installed on the remote host.");
  script_set_attribute(attribute:"description", value:
"According to its version, Apache Log4j is less than or equal to 1.x. It is, therefore, no longer maintained by its
vendor or provider.

Lack of support implies that no new security patches for the product will be released by the vendor. As a result, it may
contain security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://logging.apache.org/log4j/1.2/");
  # https://news.apache.org/foundation/entry/apache_logging_services_project_announces
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5384dc7a");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Apache Log4j that is currently supported.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Tenable standard unsupported software score.");

  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/29");
  script_set_attribute(attribute:"seol_date", value:"2015/08/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:log4j");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("apache_log4j_win_installed.nbin", "apache_log4j_nix_installed.nbin");
  script_require_keys("installed_sw/Apache Log4j");

  exit(0);
}

include('ucf.inc');

var app = 'Apache Log4j';

var app_info = vcf::combined_get_app_info(app:app);

vcf::check_all_backporting(app_info:app_info);

vcf::check_granularity(app_info:app_info, sig_segments:2);

var constraints = [
  { max_branch : '1', seol : 20150805 }
];

ucf::check_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
