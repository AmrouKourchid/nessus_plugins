#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(213948);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/10");

  script_name(english:"IBM DB2 SEoL (9.5.x)");

  script_set_attribute(attribute:"synopsis", value:
"An unsupported version of IBM DB2 is installed on the remote host.");
  script_set_attribute(attribute:"description", value:
"According to its version, IBM DB2 is 9.5.x. It is, therefore, no longer maintained by its vendor or provider.

Lack of support implies that no new security patches for the product will be released by the vendor. As a result, it may
contain security vulnerabilities.");
  # http://www-01.ibm.com/common/ssi/ShowDoc.wss?docURL=/common/ssi/rep_ca/0/897/ENUS913-220/index.html&lang=en&request_locale=en
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c6c3bca3");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of IBM DB2 that is currently supported.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Tenable standard unsupported software score.");

  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/10");
  script_set_attribute(attribute:"seol_date", value:"2018/04/30");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:db2");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("db2_and_db2_connect_installed.nbin", "db2_installed.nbin", "db2_das_detect.nasl");
  script_require_keys("installed_sw/DB2 Server");

  exit(0);
}

include('ucf.inc');

var app = 'DB2 Server';

var app_info = vcf::combined_get_app_info(app:app);

vcf::check_all_backporting(app_info:app_info);

vcf::check_granularity(app_info:app_info, sig_segments:2);

var constraints = [
  { max_branch : '9.5', min_branch : '9.5', seol : 20180430 }
];

ucf::check_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
