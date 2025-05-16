#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(182256);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/02");

  script_name(english:"Apache Subversion Client SEoL (1.7.x)");

  script_set_attribute(attribute:"synopsis", value:
"An unsupported version of Apache Subversion Client is installed on the remote host.");
  script_set_attribute(attribute:"description", value:
"According to its version, Apache Subversion Client is 1.7.x. It is, therefore, no longer maintained by its vendor or
provider.

Lack of support implies that no new security patches for the product will be released by the vendor. As a result, it may
contain security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://subversion.apache.org/roadmap.html#release-planning");
  script_set_attribute(attribute:"see_also", value:"https://subversion.apache.org/docs/release-notes/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Apache Subversion Client that is currently supported.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Tenable standard unsupported software score.");

  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/29");
  script_set_attribute(attribute:"seol_date", value:"2015/10/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:subversion");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:apache:subversion_client");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("subversion_installed.nasl");
  script_require_keys("installed_sw/Subversion Client");

  exit(0);
}

include('ucf.inc');

var app = 'Subversion Client';

var app_info = vcf::combined_get_app_info(app:app);

vcf::check_all_backporting(app_info:app_info);

vcf::check_granularity(app_info:app_info, sig_segments:2);

var constraints = [
  { max_branch : '1.7', min_branch : '1.7', seol : 20151011 }
];

ucf::check_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
