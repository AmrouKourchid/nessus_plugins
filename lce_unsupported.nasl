#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71457);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/03");

  script_xref(name:"IAVA", value:"0001-A-0602");

  script_name(english:"Tenable Log Correlation Engine Server SEoL");

  script_set_attribute(attribute:"synopsis", value:
"An unsupported version of Tenable Log Correlation Engine Server is installed on the remote host.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of Tenable Log Correlation Engine (LCE) Server on the remote host is no
longer maintained by its vendor or provider.

Lack of support implies that no new security patches for the product will be released by the vendor. As a result, it is
likely to contain security vulnerabilities.");
  # https://docs.tenable.com/PDFs/product-lifecycle-management/tenable-software-release-lifecycle-matrix.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e7570286");
  script_set_attribute(attribute:"see_also", value:"http://www.tenable.com/products/log-correlation-engine");
  script_set_attribute(attribute:"solution", value:
"Log Correlation Engine Server has been discontinued. Please refer to the vendor for support.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Tenable standard unsupported software score.");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/16");
  script_set_attribute(attribute:"seol_date", value:"2021/10/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:log_correlation_engine");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2024 Tenable Network Security, Inc.");

  script_dependencies("lce_installed.nbin");
  script_require_keys("installed_sw/Log Correlation Engine Server");

  exit(0);
}

include('ucf.inc');

var app = 'Log Correlation Engine Server';

var app_info = vcf::combined_get_app_info(app:app);

var constraints = [{ max_branch : '0', seol : 20211031, eseol : 20241231 }];

ucf::check_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
