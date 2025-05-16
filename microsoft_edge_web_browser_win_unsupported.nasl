##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(112152);
  script_version("1.11");

  script_name(english:"Microsoft Edge Legacy Browser SEoL");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/02");

  script_xref(name:"IAVA", value:"0001-A-0554");

  script_set_attribute(attribute:"synopsis", value:
"The version of Microsoft Edge web browser installed on the remote host is
no longer supported.");
  script_set_attribute(attribute:"description", value:
"The remote host has an install of Microsoft Edge Legacy, a web browser, which is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7d9d220f");
  # https://learn.microsoft.com/en-us/lifecycle/products/microsoft-edge-legacy
  script_set_attribute(attribute:"see_also", value:"https://www.microsoft.com/en-us/windows/microsoft-edge");
    # https://techcommunity.microsoft.com/t5/microsoft-365-blog/new-microsoft-edge-to-replace-microsoft-edge-legacy-with-april-s/ba-p/2114224
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cf25ecb2");
  script_set_attribute(attribute:"solution", value:"Remove Edge Legacy and install a supported web browser.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");

  script_set_attribute(attribute:"cvss_score_rationale", value:"Tenable standard unsupported software score.");

  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:edge");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2018-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_edge_web_browser_win_installed.nbin");
  script_require_keys("SMB/MicrosoftEdge/Version");

  exit(0);
}

include('ucf.inc');

var app = 'Microsoft Edge Web Browser';

var app_info = vcf::combined_get_app_info(app:app);

vcf::check_all_backporting(app_info:app_info);

vcf::check_granularity(app_info:app_info, sig_segments:2);

var constraints = [
  { min_branch : '1.0', seol : 20210309 }
];

ucf::check_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);