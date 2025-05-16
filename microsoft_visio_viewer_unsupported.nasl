#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93229);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/02");

  script_xref(name:"IAVA", value:"0001-A-0561");

  script_name(english:"Microsoft Visio Viewer SEoL");
  script_summary(english:"Checks the Visio Viewer version.");

  script_set_attribute(attribute:"synopsis", value:
"The version of Microsoft Visio Viewer installed on the remote host is
no longer supported.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the installation of
Microsoft Visio Viewer on the remote host is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.

Note: Future Versions of Visio Viewer are bundled with Visio and are not longer offered seperately.");
  script_set_attribute(attribute:"see_also", value:"https://learn.microsoft.com/en-us/lifecycle/products/?terms=visio");
  # https://support.microsoft.com/en-us/topic/supported-versions-of-the-office-viewers-a2a766fe-06bb-b0d7-2a55-e200d9ccad6f
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5dca4a5f");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Microsoft Visio Viewer that is currently
supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:'cvss_score_source', value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Tenable score for unsupported products");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/30");
  script_set_attribute(attribute:"seol_date", value:"2020/10/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visio_viewer");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_visio_viewer_installed.nbin");
  script_require_keys("installed_sw/Microsoft Visio Viewer");

  exit(0);
}

include('ucf.inc');

var app = 'Microsoft Visio Viewer';

var app_info = vcf::combined_get_app_info(app:app);

var constraints = [
  { min_branch : '0', max_branch:'11', seol : 20180208},
  { min_branch : '12', max_branch:'14', seol : 20201013}
];

ucf::check_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
