#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93228);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/23");

  script_xref(name:"IAVA", value:"0001-A-0503");

  script_name(english:"Microsoft PowerPoint Viewer Unsupported Version Detection");
  script_summary(english:"Checks the PowerPoint Viewer version.");

  script_set_attribute(attribute:"synopsis", value:
"The version of Microsoft PowerPoint Viewer installed on the remote
host is no longer supported.");
  script_set_attribute(attribute:"description", value:
"All versions of Microsoft PowerPoint Viewer are no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.

Note that PowerPoint Viewer was formerly known as PowerPoint Viewer
2010. The file versions are the same, only the name has changed in
references to the product.");
  # https://support.microsoft.com/en-us/topic/supported-versions-of-the-office-viewers-a2a766fe-06bb-b0d7-2a55-e200d9ccad6f
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5dca4a5f");
  script_set_attribute(attribute:"solution", value:
"Uninstall Microsoft PowerPoint Viewer.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Tenable standard unsupported software score.");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/30");
  script_set_attribute(attribute:"seol_date", value:"2018/02/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:powerpoint_viewer");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016-2023 Tenable Network Security, Inc.");

  script_dependencies("microsoft_powerpoint_viewer_installed.nbin");
  script_require_keys("installed_sw/Microsoft PowerPoint Viewer");

  exit(0);
}

include('ucf.inc');

var app = 'Microsoft PowerPoint Viewer';

var app_info = vcf::combined_get_app_info(app:app);

var constraints = [
  { min_branch : '0', seol : 20180208}
];

ucf::check_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
