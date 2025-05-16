#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92700);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/02");

  script_xref(name:"IAVA", value:"0001-A-0562");

  script_name(english:"Microsoft Visual FoxPro Unsupported Version Detection");
  script_summary(english:"Checks the Microsoft Visual FoxPro version.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is no longer supported by
the vendor.");
  script_set_attribute(attribute:"description", value:
"Microsoft Visual FoxPro has been discontinued by Microsoft. Therefore,
the installation of Visual FoxPro on the remote Windows host is
unsupported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://msdn.microsoft.com/en-us/vfoxpro/bb308952.aspx");
  # https://support.microsoft.com/en-us/lifecycle/search?sort=PN&alpha=FoxPro&Filter=FilterNO
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?29ba0a28");
  # https://learn.microsoft.com/en-us/lifecycle/products/microsoft-visual-foxpro-90
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?85532317");
  script_set_attribute(attribute:"solution", value:
"Remove Microsoft Visual FoxPro from the system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Tenable standard unsupported software score.");


  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/03");
  script_set_attribute(attribute:"seol_date", value:"2015/01/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_foxpro");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016-2024 Tenable Network Security, Inc.");

  script_dependencies("foxpro_installed.nasl");
  script_require_keys("installed_sw/Visual FoxPro");

  exit(0);
}

include("ucf.inc");

var app = 'Visual FoxPro';

var app_info = vcf::combined_get_app_info(app:app);

var constraints = [
  { min_branch : '0', seol : 20150113}
];

ucf::check_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

