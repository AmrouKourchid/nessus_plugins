#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(211460);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/18");
  script_xref(name:"MSKB", value:"5002650");
  script_xref(name:"MSFT", value:"MS23-5002650");
  script_xref(name:"IAVA", value:"2024-A-0746-S");

  script_name(english:"Defense-in-Depth Security Updates for Microsoft SharePoint Server 2019 (November 2024)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft SharePoint Server 2019 is missing defense-in-depth security updates to help improve security-related features.");
  script_set_attribute(attribute:"description", value:
"The Microsoft SharePoint Server 2019 installation is missing defense-in-depth security updates to help improve 
security-related features.");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/ADV240001");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released KB5002650 to address this issue.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_server:2019");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_sharepoint_installed.nbin", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('vcf_extras_microsoft.inc');

var app_info = vcf::microsoft::sharepoint::get_app_info();
var kb_checks = 
[
  {
    'product'      : '2019',
    'edition'      : 'Server',
    'kb'           : '5002650',
    'path'         : app_info.path,
    'version'      : '16.0.10416.20000',
    'append'       : 'bin',
    'file'         : 'ascalc.dll',
    'product_name' : 'Microsoft SharePoint Enterprise Server 2019'
  }
];
vcf::microsoft::sharepoint::check_version_and_report
(
  app_info:app_info, 
  bulletin:'MS24-11',
  constraints:kb_checks, 
  severity:SECURITY_NOTE
);
