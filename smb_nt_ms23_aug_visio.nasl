#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(179669);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/08/10");

  script_xref(name:"MSKB", value:"5002417");
  script_xref(name:"MSKB", value:"5002418");
  script_xref(name:"MSFT", value:"MS23-5002417");
  script_xref(name:"MSFT", value:"MS23-5002418");

  script_name(english:"Defense-in-Depth Security Updates for Microsoft Visio Products (August 2023)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Visio Products are missing defense-in-depth security updates.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Visio Products are missing defense-in-depth security updates to help improve security-related features.");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/en-US/vulnerability/ADV230003");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5002417");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5002418");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB5002417
  -KB5002418");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visio");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("office_installed.nasl", "microsoft_visio_installed.nbin", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('vcf_extras_office.inc');

var bulletin = 'MS23-08';
var kbs = make_list(
  '5002417',
  '5002418'
);

var constraints = [
  { 'kb':'5002417',  'fixed_version': '15.0.5579.1001', 'sp' : 1},
  { 'kb':'5002418', 'channel':'MSI', 'fixed_version': '16.0.5408.1002', 'sp' : 0}
];

vcf::microsoft::office_product::check_version_and_report(
  kbs:kbs,
  constraints:constraints,
  severity:SECURITY_NOTE,
  bulletin:bulletin,
  subproduct:'Visio'
);
