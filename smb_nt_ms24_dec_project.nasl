#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc. 
##

include('compat.inc');

if (description)
{
  script_id(212231);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/16");
  script_xref(name:"MSKB", value:"5002652");
  script_xref(name:"MSFT", value:"MS24-5002652");
  script_xref(name:"IAVA", value:"2024-A-0808-S");

  script_name(english:"Defense-in-Depth Security Updates for Microsoft Project (December 2024)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Project installation on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Project products are missing defense-in-depth security updates to help improve security-related features.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/ADV240002");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5002652");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB5002652");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/12/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:project");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl", "office_installed.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('vcf_extras_office.inc');

var bulletin = 'MS24-12';
var kbs = make_list(
  '5002652'
);

var constraints = [
  { 'kb':'5002652', 'fixed_version': '16.0.5478.1000', 'sp' : 0}
];

vcf::microsoft::office_product::check_version_and_report(
  kbs:kbs,
  constraints:constraints,
  severity:SECURITY_NOTE,
  bulletin:bulletin,
  subproduct:'Project'
);
