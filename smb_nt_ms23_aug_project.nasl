#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc. 
##

include('compat.inc');

if (description)
{
  script_id(179670);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/08/10");

  script_xref(name:"MSKB", value:"4484489");
  script_xref(name:"MSKB", value:"5002328");
  script_xref(name:"MSFT", value:"MS23-4484489");
  script_xref(name:"MSFT", value:"MS23-5002328");

  script_name(english:"Defense-in-Depth Security Updates for Microsoft Project (August 2023)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Project installation on the remote host is missing defense-in-depth security updates.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Project products are missing defense-in-depth security updates to help improve security-related features.");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/en-US/vulnerability/ADV230003");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4484489");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5002328");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4484489
  -KB5002328");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:project");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl", "office_installed.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');
include('smb_reg_query.inc');
include('install_func.inc');

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');
var bulletin = 'MS23-08';

var kbs = make_list(
  '4484489', 
  '5002328'
);

if (get_kb_item('Host/patch_management_checks'))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_NOTE);

get_kb_item_or_exit('SMB/Registry/Enumerated', exit_code:1);

var port = kb_smb_transport();

var project_checks = make_array(
  "15.0", make_array('sp', 1, 'version', "15.0.5579.1001", 'kb', '4484489'),
  "16.0", make_nested_list(
    make_array('version', "16.0.5408.1001", 'channel', 'MSI', 'kb', '5002328')
    )
  );

if (hotfix_check_office_product(product:'Project', checks:project_checks, bulletin:bulletin))
{
  replace_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_note();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
