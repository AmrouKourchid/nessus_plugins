#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#

include('compat.inc');

if (description)
{
  script_id(144056);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/06");

  script_cve_id(
    "CVE-2020-17089",
    "CVE-2020-17115",
    "CVE-2020-17118",
    "CVE-2020-17120",
    "CVE-2020-17121"
  );
  script_xref(name:"MSKB", value:"4486751");
  script_xref(name:"MSKB", value:"4486752");
  script_xref(name:"MSKB", value:"4493231");
  script_xref(name:"MSFT", value:"MS20-4486751");
  script_xref(name:"MSFT", value:"MS20-4486752");
  script_xref(name:"MSFT", value:"MS20-4493231");
  script_xref(name:"IAVA", value:"2020-A-0560-S");
  script_xref(name:"CEA-ID", value:"CEA-2020-0138");

  script_name(english:"Security Updates for Microsoft SharePoint Server 2019 (December 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft SharePoint Server 2019 installation on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft SharePoint Server 2019 installation on the
remote host is missing security updates. It is, therefore,
affected by multiple vulnerabilities :

  - An elevation of privilege vulnerability. An attacker can
    exploit this to gain elevated privileges.
    (CVE-2020-17089)

  - A remote code execution vulnerability. An attacker can
    exploit this to bypass authentication and execute
    unauthorized arbitrary commands. (CVE-2020-17118,
    CVE-2020-17121)

  - An information disclosure vulnerability. An attacker can
    exploit this to disclose potentially sensitive
    information. (CVE-2020-17120)

  - A session spoofing vulnerability exists. An attacker can
    exploit this to perform actions with the privileges of
    another user. (CVE-2020-17115)");
  # https://support.microsoft.com/en-us/help/4486751/security-update-for-sharepoint-server-2019-dec-8-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c153ce68");
  # https://support.microsoft.com/en-us/help/4486752/security-update-for-sharepoint-server-2019-language-pack-dec-8-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e3432e77");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4486751
  -KB4486752
  -KB4493231");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-17118");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-17121");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_server:2019");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_sharepoint_installed.nbin", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
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

bulletin = 'MS20-12';

kbs = make_list(
  '4486751',
  '4486752',
  '4493231'
);

if (get_kb_item('Host/patch_management_checks'))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/Registry/Enumerated', exit_code:1);

# Get path information for Windows.
windir = hotfix_get_systemroot();
if (isnull(windir)) exit(1, 'Failed to determine the location of %windir%.');

registry_init();
app_name = 'Microsoft SharePoint Server';
install = get_single_install(app_name:app_name);

kb_checks =
{
  '2019':
  { '0':
    {'Server':
     [{
         'kb'           : '4486751',
         'path'         : install['path'],
         'append'       : 'bin',
         'file'         : 'ascalc.dll',
         'version'      : '16.0.10369.20000',
         'product_name' : 'Microsoft SharePoint Server 2019'
      },
      { #Commented out for ease of adding in later, if a file check can be determined.
         'kb'           : '4486752',
         #'path'         : install['path'],
         #'append'       : 'bin',
         #'file'         : 'ascalc.dll',
         #'version'      : '16.0.10368.20000',
         'product_name' : 'Microsoft SharePoint Server 2019'
      },
      { #Commented out for ease of adding in later, if a file check can be determined.
         'kb'           : '4493231',
         #'path'         : install['path'],
         #'append'       : 'bin',
         #'file'         : 'ascalc.dll',
         #'version'      : '16.0.10368.20000',
         'product_name' : 'Microsoft SharePoint Server 2019'
      }]
    }
  }
};

# Get the specific product / path
param_list = kb_checks[install['Product']][install['SP']][install['Edition']];
# audit if not affected
if(isnull(param_list)) audit(AUDIT_INST_VER_NOT_VULN, 'Microsoft SharePoint Server');
paranoid_audit = FALSE;
port = kb_smb_transport();
reg_keys = get_kb_list('SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName');
# grab the path otherwise
foreach check (param_list)
{
  if (check['kb'] == '4486752')
  { 
    are_we_vuln = HCF_OLDER;
    foreach display_name (reg_keys)
    {
      if ('KB'+check['kb'] >< display_name || 'KB4493161' >< display_name)
      {
        are_we_vuln = HCF_OK;
        break;
      }
    }
  }
  else if (check['kb'] == '4493231')
  {
    are_we_vuln = HCF_OLDER;
    foreach display_name (reg_keys)
    {
      if ('KB'+check['kb'] >< display_name || 'KB4493231' >< display_name)
      {
        are_we_vuln = HCF_OK;
        break;
      }
    }
    if (report_paranoia < 2 && are_we_vuln != HCF_OK)
    {
      paranoid_audit = TRUE;
      are_we_vuln = HCF_OK;
      report = '\n';
      if (check['product_name'])
        report += '  Product : ' + check['product_name'] + '\n';
        report += '  KB : ' + check['kb'] + ' was not confirmed due to Paranoid Check settings \n';
      hotfix_add_report(report, kb:check['kb']);
      break;
    }
  }
  if (!isnull(check['version']))
  {
    path = hotfix_append_path(path:check['path'], value:check['append']);
    are_we_vuln = hotfix_check_fversion(
      file:check['file'],
      version:check['version'],
      path:path,
      kb:check['kb'],
      product:check['product_name']
    );
  }
  else
  {
    if (are_we_vuln != HCF_OLDER) break;

    report = '\n';
    if (check['product_name'])
      report += '  Product : ' + check['product_name'] + '\n';
    if (check['kb'])
      report += '  KB : ' + check['kb'] + '\n';
      
    hotfix_add_report(report, kb:check['kb']);
  }
}
if (are_we_vuln == HCF_OLDER)
{
  port = kb_smb_transport();
  replace_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  if (paranoid_audit == TRUE) audit(AUDIT_POTENTIAL_VULN, app_name);
  audit(AUDIT_INST_VER_NOT_VULN, app_name);
}

