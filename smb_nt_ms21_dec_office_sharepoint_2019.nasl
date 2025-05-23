#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158165);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/06");

  script_cve_id(
    "CVE-2021-42294",
    "CVE-2021-42309",
    "CVE-2021-42320",
    "CVE-2021-43242"
  );
  script_xref(name:"MSKB", value:"5002054");
  script_xref(name:"MSKB", value:"5002061");
  script_xref(name:"MSFT", value:"MS21-5002054");
  script_xref(name:"MSFT", value:"MS21-5002061");

  script_name(english:"Security Updates for Microsoft SharePoint Server 2019 (December 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft SharePoint Server 2019 installation on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft SharePoint Server 2019 installation on the
remote host is missing security updates. It is, therefore,
affected by multiple vulnerabilities:

  - A session spoofing vulnerability exists. An attacker can
    exploit this to perform actions with the privileges of
    another user. (CVE-2021-42320, CVE-2021-43242)

  - A remote code execution vulnerability. An attacker can
    exploit this to bypass authentication and execute
    unauthorized arbitrary commands. (CVE-2021-42294,
    CVE-2021-42309)");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5002054");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5002061");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB5002054
  -KB5002061");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-42309");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_server:2019");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

var bulletin = 'MS21-12';
var app_name = 'Microsoft SharePoint Server';
var kbs = make_list(
  '5002054', '5002061'
);

if (get_kb_item('Host/patch_management_checks'))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit('SMB/Registry/Enumerated', exit_code:1);

# Get path information for Windows.

var install = get_single_install(app_name:app_name);
if(install['Product'] != '2019') audit(AUDIT_HOST_NOT, 'affected: Server is Sharepoint ' + install['Product']);
if(install['Edition'] != 'Server') audit(AUDIT_HOST_NOT, 'affected: Server Edition is ' + install['Edition']);

var windir = hotfix_get_systemroot();
if (isnull(windir)) exit(1, 'Failed to determine the location of %windir%.');
registry_init();

var kb_checks =
{
  'Server':
  {
    'kb'           : '5002054',
    'path'         : install['path'],
    'version'      : '16.0.10381.20001',
    'append'       : 'bin',
    'file'         : 'ascalc.dll',
    'product_name' : 'Microsoft SharePoint Enterprise Server 2019'
  }
};

# Get the specific product / path

var port = kb_smb_transport();
# grab the path otherwise
var check;
foreach check (kb_checks)
{
  if (!isnull(check['version']))
  {
    var path = check['path'];
    if (!empty_or_null(check['append']))
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
    var report = '\n';
    if (check['product_name'])
      report += '  Product : ' + check['product_name'] + '\n';
    if (check['kb'])
      report += '  KB : ' + check['kb'] + '\n';
    hotfix_add_report(report, kb:check['kb']);
  }

  if(are_we_vuln == HCF_OLDER) vuln = TRUE;

}
if (vuln)
{
  port = kb_smb_transport();
  replace_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_INST_VER_NOT_VULN, app_name);
}

