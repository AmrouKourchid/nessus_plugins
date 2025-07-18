#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#
##

include('compat.inc');

if (description)
{
  script_id(234040);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/11");

  script_cve_id("CVE-2025-26642","CVE-2025-27746","CVE-2025-27751");
  script_xref(name:"MSKB", value:"5002699");
  script_xref(name:"MSFT", value:"MS25-5002699");
  script_xref(name:"IAVA", value:"2025-A-0245");
  script_xref(name:"IAVA", value:"2025-A-0246");

  script_name(english:"Security Updates for Microsoft Office Online Server  (April 2025)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office Online Server installation on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office Online Server installation on the remote host is missing security updates. It is, therefore,
affected by multiple vulnerabilities:
  - A remote code execution vulnerability. An attacker can exploit this to bypass authentication and execute
    unauthorized arbitrary commands. (CVE-2025-26642, CVE-2025-27746, CVE-2025-27751)");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5002699");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released KB5002699 to address this issue.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-26642");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_web_apps");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("office_installed.nasl", "microsoft_owa_installed.nbin", "microsoft_office_compatibility_pack_installed.nbin", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');
include('install_func.inc');

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

var path, vuln;

var bulletin = 'MS25-04';
var kbs = make_list('5002699');


if (get_kb_item('Host/patch_management_checks'))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/Registry/Enumerated', exit_code:1);

var port = kb_smb_transport();

# Get installs of Office Web Apps
var owa_installs = get_installs(app_name:'Microsoft Office Web Apps');

if (!empty_or_null(owa_installs))
{
  var owa_install;
  foreach owa_install (owa_installs[1])
  {
    if (owa_install['Product'] == '2016')
    {
      var oos_path = owa_install['path'];
      var oos_sp = owa_install['SP'];
    }
  }
}
vuln = FALSE;

####################################################################
# Office Online Server
####################################################################
if (oos_path && (!isnull(oos_sp) && oos_sp == '0'))
{
  path = hotfix_append_path(path:oos_path, value:'ExcelServicesEcs\\bin');
  if (hotfix_check_fversion(file:'xlsrv.dll', version:'16.0.10417.20003', min_version:'16.0.10000.0', path:path, kb:'5002699', product:'Office Online Server') == HCF_OLDER)
    vuln = TRUE;
}


if (vuln)
{
  replace_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
