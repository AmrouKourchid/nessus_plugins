#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#

include('compat.inc');

if (description)
{
  script_id(168395);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/20");

  script_cve_id("CVE-2022-26832");
  script_xref(name:"MSKB", value:"5012117");
  script_xref(name:"MSKB", value:"5012118");
  script_xref(name:"MSKB", value:"5012119");
  script_xref(name:"MSKB", value:"5012120");
  script_xref(name:"MSKB", value:"5012121");
  script_xref(name:"MSKB", value:"5012122");
  script_xref(name:"MSKB", value:"5012123");
  script_xref(name:"MSKB", value:"5012124");
  script_xref(name:"MSKB", value:"5012125");
  script_xref(name:"MSKB", value:"5012128");
  script_xref(name:"MSKB", value:"5012129");
  script_xref(name:"MSKB", value:"5012130");
  script_xref(name:"MSKB", value:"5012131");
  script_xref(name:"MSKB", value:"5012136");
  script_xref(name:"MSKB", value:"5012137");
  script_xref(name:"MSKB", value:"5012138");
  script_xref(name:"MSKB", value:"5012139");
  script_xref(name:"MSKB", value:"5012140");
  script_xref(name:"MSKB", value:"5012141");
  script_xref(name:"MSKB", value:"5012142");
  script_xref(name:"MSKB", value:"5012143");
  script_xref(name:"MSKB", value:"5012144");
  script_xref(name:"MSKB", value:"5012145");
  script_xref(name:"MSKB", value:"5012146");
  script_xref(name:"MSKB", value:"5012147");
  script_xref(name:"MSKB", value:"5012148");
  script_xref(name:"MSKB", value:"5012149");
  script_xref(name:"MSKB", value:"5012150");
  script_xref(name:"MSKB", value:"5012151");
  script_xref(name:"MSKB", value:"5012152");
  script_xref(name:"MSKB", value:"5012153");
  script_xref(name:"MSKB", value:"5012154");
  script_xref(name:"MSKB", value:"5012155");
  script_xref(name:"MSFT", value:"MS22-5012117");
  script_xref(name:"MSFT", value:"MS22-5012118");
  script_xref(name:"MSFT", value:"MS22-5012119");
  script_xref(name:"MSFT", value:"MS22-5012120");
  script_xref(name:"MSFT", value:"MS22-5012121");
  script_xref(name:"MSFT", value:"MS22-5012122");
  script_xref(name:"MSFT", value:"MS22-5012123");
  script_xref(name:"MSFT", value:"MS22-5012124");
  script_xref(name:"MSFT", value:"MS22-5012125");
  script_xref(name:"MSFT", value:"MS22-5012128");
  script_xref(name:"MSFT", value:"MS22-5012129");
  script_xref(name:"MSFT", value:"MS22-5012130");
  script_xref(name:"MSFT", value:"MS22-5012131");
  script_xref(name:"MSFT", value:"MS22-5012136");
  script_xref(name:"MSFT", value:"MS22-5012137");
  script_xref(name:"MSFT", value:"MS22-5012138");
  script_xref(name:"MSFT", value:"MS22-5012139");
  script_xref(name:"MSFT", value:"MS22-5012140");
  script_xref(name:"MSFT", value:"MS22-5012141");
  script_xref(name:"MSFT", value:"MS22-5012142");
  script_xref(name:"MSFT", value:"MS22-5012143");
  script_xref(name:"MSFT", value:"MS22-5012144");
  script_xref(name:"MSFT", value:"MS22-5012145");
  script_xref(name:"MSFT", value:"MS22-5012146");
  script_xref(name:"MSFT", value:"MS22-5012147");
  script_xref(name:"MSFT", value:"MS22-5012148");
  script_xref(name:"MSFT", value:"MS22-5012149");
  script_xref(name:"MSFT", value:"MS22-5012150");
  script_xref(name:"MSFT", value:"MS22-5012151");
  script_xref(name:"MSFT", value:"MS22-5012152");
  script_xref(name:"MSFT", value:"MS22-5012153");
  script_xref(name:"MSFT", value:"MS22-5012154");
  script_xref(name:"MSFT", value:"MS22-5012155");
  script_xref(name:"IAVA", value:"2022-A-0143-S");

  script_name(english:"Security Updates for Microsoft .NET Framework (April 2022)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft .NET Framework installation on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft .NET Framework installation on the remote host is missing a security update. It is, therefore, affected
by a denial of service vulnerability.");
  # https://devblogs.microsoft.com/dotnet/dotnet-framework-april-2022-updates/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?496ec3f1");
  # https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-26832
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eff833d3");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5012117");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5012118");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5012119");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5012120");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5012121");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5012122");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5012123");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5012124");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5012125");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5012128");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5012129");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5012130");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5012131");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5012136");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5012137");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5012138");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5012139");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5012140");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5012141");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5012142");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5012143");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5012144");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5012145");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5012146");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5012147");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5012148");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5012149");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5012150");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5012151");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5012152");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5012153");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5012154");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5012155");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released security updates for Microsoft .NET Framework.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-26832");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_framework");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_check_dotnet_rollup.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl", "microsoft_net_framework_installed.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('install_func.inc');
include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

var bulletin = 'MS22-04';
var kbs = make_list(
  '5012117',
  '5012118',
  '5012119',
  '5012120',
  '5012121',
  '5012122',
  '5012123',
  '5012124',
  '5012125',
  '5012128',
  '5012129',
  '5012130',
  '5012131',
  '5012136',
  '5012137',
  '5012138',
  '5012139',
  '5012140',
  '5012141',
  '5012142',
  '5012143',
  '5012144',
  '5012145',
  '5012146',
  '5012147',
  '5012148',
  '5012149',
  '5012150',
  '5012151',
  '5012152',
  '5012153',
  '5012154',
  '5012155'
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit('SMB/Registry/Enumerated');
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(vista:'2' , win7:'1', win8:'0', win81:'0', win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

var share = hotfix_get_systemdrive(exit_on_fail:TRUE, as_share:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

var app = 'Microsoft .NET Framework';
get_install_count(app_name:app, exit_if_zero:TRUE);
var installs = get_combined_installs(app_name:app);

var install, version;
var vuln = 0;

if (installs[0] == 0)
{
  foreach install (installs[1])
  {
    version = install['version'];
    if( version != UNKNOWN_VER &&
        smb_check_dotnet_rollup(rollup_date:'04_2022', dotnet_ver:version))
      vuln++;
  }
}
if(vuln)
{
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
