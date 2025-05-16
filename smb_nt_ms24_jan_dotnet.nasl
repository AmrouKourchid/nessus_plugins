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
  script_id(187901);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/29");

  script_cve_id(
    "CVE-2023-36042",
    "CVE-2024-0056",
    "CVE-2024-0057",
    "CVE-2024-21312"
  );
  script_xref(name:"MSKB", value:"5033898");
  script_xref(name:"MSKB", value:"5033899");
  script_xref(name:"MSKB", value:"5033904");
  script_xref(name:"MSKB", value:"5033907");
  script_xref(name:"MSKB", value:"5033909");
  script_xref(name:"MSKB", value:"5033910");
  script_xref(name:"MSKB", value:"5033911");
  script_xref(name:"MSKB", value:"5033912");
  script_xref(name:"MSKB", value:"5033914");
  script_xref(name:"MSKB", value:"5033916");
  script_xref(name:"MSKB", value:"5033917");
  script_xref(name:"MSKB", value:"5033918");
  script_xref(name:"MSKB", value:"5033919");
  script_xref(name:"MSKB", value:"5033920");
  script_xref(name:"MSKB", value:"5033922");
  script_xref(name:"MSKB", value:"5033945");
  script_xref(name:"MSKB", value:"5033946");
  script_xref(name:"MSKB", value:"5033947");
  script_xref(name:"MSKB", value:"5033948");
  script_xref(name:"MSFT", value:"MS24-5033898");
  script_xref(name:"MSFT", value:"MS24-5033899");
  script_xref(name:"MSFT", value:"MS24-5033904");
  script_xref(name:"MSFT", value:"MS24-5033907");
  script_xref(name:"MSFT", value:"MS24-5033909");
  script_xref(name:"MSFT", value:"MS24-5033910");
  script_xref(name:"MSFT", value:"MS24-5033911");
  script_xref(name:"MSFT", value:"MS24-5033912");
  script_xref(name:"MSFT", value:"MS24-5033914");
  script_xref(name:"MSFT", value:"MS24-5033916");
  script_xref(name:"MSFT", value:"MS24-5033917");
  script_xref(name:"MSFT", value:"MS24-5033918");
  script_xref(name:"MSFT", value:"MS24-5033919");
  script_xref(name:"MSFT", value:"MS24-5033920");
  script_xref(name:"MSFT", value:"MS24-5033922");
  script_xref(name:"MSFT", value:"MS24-5033945");
  script_xref(name:"MSFT", value:"MS24-5033946");
  script_xref(name:"MSFT", value:"MS24-5033947");
  script_xref(name:"MSFT", value:"MS24-5033948");
  script_xref(name:"IAVA", value:"2024-A-0011-S");

  script_name(english:"Security Updates for Microsoft .NET Framework (January 2024)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft .NET Framework installation on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft .NET Framework installation on the remote host is missing a security update. It is, therefore, affected
by multiple vulnerabilities, as follows:

  - Denial of service vulnerability in Microsoft .NET Framework. (CVE-2023-36042, CVE-2024-21312)

  - Security feature bypass in System.Data.SqlClient SQL data provider. An attacker can perform a
    man-in-the-middle attack on the connection between the client and server in order to read and modify the
    TLS traffic. (CVE-2024-0056)

  - Security feature bypass in applications that use the X.509 chain building APIs. When processing an
    untrusted certificate with malformed signatures, the framework returns an incorrect reason code.
    Applications which make use of this reason code may treat this scenario as a successful chain build,
    potentially bypassing the application's typical authentication logic. (CVE-2024-0057)");
  # https://devblogs.microsoft.com/dotnet/dotnet-framework-january-2024-security-and-quality-rollup/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a8f77e6e");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36042");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-0056");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-0057");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21312");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5033898");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5033899");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5033904");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5033907");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5033909");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5033910");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5033911");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5033912");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5033914");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5033916");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5033917");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5033918");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5033919");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5033920");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5033922");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5033945");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5033946");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5033947");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5033948");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released security updates for Microsoft .NET Framework.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-0057");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_framework");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

var bulletin = 'MS24-01';
var kbs = make_list(
  '5033898',
  '5033899',
  '5033904',
  '5033907',
  '5033909',
  '5033910',
  '5033911',
  '5033912',
  '5033914',
  '5033916',
  '5033917',
  '5033918',
  '5033919',
  '5033920',
  '5033922',
  '5033945',
  '5033946',
  '5033947',
  '5033948'
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

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
        smb_check_dotnet_rollup(rollup_date:'01_2024', dotnet_ver:version))
      vuln++;
  }
}
if(vuln)
{
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
