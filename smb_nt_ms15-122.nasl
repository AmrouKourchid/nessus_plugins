#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(86828);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/12");

  script_cve_id("CVE-2015-6095");
  script_bugtraq_id(77475);
  script_xref(name:"MSFT", value:"MS15-122");
  script_xref(name:"MSKB", value:"3101246");
  script_xref(name:"MSKB", value:"3105213");
  script_xref(name:"MSKB", value:"3105211");
  script_xref(name:"IAVA", value:"2015-A-0278");

  script_name(english:"MS15-122: Security Update for Kerberos to Address Security Feature Bypass (3105256)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by a security feature bypass
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is affected by a security feature bypass
vulnerability in Kerberos due to a failure to check the password
change of a user signing into a workstation. A remote attacker can
exploit this vulnerability by connecting a workstation to a malicious
Kerberos Key Distribution Center (KDC), resulting in the ability to
decrypt drives protected by BitLocker.

Note that this vulnerability can only be exploited if the target
system has BitLocker enabled without a PIN or USB key, and the
computer is domain-joined.");
  # https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2015/ms15-122
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a5f58ee1");
  # https://support.microsoft.com/en-us/topic/ms15-122-description-of-the-security-update-for-windows-kerberos-november-10-2015-d2e80a23-2e28-05ea-10c2-9094b3531d49
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?34a741e7");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista, 2008, 7,
2008 R2, 8, RT, 2012, 8.1, RT 8.1, 2012 R2, and 10.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-6095");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/11/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2015-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('smb_hotfixes_fcheck.inc');
include('smb_hotfixes.inc');
include('smb_func.inc');

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

var bulletin = 'MS15-122';

var kb = "3101246";
var kbs = make_list("3101246","3105213","3105211");

if (get_kb_item("Host/patch_management_checks"))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

# Exclude all but affected OS
var productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if (productname =~ "Windows(?: Server)?\s(10|8|7|20[01][28]|Vista)")
{
  if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0', win81:'0', win10: '0') <= 0)
    audit(AUDIT_OS_SP_NOT_VULN);

  var share = hotfix_get_systemdrive(exit_on_fail:TRUE, as_share:TRUE);
  if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

  if (
    # Windows 10
    hotfix_is_vulnerable(os:"10", file:"Kerberos.dll", version:"10.0.10586.3", min_version:"10.0.10586.0", dir:"\system32", bulletin:bulletin, kb:"3105211") ||
    hotfix_is_vulnerable(os:"10", file:"Kerberos.dll", version:"10.0.10240.16590", dir:"\system32", bulletin:bulletin, kb:"3105213") ||
    # Windows 8.1 / 2012 R2
    hotfix_is_vulnerable(os:"6.3", file:"Kerberos.dll", version:"6.3.9600.18091", min_version:"6.3.9600.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||
    # Windows 8 / 2012
    hotfix_is_vulnerable(os:"6.2", file:"Kerberos.dll", version:"6.2.9200.21674", min_version:"6.2.9200.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
    hotfix_is_vulnerable(os:"6.2", file:"Kerberos.dll", version:"6.2.9200.17557", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||
    # Windows 7 / 2008 R2
    hotfix_is_vulnerable(os:"6.1", sp:1, file:"Kerberos.dll", version:"6.1.7601.23249", min_version:"6.1.7601.22000", dir:"\system32", bulletin:bulletin, kb:kb) ||
    hotfix_is_vulnerable(os:"6.1", sp:1, file:"Kerberos.dll", version:"6.1.7601.19043", min_version:"6.1.7600.18000", dir:"\system32", bulletin:bulletin, kb:kb) ||
    # Vista / 2008
    hotfix_is_vulnerable(os:"6.0", sp:2, file:"Kerberos.dll", version:"6.0.6002.23835", min_version:"6.0.6002.23000", dir:"\system32", bulletin:bulletin, kb:kb) ||
    hotfix_is_vulnerable(os:"6.0", sp:2, file:"Kerberos.dll", version:"6.0.6002.19525", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:kb)
  )
  {
    set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
    hotfix_security_warning();
    hotfix_check_fversion_end();
    exit(0);
  }
  else
  {
    hotfix_check_fversion_end();
    audit(AUDIT_HOST_NOT, 'affected');
  }
}
else audit(AUDIT_OS_SP_NOT_VULN);