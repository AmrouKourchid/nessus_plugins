##
# (C) Tenable, Inc.
##
#
# This script has been written by Montgomery County Maryland
# This script is released under GPLv2
#
# For reference, below are the released Internet Explorer versions.
# This information is from:
# http://support.microsoft.com/kb/164539/
#  Version		Product
#
#  4.40.308		Internet Explorer 1.0 (Plus!)
#  4.40.520		Internet Explorer 2.0
#  4.70.1155		Internet Explorer 3.0
#  4.70.1158		Internet Explorer 3.0 (OSR2)
#  4.70.1215		Internet Explorer 3.01
#  4.70.1300		Internet Explorer 3.02 and 3.02a
#  4.71.544		Internet Explorer 4.0 Platform Preview 1.0 (PP1)
#  4.71.1008.3		Internet Explorer 4.0 Platform Preview 2.0 (PP2)
#  4.71.1712.6		Internet Explorer 4.0
#  4.72.2106.8		Internet Explorer 4.01
#  4.72.3110.8		Internet Explorer 4.01 Service Pack 1 (SP1)
#  4.72.3612.1713	Internet Explorer 4.01 Service Pack 2 (SP2)
#  5.00.0518.10		Internet Explorer 5 Developer Preview (Beta 1)
#  5.00.0910.1309	Internet Explorer 5 Beta (Beta 2)
#  5.00.2014.0216	Internet Explorer 5
#  5.00.2314.1003	Internet Explorer 5 (Office 2000)
#  5.00.2614.3500	Internet Explorer 5 (Windows 98 Second Edition)
#  5.00.2516.1900	Internet Explorer 5.01 (Windows 2000 Beta 3, build 5.00.2031)
#  5.00.2919.800	Internet Explorer 5.01 (Windows 2000 RC1, build 5.00.2072)
#  5.00.2919.3800	Internet Explorer 5.01 (Windows 2000 RC2, build 5.00.2128)
#  5.00.2919.6307	Internet Explorer 5.01 (Also included with Office 2000 SR-1, but not installed by default)
#  5.00.2920.0000	Internet Explorer 5.01 (Windows 2000, build 5.00.2195)
#  5.00.3103.1000	Internet Explorer 5.01 SP1 (Windows 2000)
#  5.00.3105.0106	Internet Explorer 5.01 SP1 (Windows 95/98 and Windows NT 4.0)
#  5.00.3314.2101	Internet Explorer 5.01 SP2 (Windows 95/98 and Windows NT 4.0)
#  5.00.3315.1000	Internet Explorer 5.01 SP2 (Windows 2000)
#  5.50.3825.1300	Internet Explorer 5.5 Developer Preview (Beta)
#  5.50.4030.2400	Internet Explorer 5.5 & Internet Tools Beta
#  5.50.4134.0100	Windows Me (4.90.3000)
#  5.50.4134.0600	Internet Explorer 5.5
#  5.50.4308.2900	Internet Explorer 5.5 Advanced Security Privacy Beta
#  5.50.4522.1800	Internet Explorer 5.5 Service Pack 1
#  5.50.4807.2300	Internet Explorer 5.5 Service Pack 2
#  6.00.2462.0000	Internet Explorer 6 Public Preview (Beta)
#  6.00.2479.0006	Internet Explorer 6 Public Preview (Beta) Refresh
#  6.00.2600.0000	Internet Explorer 6
#  6.00.2800.1106	Internet Explorer 6 Service Pack 1 (Windows XP SP1)
#  6.00.2900.2180	Internet Explorer 6 Service Pack 2 (Windows XP SP2)
#  6.00.3663.0000	Internet Explorer 6 for Microsoft Windows Server 2003 RC1
#  6.00.3718.0000	Internet Explorer 6 for Windows Server 2003 RC2
#  6.00.3790.0000	Internet Explorer 6 for Windows Server 2003 (released)
#  6.00.3790.1830	Internet Explorer 6 for Windows Server 2003 SP1 and Windows XP x64
#  6.00.3790.3959	Internet Explorer 6 SP2 for Windows Server 2003 SP1 and Windows XP x64
#  7.00.5730.1100	Internet Explorer 7 for Windows XP and Windows Server 2003
#  7.00.5730.1300	Internet Explorer 7 for Windows XP and Windows Server 2003
#  7.00.6000.16386	Internet Explorer 7 for Windows Vista
#  7.00.6000.16441	Internet Explorer 7 for Windows Server 2003 SP2 x64
#  7.00.6000.16441	Internet Explorer 7 for Windows XP SP2 x64
#  7.00.6001.1800	Internet Explorer 7 for Windows Server 2008 and for Windows Vista SP1
#  8.00.6001.17184	Internet Explorer 8 Beta 1
#  8.00.6001.18241	Internet Explorer 8 Beta 2
#  8.00.6001.18372	Internet Explorer 8 RC1
#  8.00.6001.18702	Internet Explorer 8 for Windows XP, Windows Vista, Windows Server 2003 and Windows Server 2008
#  8.00.7000.00000	Internet Explorer 8 for Windows 7 Beta

include('compat.inc');

if (description)
{
  script_id(22024);
  script_version("1.31");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/06");

  script_xref(name:"IAVA", value:"0001-A-0557");

  script_name(english:"Microsoft Internet Explorer Unsupported Version Detection");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an unsupported version of Internet Explorer.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the installation of
Microsoft Internet Explorer on the remote Windows host is no longer
supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
# https://learn.microsoft.com/en-us/lifecycle/faq/internet-explorer-microsoft-edge
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?828ddfe1");
# https://support.microsoft.com/en-us/hub/4095338/microsoft-lifecycle-policy#gp/Microsoft-Internet-Explorer
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e0d2ff5a");
  script_set_attribute(attribute:"see_also", value:"https://docs.microsoft.com/en-us/deployedge/edge-ie-disable-ie11");
  script_set_attribute(attribute:"solution", value:
"Either Upgrade to a version of Internet Explorer that is currently supported
or disable Internet Explorer on the target device.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Tenable score for unsupported products.");

  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:ie");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"agent", value:"windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2006-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_login.nasl", "smb_registry_full_access.nasl", "smb_hotfixes.nasl", "smb_check_rollup.nasl");
  script_require_keys("SMB/registry_full_access", "SMB/Registry/Enumerated", "SMB/IE/Version");
  script_require_ports(139, 445);
  exit(0);
}

include('smb_func.inc');
include('smb_hotfixes.inc');

#==================================================================#
# Main code                                                        #
#==================================================================#
var warning = 0;

get_kb_item_or_exit("SMB/registry_full_access");
get_kb_item_or_exit("SMB/Registry/Enumerated");

# Note: only IE 4.0 and later will be detected by this kb item
var version = get_kb_item_or_exit("SMB/IE/Version");
var os = get_kb_item("SMB/WindowsVersion");
var os_name = get_kb_item("SMB/ProductName");
var os_build = get_kb_item('SMB/WindowsVersionBuild');
var port = get_kb_item("SMB/transport");
var esu = get_kb_item("WMI/W7_2008R2_ESU");
var reason, policy;

# Initialize registry
registry_init();

var reg_item = "SOFTWARE\Policies\Microsoft\Edge\Recommended\InternetExplorerIntegrationReloadInIEModeAllowed";
var hklm_hive = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

##
# The policy does not apply to a specific version of Internet Explorer or Windows OS. Therefore, we should report 
# InternetExplorerIntegrationReloadInIEModeAllowed policy when enabled or not configured as its own finding attached 
# to the report.
#
# Note: Report paranoia still needs to be enabled to report IE for Windows 11. However, for legacy Windows, the policy 
# note will show up in report when the policy is enabled or not configured as explained by Microsoft on Edge policies.
# 
# If get_registry_value returns empty or null from the handle created, then the registry value does not exist, which
# means it has not been configured on the host, and we should thus handle this per Microsoft Edge Policy recommendation, 
# which states, "If the InternetExplorerIntegrationReloadInIEModeAllowed policy is enabled or not configured, users will 
# be able to tell Microsoft Edge to load specific pages in Internet Explorer mode for a limited number of days." 
#
# Meaning, the policy also gets ammeded to the report if it cannot be found in the registry.
#
# More information:
#  https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies#internetexplorerintegrationreloadiniemodeallowed
##
var ie_mode_allowed = get_registry_value(handle:hklm_hive, item:reg_item);
if (empty_or_null(ie_mode_allowed))  // empty means policy not configured
{
  policy = 'The InternetExplorerIntegrationReloadInIEModeAllowed policy is not configured\n' + 
  'which means users can render content in IE Mode.\n';
}
else
{
   # 'Enabled' is 0x00000001 or 1, while empty value means 'Not Configured'
   if (ie_mode_allowed == '1')
   {
     policy = 'The InternetExplorerIntegrationReloadInIEModeAllowed policy is enabled\n' + 
     'or not configured on the host, which means users can render content in IE Mode.\n';
   }
   if (ie_mode_allowed == '0')
   {
    dbg::detailed_log(
      lvl : 1, 
      msg : "The InternetExplorerIntegrationReloadInIEModeAllowed policy is disabled.");
   }
}

# Close handle 
RegCloseKey(handle:hklm_hive);

# Close registry
close_registry();

##
# RES-137899: Check if KB5022834 is installed on Windows 10
# Supported OS Builds: 19042, 19044, and 19045
# 
# Note: February 14, 2023, the retired, out-of-support Internet Explorer 11 desktop application will be permanently 
# turned off using a Microsoft Edge update on certain versions of Windows 10.
# KB Article and Tech Notes:
#    http://www.nessus.org/u?d73959c8
#    http://www.nessus.org/u?3ed3d47d
#
# We should use the KBs stored in SMB/Microsoft/qfes as this matches the output from the systeminfo command and
# reflects each of the installed KB items on the host.
#
# In case KB5022834 is not detected as installed, we check for the latest rollup installed.
# If that rollup date is greater than February 2023 (release of KB5022834) then we consider that a KB
# superseeding KB5022834 is installed, and so IE is disabled.
#
# Note: the latest rollup date has to be strictly greater than 2023.02 because if it's equal to 2023.02
# and KB5022834 has not been detected as installed, then something is seriously wrong.
##
var kb5022834_installed = FALSE;
if (("enterprise" >< tolower(os_name) || "education" >< tolower(os_name) || "pro" >< tolower(os_name) || "home" >< tolower(os_name)) && (pgrep(pattern:"^10", string:os) && pgrep(pattern:"^11\.", string:version)) && os_build < 22000)
{
  var qfes = get_kb_item("SMB/Microsoft/qfes"); # Get list of installed KBs
  var latest_eff = get_kb_item("smb_rollup/latest");
  qfes = split(qfes, sep:',', keep:FALSE);
  foreach var kb (qfes)
  {
    if (kb == 'KB5022834')
    {
      # When flag set to TRUE, do not report warning for IE 11 on 20H2 or later
      dbg::detailed_log(lvl:1, msg:"KB5022834 is installed on the host.");
      kb5022834_installed = TRUE;
      break;
    }
  }
  # If KB5022834 is not installed then check the latest rollup date is strictly greater than 2023.02
  if (!kb5022834_installed && latest_eff =~ "^[0-9]+_[0-9]+$")
  {
    var key_segs = split(latest_eff, sep:'_', keep:FALSE);
    var int_var = key_segs[0];
    key_segs[0] = key_segs[1];
    key_segs[1] = int_var;
    var latest_date = join(key_segs, sep:'.');
    if (ver_compare(ver:latest_date, fix:'2023.02', strict:FALSE) > 0)
    {
      dbg::detailed_log(lvl:1, msg:"Rollup from " + latest_eff + " is installed which supersedes KB5022834.");
      kb5022834_installed = TRUE;
      break;
    }
  }
  if (kb5022834_installed)
  {
    audit(AUDIT_INST_VER_NOT_VULN, "Internet Explorer", version);
  }
  else
  {
    warning = 1;
    reason = 'Internet Explorer was found on the host and may still be available for use as a\n' +
    'standalone browser. To prevent the use of Internet Explorer, Microsoft has included a\n' +
    'Browser Helper Object (BHO) to handle redirects from Internet Explorer to Edge.';
  }
}

# https://techcommunity.microsoft.com/t5/windows-it-pro-blog/internet-explorer-11-desktop-app-retirement-faq/ba-p/2366549
if (tolower(os_name) =~ "(embedded|thin pc|industry update)")
  audit(AUDIT_OS_NOT, "a Windows desktop or server version");

# Check for 4.x to 8.x
if (pgrep(pattern:"^[4-8]\.", string:version))
  warning = 1;
# IE 9 on anything but Server 2008 ESU
else if (pgrep(pattern:"^[9]\.", string:version))
{
  if (tolower(os_name) =~ 'server 2008' && esu == 1)
    warning = 0;
  else
    warning = 1;
}
# IE 10 on anything
else if (pgrep(pattern:"^10\.", string:version))
{
  warning = 1;
}
# IE Legacy mode on W11. os build >= 22000 is windows 11 only
else if (pgrep(pattern:"^11\.", string:version) && os_build >= 22000)
{ 
  audit(AUDIT_INST_VER_NOT_VULN, "Internet Explorer", version);
}
else if (pgrep(pattern:"^11\.", string:version) && ("server" >< tolower(os_name)))
{
  audit(AUDIT_INST_VER_NOT_VULN, "Internet Explorer", version);
}
# https://learn.microsoft.com/en-us/troubleshoot/developer/browsers/general/information-about-ie-version#:~:text=Internet%20Explorer%2011%20will%20have%20a%20version%20number%20that%20starts%20with%2011.0.9600.*****%20on%3A
# Internet Explorer 11 will have a version number that starts with 11.0.9600.***** on:
# Windows 7
# Windows 8.1
# Windows Server 2008 R2
# Windows Server 2012
# Windows Server 2012 R2
# and are still supported
else if (pgrep(pattern:"^11\.0\.9600", string:version))
{
  audit(AUDIT_INST_VER_NOT_VULN, "Internet Explorer", version);
}
else
{
  warning = 1;
}

#==================================================================#
# Final Report                                                     #
#==================================================================#
if (warning)
{
  var report = strcat('\n',
    "The remote host has Internet Explorer version ",version,
    " installed, which is no longer supported.",
    '\n' , reason, '\n', policy);
  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
  exit(0);
}
audit(AUDIT_INST_VER_NOT_VULN, "Internet Explorer", version);
