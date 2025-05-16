#
# (C) Tenable 2018 
# 
# artifact_scrub_list.inc
# Revision 1.2
#

namespace data_protection
{
  global_var kb_scrub_list_users = make_list(
    "WMI/LocalGroups/*",
    "WMI/LocalUsers/*",
    "WMI/DomainUsers/*",
    "kerberos/*@*/tgs_session*",
    "Host/AWS/AMI/*-id",
    "SMB/host_sid",
    "SMB/null_session/host_sid",
    "SMB/last_user_login",
    "SMB/LocalUsers/*",
    "SMB/Users/AutoDisabled/*",
    "SMB/Users/PwCantChange/*",
    "SMB/Users/Disabled/*",
    "SMB/Users/NeverChangedPw/*",
    "SMB/Users/NeverLoggedOn/*",
    "SMB/Users/PwNeverExpires/*",
    "*/username",
    "*/usernames",
    "*UserName",
    "*/Groups",
    "*/LocalGroups",
    "rsh/login_*",
    "SMB/primary_domain",
    "SMB/domain_sid",
    "SMB/shares",
    "SMB/account_domain",
    "LDAP/DomainAdmins/Members/*",
    "LDAP/Groups/*",
    "Host/Users/*/Groups",
    "Host/Users",
    "SSH/LocalUsers/PwNeverExpires/*",
    "Host/MacOSX/Users",
    "Host/MacOSX/Users/*/Groups",
    "SSH/LocalAdmins/Members/*",
    "*/login",
    "*/Login",
    "registry/shellfolder/*",
    "Host/Google Compute Engine/name",
    "Host/Google Compute Engine/id"
  );

  global_var kb_scrub_list_passwords = make_list(
    "*/password",
    "*/Password"
  );

  global_var kb_scrub_list_emails = make_list(
    "www/*/mailto",
    "www/*/mailto/*"
  );

  global_var kb_scrub_list_ips = make_list(
    "*/hosts",
    "botnet_traffic/inbound/report",
    "ipthreat/lookup/custom/inbound",
    "ipthreat/lookup/custom/outbound",
    "Host/SMB/InterfaceList",
    "Host/SMB/RoutingInfo",
    "Host/Windows/netstat_an*",
    "Host/AWS/AMI/*hostname",
    "traceroute-hop/*",
    "upnp/*",
    "Host/netstat-ian",
    "Host/netstat-ianf-inet6",
    "Host/lanscan-ai",
    "Host/fwrules/output/*",
    "*/ifconfig",
    "Host/netstat_anp",
    "Host/netstat_Aan",
    "routes//nexthop",
    "nat-pmp/*/public-ip",
    "Host/Netbios/IP",
    "SMB/name",
    "Netstat/listen-*",
    "Netstat/established-*",
    "SMB/browse",
    "socks*/external_addr/*",
    "*/FQDN",
    "*IP4Addrs",
    "*IP6Addrs",
    "*ipv4",
    "*ipv6",
    "*/addr",
    "*/privateIp",
    "*/ip",
    "*/external-ip",
    "Host/Google Compute Engine/hostname",
    "Host/Google Compute Engine/*ip",
    "*/hostname",
    "*/Hostname",
    "myHostName"
  );

  global_var kb_scrub_list_paths = make_list(
    "www/*/login_form",
    "www/*/content/clickable-event/*",
    "www/*/header/missing/*",
    "www/*/content/extensions/*",
    "/tmp/404/*",
    "/tmp/XSS/*",
    "Cache/*/URL_*",
    "Host/JBoss/*",
    "relabs/known_good",
    "linux/relabs/unknown",
    "linux/relabs/known",
    "macosx/relabs/unknown",
    "macosx/relabs/known",
    "Host/MDM/MobileIron/url_base",
    "WMI/Host/*DriveWithFS",
    "Services/comelit/*",
    "MacOSX/Google Chrome/*",
    "SMB/db2/*",
    "SMB/IBM CLM/*",
    "malscan/filescan/baddir",
    "MacOSX/Adobe_Acrobat/*",
    "MacOSX/Keynote/*",
    "MacOSX/Pages/*",
    "SMB/FileVersions/*",
    "SMB/User Directory",
    "SMB/AccessibleShare/*",
    "HKEY_USERS\*",
    "www/*/installed_cgi",
    "www/*/get_cgi*",
    "/tmp/cgibin",
    "www/*/cgibin",
    "www/*/directories",
    "SMB/Wireshark/*",
    "Versant/*",
    "SMB/VirtualBox/*",
    "SMB/VLC/plugin",
    "www/*/links/*",
    "www/*/referers/*",
    "www/*/console/*",
    "www/*/content/*",
    "www/*/infected/pages",
    "www/*/java_classfile",
    "www/*/password-form",
    "www/*/password-params/*",
    "www/*/cgi",
    "SMB/Solarwinds/tftp_server/*",
    "Host/Java/JRE/*",
    "SMB/Symantec System Recovery/Installs/*",
    "SMB/Symantec Backup Exec Server/Installs*",
    "SMB/System Center Operations Manager/Install/*",
    "SMB/TeamViewer/*",
    "tftp/*/filecontent/*",
    "*path",
    "*Path",
    "SMB/Mozilla/Firefox/*",
    "SMB/Mozilla/Thunderbird/*",
    "SMB/SeaMonkey/*",
    "mssql/installs/*",
    "SMB/Java/JRE/*",
    "Java/JRE/*",
    "Antivirus/Panda/*",
    "SMB/Symantec/SMSSMTP/*",
    "ftp/*writeable_dir",
    "SMB/Google_Chrome/*",
    "SMB/Google_SketchUp/*",
    "SMB/Trimble_SketchUp/*",
    "Antivirus/Kaspersky/*",
    "Antivirus/*/description",
    "MacOSX/Adobe_Reader/*",
    "MacOSX/Bitcoin/*",
    "MacOSX/Adobe Flash Professional/*",
    "MacOSX/Remote_Desktop_Admin/*",
    "SMB/Mozilla/*",
    "*/path_to_exe",
    "*/uri",
    "AntiVirus/Check Point ZoneAlarm/*",
    "www/*/chora",
    "Host/Cisco/IOS/ImageExecutionLocation",
    "www/coldfusion/*",
    "SMB/coldfusion/*",
    "www/*/content/directories/*",
    "registry/shellfolder/*",
    "*/InstallLocation",
    "SMB/FlashFXP/Installs/*",
    "SMB/Adobe Flash Professional/Installs/*",
    "SMB/net_framework/InstallRoot"
  );

  global_var scratchpad_scrub_list = make_array();
  scratchpad_scrub_list['mdm_devices']['user'] = "user";
  scratchpad_scrub_list['maas360_device_info']['username'] = "user";
  scratchpad_scrub_list['airwatch_DeviceInfo']['UserName'] = "user";
  scratchpad_scrub_list['airwatch_DeviceInfo']['UserId'] = "user";
  scratchpad_scrub_list['mobileiron_deviceInfo']['name'] = "user";
  scratchpad_scrub_list['mobileiron_deviceInfo']['userDisplayName'] = "user";
  scratchpad_scrub_list['mobileiron_deviceInfo']['userFirstName'] = "user";
  scratchpad_scrub_list['mobileiron_deviceInfo']['userLastName'] = "user";
  scratchpad_scrub_list['airwatch_basicprofile_info']['OrganizationGroupId'] = "user";
  scratchpad_scrub_list['airwatch_basicprofile_info']['OrganizationGroupName'] = "user";
  scratchpad_scrub_list['forensics_users_groups']['value'] = "user";
  scratchpad_scrub_list['forensics_usernames']['name'] = "user";
  scratchpad_scrub_list['browser_addons']['user'] = "user";

  scratchpad_scrub_list['airwatch_fullprofile_info']['passcodeinfo'] = "password";

  scratchpad_scrub_list['gmdm_deviceInfo']['Email'] = "email";
  scratchpad_scrub_list['maas360_device_info']['email_address'] = "email";
  scratchpad_scrub_list['maas360_device_info']['email'] = "email";
  scratchpad_scrub_list['airwatch_DeviceInfo']['UserEmailAddress'] = "email";
  scratchpad_scrub_list['mobileiron_deviceInfo']['emailAddress'] = "email";
  scratchpad_scrub_list['webmirror_mailto']['email'] = "email";

  scratchpad_scrub_list['gmdm_deviceInfo']['Phone'] = "phone";
  scratchpad_scrub_list['apl_profilemgr_deviceInfo']['PhoneNumber'] = "phone";
  scratchpad_scrub_list['airwatch_DeviceInfo']['PhoneNumber'] = "phone";

  scratchpad_scrub_list['gmdm_serverInfo']['url'] = "path";
  scratchpad_scrub_list['airwatch_appInfoPreliminaryTable']['URL'] = "path";
  scratchpad_scrub_list['proc_exec_info']['path'] = "path";
  scratchpad_scrub_list['proc_mod_details']['path'] = "path";
  scratchpad_scrub_list['win_autoruns']['file'] = "path";
  scratchpad_scrub_list['CgiNames']['path'] = "path";
  scratchpad_scrub_list['AutoComplete']['path'] = "path";
  scratchpad_scrub_list['AutoComplete']['dest'] = "path";
  scratchpad_scrub_list['webmirror_meta_redirect']['redir_uri'] = "path";
  scratchpad_scrub_list['webmirror_meta_redirect']['redir2_https'] = "path";
  scratchpad_scrub_list['JavaFiles']['path'] = "path";
  scratchpad_scrub_list['ClearTextPasswds']['path'] = "path";
  scratchpad_scrub_list['ClearTextPasswds']['dest'] = "path";
  scratchpad_scrub_list['JavascriptFiles']['path'] = "path";
  scratchpad_scrub_list['JavascriptExtFiles']['path'] = "path";
  scratchpad_scrub_list['webmirror_uri']['uri'] = "path";
  scratchpad_scrub_list['webmirror_directories']['dir'] = "path";
  scratchpad_scrub_list['process_info']['Path'] = "path";
  scratchpad_scrub_list['process_info']['ProcessName'] = "path";
  scratchpad_scrub_list['process_info']['ExecutablePath'] = "path";
  scratchpad_scrub_list['process_info']['CommandLine'] = "path";
  scratchpad_scrub_list['browser_addons']['path'] = "path";
  scratchpad_scrub_list['rhss6_endpoints']['id'] = "path";
  scratchpad_scrub_list['oracle_install_envvars']['ohome'] = "path";
  scratchpad_scrub_list['oracle_homes']['path'] = "path";
  scratchpad_scrub_list['oracle_patches']['ohome'] = "path";
  scratchpad_scrub_list['oracle_components']['ohome'] = "path";
  scratchpad_scrub_list['oracle_components']['subdir'] = "path";
  scratchpad_scrub_list['oracle_products']['ohome'] = "path";
  scratchpad_scrub_list['oracle_products']['subdir'] = "path";
  scratchpad_scrub_list['oracle_domains']['ohome'] = "path";
  scratchpad_scrub_list['oracle_domains']['domain_path'] = "path";
  scratchpad_scrub_list['oracle_db_sids']['ohome'] = "path";
  scratchpad_scrub_list['malware_files']['name'] = "path";
  scratchpad_scrub_list['malware_results']['filepath'] = "path";
  scratchpad_scrub_list['malware_code_signing']['filepath'] = "path";
  scratchpad_scrub_list['webmirror_30x']['redir_uri'] = "path";
}
