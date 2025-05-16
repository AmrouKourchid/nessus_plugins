#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
 script_id(12011);
 script_version("1.16");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/30");

 script_name(english:"BetterInternet Software Detection");
 script_summary(english:"BetterInternet detection");

 script_set_attribute(attribute:"synopsis", value:"An adware program is installed on the remote host.");
 script_set_attribute(attribute:"description", value:
"The remote host is using BetterInternet. This program monitors web
traffic, displaying pop-up/pop-under advertisements based on the
content.");
 # https://www.broadcom.com/support/security-center/attacksignatures/detail?asid=20750
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?651a89f9");
 script_set_attribute(attribute:"solution", value:"Remove this program using an adware or spyware removal product.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
 script_set_attribute(attribute:"cvss_score_source", value:"manual");
 script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on analysis of the vulnerability by Tenable.");

 script_set_attribute(attribute:"plugin_publication_date", value:"2004/01/15");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"x-cpe:/a:better_internet:better_internet");
 script_set_attribute(attribute:"asset_inventory", value:"True");
 script_set_attribute(attribute:"agent", value:"windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Windows");

 script_copyright(english:"This script is Copyright (C) 2004-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

 script_dependencies("smb_registry_full_access.nasl");
 script_require_keys("SMB/registry_full_access");

 script_require_ports(139, 445);
 exit(0);
}


# start the script
include("smb_func.inc");
include("install_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

var path;

path[0] = "Software\Classes\CLSID\{DDFFA75A-E81D-4454-89FC-B9FD0631E726}";
path[1] = "Software\DBI";
path[2] = "Software\Microsoft\Code Store Database\Distribution Units\{30000273-8230-4DD4-BE4F-6889D1E74167}";
path[3] = "Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved\{DDFFA75A-E81D-4454-89FC-B9FD0631E726}";
path[4] = "Software\Microsoft\Windows\CurrentVersion\Uninstall\DBI";

var port = kb_smb_transport();
var login = kb_smb_login();
var pass  = kb_smb_password();
var domain = kb_smb_domain();


if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
var r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if ( r != 1 ) exit(0);

var handle = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if ( isnull(handle) )
{
 NetUseDel();
 exit(0);
}

var i, key_h, report, reg;

for (i=0; path[i]; i++) {
       key_h = RegOpenKey(handle:handle, key:path[i], mode:MAXIMUM_ALLOWED);
       if ( !isnull(key_h) )
       {
         reg = str_replace(find:"\", replace:"\", string:path[i]);         
         report ='\nEvidence of BetterInternet has been detected in the registry :\n\n' + 'HKLM\\' + reg;
         security_warning(port:port, extra:report);
         RegCloseKey(handle:key_h);
         RegCloseKey(handle:handle);
	  NetUseDel();
	  exit(0);
       }
}

RegCloseKey(handle:handle);
NetUseDel();
