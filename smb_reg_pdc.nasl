##
# (C) Tenable Network Security, Inc.
##

include("compat.inc");

if (description)
{
  script_id(10413);
  script_version("1.28");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/08/17");

  script_xref(name:"IAVT",value:"0001-T-0030");
  script_xref(name:"IAVT",value:"0001-T-0942");

  script_name(english:"Microsoft Windows SMB Registry : Remote PDC/BDC Detection");

  script_set_attribute(attribute:"synopsis", value:"The remote system is a Domain Controller.");
  script_set_attribute(attribute:"description", value:
"The remote host seems to be a Primary Domain Controller or a Backup
Domain Controller.

This can be verified by the value of the registry key 'ProductType'
under 'HKLM\SYSTEM\CurrentControlSet\Control\ProductOptions'.");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"solution", value:"n/a");

  script_set_attribute(attribute:"plugin_publication_date", value:"2000/05/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"agent", value:"windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2000-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("netbios_name_get.nasl", "smb_login.nasl", "smb_registry_access.nasl");
  script_require_keys("SMB/transport", "SMB/name", "SMB/login", "SMB/password", "SMB/registry_access");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_func.inc");

var login = kb_smb_login();
var pass = kb_smb_password();
var domain = kb_smb_domain();
var port = kb_smb_transport();

if ( !smb_session_init() ) audit(AUDIT_FN_FAIL, "smb_session_init");

var r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if ( r != 1 )
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, "IPC$");
}

var hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if ( isnull(hklm) )
{
  NetUseDel();
  audit(AUDIT_REG_FAIL);
}

var key = "SYSTEM\CurrentControlSet\Control\ProductOptions";
var item = "ProductType";

var key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if ( !isnull(key_h) )
{
  var value = RegQueryValue(handle:key_h, item:item);
  if (!isnull (value) && (value[1] == "LanmanNT"))
    security_note (port);

  RegCloseKey (handle:key_h);
}

RegCloseKey (handle:hklm);
NetUseDel ();
