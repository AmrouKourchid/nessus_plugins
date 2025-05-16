###
# (C) Tenable Network Security, Inc.
###

include("compat.inc");

if (description)
{
  script_id(34097);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/11");
  script_name(english:"BIOS Info (SMB)");
  script_summary(english:"Use SMB to get BIOS info");

  script_set_attribute(attribute:"synopsis", value:"BIOS info could be read.");
  script_set_attribute(attribute:"description", value: "It is possible to get information about the BIOS via the host's SMB interface.");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"solution", value:"n/a");

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/09/08");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Windows");

  script_dependencies("netbios_name_get.nasl", "smb_login.nasl", "smb_registry_access.nasl", "bios_get_info_wmi.nbin");
  script_require_keys("SMB/transport", "SMB/name", "SMB/login", "SMB/password", "SMB/registry_access");
  script_require_ports(139, 445);
  exit(0);
}

include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");

registry_init(full_access_check:FALSE);

var hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

var bios_version = get_kb_item('BIOS/Version');
var bios_date = get_kb_item('BIOS/ReleaseDate');
var secure_boot = get_kb_item('BIOS/SecureBoot');

if(empty_or_null(bios_version))
{
  bios_version = get_registry_value(handle:hklm, item:"Hardware\Description\System\Systembios_version");
  if(!empty_or_null(bios_version))
    replace_kb_item( name: "BIOS/Version", value: bios_version );
}
  
if(empty_or_null(bios_date))
{
  bios_date = get_registry_value(handle:hklm, item:"Hardware\Description\System\Systembios_date");
  if(!empty_or_null(bios_date))
    replace_kb_item( name: "BIOS/ReleaseDate", value: bios_date );
}
  
if(empty_or_null(secure_boot))
{
  secure_boot = get_registry_value(handle:hklm, item:"System\CurrentControlSet\Control\SecureBoot\State\UEFISecureBootEnabled");
  if ( secure_boot == 0 ) secure_boot = "disabled";
  else secure_boot = "enabled";

  replace_kb_item( name: "BIOS/SecureBoot", value: secure_boot );
}

RegCloseKey(handle:hklm);
close_registry();

var report = '\n  Version      : ' + bios_version +
         '\n  Release date : ' + bios_date +
         '\n  Secure boot  : ' + secure_boot + '\n';

security_report_v4(port: 0, severity:SECURITY_NOTE, extra:report);
