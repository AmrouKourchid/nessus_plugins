#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(10401);
  script_version("1.56");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/27");

  script_name(english:"Microsoft Windows SMB Registry : NT4 Service Pack Version Detection");

  script_set_attribute(attribute:"synopsis", value:
"It was possible to determine the service pack installed on the remote
system.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to determine the Service Pack version of the Windows
NT system by reading the following registry key :

HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\CSDVersion");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2000/05/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"agent", value:"windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2005-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("netbios_name_get.nasl", "smb_login.nasl", "smb_registry_access.nasl");
  script_require_keys("SMB/transport", "SMB/name", "SMB/login", "SMB/password", "SMB/registry_access");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");

get_kb_item_or_exit("SMB/registry_access");

var hklm, key, items, data;

registry_init(full_access_check:FALSE);
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion";
items = make_list(
  "CSDVersion",
  "CurrentBuild",
  "CurrentBuildNumber",
  "CurrentMajorVersionNumber",
  "CurrentVersion",
  "ProductName",
  "BuildLabEx",
  'DisplayVersion',
  'ReleaseId',
  'UBR'
);

data = get_values_from_key(handle:hklm, key:key, entries:items);

if (isnull(data)) exit(1, "Failed to query 'HKLM"+key+"'.");

var key2, key_h2, kb_name;

if (!isnull(data["CSDVersion"]))
{
  # nb: Microsoft seems to have made an exception for Hungarian.
  if ("Szervizcsomag " >< data["CSDVersion"])
  {
    data["CSDVersion"] = str_replace(find:"Szervizcsomag ", replace:"Service Pack ", string:data["CSDVersion"]);
  }

  if (
    !isnull(data["CurrentVersion"]) &&
    data["CurrentVersion"] == "5.1"
  )
  {
    key2 = "SOFTWARE\Microsoft\POSReady";
    key_h2 = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
    if (!isnull(key_h2))
    {
      data["ProductName"] = "Windows Embedded POSReady";
      RegCloseKey(handle:key_h2);
    }

  }

  if (
    !isnull(data["CurrentVersion"]) &&
    data["CurrentVersion"] == "5.0" &&
    data["CSDVersion"] == "Service Pack 4"
  )
  {
    key2 = "SOFTWARE\Microsoft\Updates\Windows 2000\SP5\Update Rollup 1";
    key_h2 = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
    if (!isnull(key_h2))
    {
      set_kb_item(name:"SMB/URP1", value:TRUE);
      RegCloseKey(handle:key_h2);
    }
    else
    {
      key2 = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\HotFix\Update Rollup 1";
      key_h2 = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
      if (!isnull(key_h2))
      {
        set_kb_item(name:"SMB/URP1", value:TRUE);
        RegCloseKey(handle:key_h2);
      }
    }
  }
}

RegCloseKey(handle:hklm);
close_registry();

# Check for non-Windows systems.
if (
  !isnull(data["CSDVersion"]) &&
  "EMC Celerra File Server" >< data["CSDVersion"]
)
{
  replace_kb_item(name:"SMB/not_windows", value:TRUE);
  audit(AUDIT_OS_NOT, 'Windows', 'EMC Celerra');
}
if (
  !isnull(data["CurrentVersion"]) &&
  data["CurrentVersion"] == "5.0" &&
  isnull(data["CSDVersion"]) &&
  isnull(data["ProductName"])
)
{
  replace_kb_item(name:"SMB/not_windows", value:TRUE);
  audit(AUDIT_OS_NOT, 'Windows', 'NetApp');
}

# Save info in KB.
foreach key (keys(data))
{
  if (key == "CurrentVersion" || key == "CurrentMajorVersionNumber")
  {
    # Windows 10 now uses CurrentMajorVersionNumber - Only use CurrentVersion if
    # the CurrentMajorVersionNumber key is missing
    if (key == "CurrentVersion" && !empty_or_null(data["CurrentMajorVersionNumber"]))
      continue;
    kb_name = "SMB/WindowsVersion";
  }
  else if (key == "CurrentBuildNumber")
  {
    kb_name = "SMB/WindowsVersionBuild";
  }
  else kb_name = "SMB/" + key;

  set_kb_item(name:kb_name, value:data[key]);
}

# CurrentBuild and CurrentBuildNumber are not always identical except when installing 
# the OS from an image. These build numbers can deviate after updating the OS. 
if(!empty_or_null(data["CurrentBuild"]) && !empty_or_null(data["CurrentBuildNumber"]))
{
  kb_name = "SMB/WindowsVersionBuild";
  # this is an optimal place to perform this check as it avoids duplicate kb items and
  # does not require updating every single smb unsupported plugin to support new items
  if(int(data["CurrentBuild"]) > int(data["CurrentBuildNumber"]))
  {
    replace_kb_item(name:kb_name, value:data["CurrentBuild"]);
  }
}

# Finally, generate the report if the host is running NT with a service pack.
if (isnull(data["CurrentVersion"])) exit(1, "Failed to query 'HKLM\"+key+"\CurrentVersion'.");

# Retrieve the channel/release version (e.g. 1709, 22H2) for newer Windows versions (e.g. 10/11, 2016/2019/2022)
kb_name = 'SMB/ChannelVersion';
if (!empty_or_null(data['DisplayVersion']))
  replace_kb_item(name:kb_name, value:data['DisplayVersion']);
else if (!empty_or_null(data['ReleaseId']))
  replace_kb_item(name:kb_name, value:data['ReleaseId']);

# Retrieve the Update Build Revision (UBR)
#  - Example: '2600' of the '22000.2600' build
kb_name = 'SMB/UpdateBuildRevision';
if (!empty_or_null(data['UBR']))
  replace_kb_item(name:kb_name, value:data['UBR']);

var sp, port, report;

if (data["CurrentVersion"] == "4.0")
{
  if (isnull(data["CSDVersion"])) exit(0, "There is no service pack installed.");
  else
  {
    sp = data["CSDVersion"];
    if (preg(string:sp, pattern:"^Service Pack [0-9]"))
    {
      set_kb_item(name:"SMB/WinNT4/ServicePack", value:sp);

      port = kb_smb_transport();
      if (report_verbosity > 0)
      {
        report = '\n' + 'The remote Windows NT system has ' + sp + ' applied.' + '\n';
        security_note(port:port, extra:report);
      }
      else security_note(port);
    }
  }
}
else audit(AUDIT_OS_NOT, 'Windows NT');
