#TRUSTED 4b4e347daef9d1ca0259540723e75804427b44cf06cfcedaad62295812e3c2c7f97200b62a912c2dfa287b1a6094356c0a93753ca3630667d37a26d3ef84aa7a434c2b64e45543777e9dc3d129b43e8722dda6780b0856660dffa105bf041e58a8eb15e604c7bea1dd1623f499d31cd06ffac51d30a996caf0430d9816408595ee7c87954f9b99a526991096eb31c812e4b302e479665e25afb2c7039ce367298daa3064d3147331524b0b152c491ca3950405a0d285685f768864201d581afba8691fbdd03fa2099d72171d4da62d4e565c641646179104fa7baa80e797e43e0eab5f1df1417600007b1a0ad92c13eaa74b9a49193e871453105fdc252000757d0b52aa98a7857fd249538e91e3a3abd0de3cff9a61ae924799d2c2e4372b267ae33ce92e359186c1d9c4a895c84395af7a0a250f8a78521d06b65b957d83c811545991d1c6f08c60369c3b35c5a0f6dc5a63c5f18a931152d52242092ddc367abd9381d8865613963e9442cc34d38ae7ef71c3c76ff38a689b0a64e04dae0ff2e62da53c0a93277a45cb95e2c37d32f9cd37f28fea21a7352e2013e74c6e946726679af045ae21b1774921c514e123eb3b8d71d3cade67015c75a0b1a18c60aad6ac08dc3f9ef166fbe3da12e8f10382dc25623c7e8488125aa1db775d03499e08963576a9eab6148595f7f3365dcb7469e3e82dad19b7b374d1b825d3407e
#TRUST-RSA-SHA256 7a60fb92dcbd86000165960aead536a8e20a8c0434dbe82652675b8d24a9a36b41e4709873e7f6e32e12d95475aeb342aec95eba7456865d2672035da1ded9a69dbb39817b7803b99deacd116c24703e95b759fb9d5c187e9688c6bdf1092125382e2a99602539181699e3bb2f016e59e84fbb2ce6891298004e84190f1316446a0c573c306ebdb80de4d755b5466832e1d0cc30cc73deaec2decb7f1de00d74d036df8ff5799da3156d42efe2933d7df18cd8affc8687cc5d855846c80426c036e3ccecf911a60a9b1d9233289eb83a969bb121e966627720d0ca68a4c612435182d87fb62c72c644ac26268d4930675ac09c06dd02b864aadb5348b8e8346836f4c8599edef2a0268ef3119b3790a70fb0d2df1c8bcb240c8adc4507055109a1eaf5e331ec287b2b237fff0cd10f7d349e0f9bbf4d7aedc7da4205383b4771d6354abb613173f121c1605eb6e8f4b7622a998eb5a1ca010ea3d0ef9dde66a0295dd9220d9803b5ba7c7dfe88ffb5aaa66b0894981e4e77259c0f8bf13646c1ae0706854f373bfc9f089fd2570f6cff6e6d3d12bb366e1c8cf9286437b0259a49a0409044201b227399ae4b53b1fb01c1c7b784b7138080f4bfac382a7f80a87170466df71469f755a2ab3ca1bcf15fa44b9ff3d26d62a72055ee30986de1bb45cab9debb2ead4c79623e79d174a603c1052f4e62bd161575a8d6eb356aad4c
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(54845);
  script_version("1.41");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_name(english:"Sophos Anti-Virus for Mac OS X Detection");
  script_summary(english:"Checks for Sophos Anti-Virus.");

  script_set_attribute(attribute:"synopsis", value:
"An antivirus application is installed on the remote Mac OS X host.");
  script_set_attribute(attribute:"description", value:
"Sophos Anti-Virus for Mac OS X, a commercial antivirus software
package, is installed on the remote host. Note that this plugin only
gathers information about the software, if it's installed. By itself,
it does not perform any security checks and does not issue a report.");
  script_set_attribute(attribute:"see_also", value:"https://www.sophos.com/en-us.aspx");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sophos:sophos_anti-virus");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"asset_categories", value:"security_control");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/MacOSX/packages");

  exit(0);
}

include("datetime.inc");
include("install_func.inc");
include("macosx_func.inc");
include("ssh_func.inc");
include("security_controls.inc");

enable_ssh_wrappers();

var app = "Sophos Anti-Virus";
var cpe = "cpe:/a:sophos:sophos_anti-virus";
var plist = NULL;
var regex = NULL;
var sweep = "/usr/local/bin/sweep -v";
var plutil = "plutil -convert xml1 -o - ";
var sophos_product = "Anti-Virus"; # by default

 # Sophos v10.x for Mac:
 # Endpoint: /Applications/Sophos/Sophos Endpoint.app/Contents/Info.plist
var products = make_array(
          'Anti-Virus', make_list('/Applications/Sophos Anti-Virus.app/Contents/Info.plist'),
          'Home', make_list('/Applications/Sophos Home.app/Contents/Info.plist'),
          'Endpoint', make_list('/Applications/Sophos Endpoint.app/Contents/Info.plist',
                                '/Applications/Sophos/Sophos Endpoint.app/Contents/Info.plist'));

var paths = make_array(
          '/Library/Sophos Anti-Virus/product-info.plist', 'ProductVersion'
      );

var order = make_list(
          '/Library/Sophos Anti-Virus/product-info.plist'
      );

var flav, flav_paths, flav_path, found, cmd1, av_log, cmd2, vvf, cmd3, cmd4, cmd5, cmd6,
    sophos_product_version, sophos_threat_data, sophos_engine_version, sophos_auto_update_running,
    sophos_antivirus_running, sophos_last_update_date, date_match, day, month, year, pattern,
    date_pattern, extra_info, results;

foreach flav (keys(products))
{
  dbg::log(src:SCRIPT_NAME, msg:"Checking product "+flav);
  flav_paths = products[flav];
  foreach flav_path (flav_paths)
  {
    found = exec_cmd(cmd:'plutil \"' + flav_path + '\"');
    if (!isnull(found) &&
        "file does not exist" >!< found)
    {
      sophos_product = flav;
      paths[flav_path] = 'CFBundleShortVersionString';
      # adding the element regex for that file
      append_element(var:order, value:flav_path);
      if (flav == 'Home')
      {
        # look for HomeVersion in this case
        paths['/Library/Sophos Anti-Virus/product-info.plist'] = 'HomeVersion';
      }
      break;
    }
  }
}

var path;

foreach path (order)
{
  found = exec_cmd(cmd:'plutil \"' + path + '\"');
  if (!isnull(found) &&
      "file does not exist" >!< found)
  {
    plist = path;
    regex = paths[path];
    break;
  }
}

if ("Info.plist" >< path)
  sweep = "/usr/bin/sweep -v";

if (isnull(plist))
  audit(AUDIT_NOT_INST, "Sophos Anti-Virus");

cmd1 = plutil + "'" + plist + "' | "
     + "grep -A 1 " + regex + "| "
     + "tail -n 1 | "
     + 'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';

# This value will return a string in format HH:MM:SS DD MON YYYY
av_log = "/Library/Logs/Sophos Anti-Virus.log";
cmd2 = "cat '" + av_log + "' | "
     + "grep up-to-date | "
     + "tail -n 1 | "
     + 'sed -e \'s/.*Software is up-to-date at //\'';

vvf = "/Library/Sophos Anti-Virus/VDL/vvf.xml";
cmd3 = "cat '" + vvf + "' | "
     + "grep VirusData | " 
     + 'sed -e \'s/.*VirusData Version="//\' -e \'s/"//\' -e \'s/ .*//\'';

cmd4 = "ps aux | grep -E 'SophosUpdater|SophosAutoUpdate' | grep -v 'grep'";

cmd5 = "ps aux | grep -e 'SophosAntiVirus' | grep -v 'grep'";

cmd6 = sweep + " | grep 'Engine version'";

results = exec_cmds(cmds:make_list(cmd1, cmd2, cmd3, cmd4, cmd5, cmd6));


if (isnull(results))
  audit(AUDIT_UNKNOWN_APP_VER, "Sophos Anti-Virus");

sophos_product_version = results[cmd1];

# If the version is <9, we don't have the signature date. <9 is unsupported.
if (sophos_product_version =~ "^[0-8]\.")
  sophos_threat_data = UNKNOWN_VER;
else
  sophos_threat_data = results[cmd3];

sophos_engine_version = split(results[cmd6], sep:":");
if (!empty_or_null(sophos_engine_version[1]))
  sophos_engine_version = strip(sophos_engine_version[1]);
else
 sophos_engine_version = UNKNOWN_VER;

sophos_auto_update_running = results[cmd4];
sophos_antivirus_running = results[cmd5];

date_match = pregmatch(string:results[cmd2], pattern:"^\d\d:\d\d:\d\d (\d+)\s+([A-Za-z]+)\s+(\d+)$");
if (!isnull(date_match))
{
  day = date_match[1];
  month = month_num_by_name(date_match[2], base:1);
  if (!isnull(month) && int(month) < 10)
    month = "0" + month;
  year = date_match[3];
  if (!isnull(year) && !isnull(month) && !isnull(day))
  {
    sophos_last_update_date = year + "-" + month + "-" + day;
  }
}

if (isnull(sophos_product_version) || isnull(sophos_threat_data))
  audit(AUDIT_UNKNOWN_APP_VER, "Sophos Anti-Virus");

if (isnull(sophos_engine_version))
  sophos_engine_version = 0;

pattern = "^[0-9][0-9.]+$";

if (sophos_product_version !~ pattern)
  audit(AUDIT_UNKNOWN_APP_VER, "the Sophos Anti-Virus product");

if (sophos_threat_data !~ pattern && sophos_product_version !~ "^[0-8]\.")
  audit(AUDIT_UNKNOWN_APP_VER, "the Sophos Anti-Virus threat data");

if (sophos_engine_version !~ pattern)
  audit(AUDIT_UNKNOWN_APP_VER, "the Sophos Anti-Virus engine");

date_pattern = "^\d{4}-\d{2}-\d{2}$";

if (sophos_last_update_date !~ date_pattern)
  sophos_last_update_date = "Unknown";

set_kb_item(name:"Antivirus/SophosOSX/installed", value:TRUE);
set_kb_item(name:"MacOSX/Sophos/Path", value:path);
set_kb_item(name:"MacOSX/Sophos/Product", value:sophos_product);
set_kb_item(name:"MacOSX/Sophos/Version", value:sophos_product_version);
set_kb_item(name:"MacOSX/Sophos/ThreatDataVersion", value:sophos_threat_data);
set_kb_item(name:"MacOSX/Sophos/EngineVersion", value:sophos_engine_version);
set_kb_item(name:"MacOSX/Sophos/LastUpdateDate", value:sophos_last_update_date);

extra_info = make_array(
    "ThreatDataVersion", sophos_threat_data,
    "EngineVersion", sophos_engine_version,
    "AutoUpdateRunning", sophos_auto_update_running,
    "AntiVirusRunning", sophos_antivirus_running,
    "LastUpdateDate", sophos_last_update_date);

if ("SophosAutoUpdate" >< sophos_auto_update_running || "SophosUpdater" >< sophos_auto_update_running)
{
  extra_info['AutoUpdateRunning'] = 'on';
  set_kb_item(name:"MacOSX/Sophos/AutoUpdateRunning", value:TRUE);
}
else
{
  extra_info['AutoUpdateRunning'] = 'off';
  set_kb_item(name:"MacOSX/Sophos/AutoUpdateRunning", value:FALSE);
}

if ("SophosAntiVirus -d" >< sophos_antivirus_running)
{
  extra_info["AntiVirusRunning"] = 'on';
  set_kb_item(name:"MacOSX/Sophos/AntiVirusRunning", value:TRUE);
}
else
{
  extra_info["AntiVirusRunning"] = 'off';
  set_kb_item(name:"MacOSX/Sophos/AntiVirusRunning", value:FALSE);
}

extra_info['Product'] = sophos_product;

register_install(
  vendor:"Sophos",
  product:"Sophos Anti-Virus",
  app_name:app,
  path:path,
  version:sophos_product_version,
  extra:extra_info,
  cpe: cpe
 );

var autoupdate_string = "yes";
if(!sophos_auto_update_running) autoupdate_string = "no";

var running_string = "yes";
if(!sophos_antivirus_running) running_string = "no";

security_controls::endpoint::register(
  subtype                : 'EPP',
  vendor                 : "Sophos",
  product                : app,
  product_version        : sophos_product_version,
  cpe                    : cpe,
  path                   : path,
  running                : running_string,
  signature_version      : sophos_threat_data,
  signature_install_date : sophos_last_update_date,
  signature_autoupdate   : autoupdate_string
);

report_installs(app_name:app);
