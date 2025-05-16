#TRUSTED 319c843338a094810977e7e2d51b9845fff9eec4c96bde4a270a718691d51be6855b6bea10a86b128ec8393e497ed1215a3049ab80c2b212f8604cd2d56bbf395a1fef13f5784b27adfa8f6a467f955b7af7fbeea45799e8dfe16288dc30bc095581c709713632a859190a0c14fa674946d1d5b2a7a0ccf2cdf28cbdbebfcaa2d4617b509432558cdb2c05c7c0816c205192985abc88bf3814f02a1931c75b676d22c3bffeb2540a830caf83108e2229e1a7b6a7083938fa7f43e5615242feb67ae9ca0ca12a2240dbd7d049700af9a72edb0beeeda59499277cab54867525b333f92cba7d9d185617ffe2dd971a659a1678f7cde789389fb892ab83e6932409494ea1bddce8e4ff1e5bcf3ed24ce0e7601d1f88d693fd4ea05761b37a8ddbce302271f95191ad6674ee062bbe0e8c9c4120f615aa90b24e1b06c089781de62712f6de626de3202d1a7737a50016aea10da04b32ee31025b3f52a454ee19fedd3b69ba302647546d1d1bfe53b7233774e55e0163092ae5abc7b5c1927ea9e804199aeebc0f273cf8622d971d81acba353edb575a7ac935aad2f1a58c6197d8dbd9202985ed995a36665fc549be4c341dca8ba8073129f76a52b14f3abac9d8246da98f73ddee504de5551aeae253a241eeeff8aefbbe58291ae50ffa40b37bcdb54e31fab480a68ee5d7e2582572932290327fc9f3cf5ee9bc0392d77f85b379
#TRUST-RSA-SHA256 9ce7aaa7c8ecbcf1e7d36dc52efe075d90fbadcaac143f6f5d46312011b7f2bc7ad515406783f97a702e3e6dec89d1b33be955c310e102dc353462fcad1dd607c462fda7dd2fcb00461f6616503c01f8c4aa124fb1f677a7c1d90a94946f58e0933687280c9fc0efc79be3988a2f5c59f50567391b9dc8e6cbdf4b97b4cd32277bb5d9670e689b4db8ffa0b5d0c47bc08bdd8c8623f406ee19b1e714c2bac7e5251c6cf0ec9a7c6c07a64675af198fb0a47e7a9f1e00fafb512a16271e6b48a8e8c724bb7616c4ccb6fba0ff097c2af80fa6a0387cec6f859b030181d489c36a5a435a0afcab4ce47531daa5f7d34534cd9da9dbe3477137e5ae5470ca501b6350b3a2bda5fcbdb56898b9b6a318c71a56c71b08cc34b8586a1e65f76d741b0846269d6a207eff8101f55d3ec7d2085f8ad327d551c7d12ef13dcb6fd2560580a5a1d58eb23aea23897b8365fc18bf5f37c7516d3c5fedd407594e10b655a2b516cd1550b8975efbacfeb1fae9adc93c50917c6e2ecb40ecc1bc52e6bc2ec02361606a4a1984695fd22862bf1421e038160eba8bd60c57527f6ee9eb1eb53ed6ddd8dff8baa4335ae17d1b06e2d92f61c155ae2236b320c7b55d57219edbd5d6adb1d08db536a8536df56b461caa54b399c7623a4fe87db3135e75613e13cf0bc1463306a95558a41c3b928ed4afcf6d9a1223e25ff2ed5a89cd89da49a3d38a
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56567);
  script_version("1.25");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_name(english:"Mac OS X XProtect Detection");
  script_summary(english:"Checks for Apple's XProtect");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Mac OS X host has an antivirus application installed on
it."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote Mac OS X host includes XProtect, an antivirus / anti-
malware application from Apple included with recent releases of Snow
Leopard (10.6) and later.  It is used to scan files that have been
downloaded from the Internet by browsers and other tools. 

Note that this plugin only gathers information about the application
and does not, by itself, perform any security checks or issue a
report."
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"https://en.wikipedia.org/wiki/Xprotect"
  );
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:apple:xprotect");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"asset_categories", value:"security_control");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");
  script_copyright(english:"This script is Copyright (C) 2011-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version");

  exit(0);
}

include("debug.inc");
include("install_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");
include("security_controls.inc");
include("spad_log_func.inc");

enable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");

# Mac OS X 10.6 and 10.7.
var os = get_kb_item("Host/MacOSX/Version");
if (!os) exit(0, "The host does not appear to be running Mac OS X.");
if (preg(pattern:"Mac OS X ([0-9]\.|10\.[0-5]([^0-9]|$))", string:os))
  exit(0, "The host is running "+os+", which does not have XProtect.");

var os_ver = pregmatch(pattern:"Mac OS X (([0-9]+)\.([0-9]+)?)", string:os);

if (empty_or_null(os_ver) || empty_or_null(os_ver[2]))
  exit(0, "Unable to determine Mac OS X version.");

# Runs various comments to check XProtect's status.
var cmd1, cmd2, cmd3, cmd4, cmd5, plist1, plist4;

# - Is it configured to get updates?
plist1 = "/System/Library/LaunchDaemons/com.apple.xprotectupdater.plist";
cmd1 = 'cat \'' + plist1 + '\'';

# - Does the XProtectUpdater daemon exist?
cmd2 = 'ls -al /usr/libexec/XProtectUpdater';

# - Is the XProtectUpdater daemon loaded?
if (os_ver[2] == 10 && os_ver[3] < 8)
  cmd3 = 'launchctl list';
else
  cmd3 = 'spctl --status';

# - When was it last updated?
if ((os_ver[2] > 10) || (os_ver[2] > 10 && os_ver[3] > 14))   # 11.x, 12.x, 13.x
{
  plist4 = "/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/XProtect.meta.plist";
  cmd4 = 
    'cat \'' + plist4 + '\' | ' +
    'grep -A 1 LastModification | ' +
    'tail -n 1 | ' +
    'sed \'s/.*<string>\\(.*\\)<\\/string>.*/\\1/g\'';
}
else if (os_ver[2] == 10 && os_ver[3] < 14)    # 10.11 - 10.13
  cmd4 = "stat -f'%Sp %Sm' /System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.plist";
else
  cmd4 = "stat -f'%Sp %Sm' /Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.plist";
  

# - And what's its version?
#   (obtained different ways, depending on OS version)
if (os_ver[2] == 10 && os_ver[3] < 10)    # 10.6 - 10.7
  cmd5 = 'cat \'' + plist4 + '\' | grep -A 1 Version | tail -n 1 | sed \'s/.*<integer>\\([0-9]*\\)<\\/integer>.*/\\1/g\'';
else if (os_ver[2] == 10 && os_ver[3] == 10)    # 10.10
  cmd5 = 'defaults read /System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/XProtect.meta.plist Version';
else if (os_ver[2] == 10 && (os_ver[3] > 10 && os_ver[3] < 14))    # 10.11 - 10.13 changed file path to ../CoreServices/XProtect.bundle/..
  cmd5 = 'defaults read /System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.meta.plist';
else if ((os_ver[2] > 10) || (os_ver[2] == 10 && os_ver[3] > 13))   # 10.14+, 11.x, 12.x, 13.x
  cmd5 = 'system_profiler SPInstallHistoryDataType | grep -A 5 "XProtectPlistConfigData"';

# - Final effort in case other methods didn't work on OS X > 10.x
if ((isnull(cmd5) && os_ver[2] > 10))    
  cmd5 = 'defaults read /Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.meta.plist Version';

var results = exec_cmds(cmds:make_list(cmd1, cmd2, cmd3, cmd4, cmd5));
  dbg::detailed_log(lvl:2, msg:'cmd results: ' + obj_rep(results));

if (isnull(results)) exit(1, "Unable to determine the status of XProtect.");

var running = "unknown";
var sig_autoupdate = "unknown";
var kb_base = 'MacOSX/XProtect/';
if (os_ver[2] == 10 && os_ver[3] < 8)    # 10.7 or earlier
{
  if (isnull(results[cmd3]) || !egrep(pattern:"^1[ \t]+.+launchd", string:results[cmd3]))
    exit(1, "'launchctl list' failed, perhaps because it was run as a non-root user.");

  if (
    !isnull(results[cmd1]) && 
    egrep(pattern:"^[ \t]*<string>/usr/libexec/XProtectUpdater</string>", string:results[cmd1]) && 
    egrep(pattern:"^[ \t]*<key>RunAtLoad</key>", string:results[cmd1])
  )
  {
    set_kb_item(name:kb_base+'XProtectUpdater/Configured', value:TRUE);
    running = "yes";
  }
  else
  {
    set_kb_item(name:kb_base+'XProtectUpdater/Configured', value:FALSE);
    running = "no";
  }
}
else   # 10.8 or later (GateKeeper was introduced in 10.8)
{
  if (!isnull(results[cmd3]))
  {
    set_kb_item(name:kb_base+'spctl --status', value:results[cmd3]);
    if (results[cmd3] =~ "enabled")
    {
      running = "yes";
      sig_autoupdate = "yes";
    }
    else
    {
      running = "no";
      sig_autoupdate = "no";
    }
  }
}

set_kb_item(name:"Antivirus/XProtect/installed", value:TRUE);

if (
  !isnull(results[cmd2]) &&
  # nb: we're looking here for a file of a non-trivial size.
  egrep(pattern:"^.+rwx.+ root +wheel +[1-9][0-9]+ .+ /", string:results[cmd2])
)
{
  set_kb_item(name:kb_base+'XProtectUpdater/Exists', value:TRUE);
  sig_autoupdate = 'yes';
}

if (
  !isnull(results[cmd3]) && 
  "com.apple.xprotectupdater" >< results[cmd3]
) set_kb_item(name:kb_base+'XProtectUpdater/Loaded', value:TRUE);

var version, greatest_ver, sysprof_lines, line, date_parts; 
if (!isnull(results[cmd5]))
{
  # If version 10 and minor version is less than 10
  if (os_ver[2] == 10 && os_ver[3] < 10)   # 10.6 - 10.7
  {
    set_kb_item(name:kb_base+'DefinitionsVersion', value:results[cmd5]);
    version = results[cmd5];
  }
  else    # 10.10 or greater
  {
    version = UNKNOWN_VER;
    greatest_ver = NULL;
    if (!isnull(results[cmd5]))
    {
      if ('XProtectPlistConfigData' >< results[cmd5])
      {
        sysprof_lines = split(results[cmd5], sep:'XProtectPlistConfigData', keep:FALSE);
        foreach line (sysprof_lines)
        {
          if (line =~ "Version" && line =~ "Install Date")
          {
            version = pregmatch(string:line, pattern:'Version: (\\d+)');
            if (!empty_or_null(version) && !empty_or_null(version[1]))
            {
              if (isnull(greatest_ver) || int(version[1]) > greatest_ver)
              {
                greatest_ver = version[1];
                sig_install_date = pregmatch(string:line, pattern:'Install Date: ([^,]+),');
                if (!empty_or_null(sig_install_date) && !empty_or_null(sig_install_date[1]))
                {
                  sig_install_date = sig_install_date[1];
                  spad_log(message:'found greatest_ver ' + version[1] + ' and sig_install_date ' + sig_install_date + ' via line ' + line);
                }
              }
            }
          }
          else if(line =~ "CatalinaAndBigSur_" && line =~ "Install Date")
          {
            version = pregmatch(string:line, pattern:'CatalinaAndBigSur_(\\d+)');
            if (!empty_or_null(version) && !empty_or_null(version[1]))
            {
              if (isnull(greatest_ver) || int(version[1]) > greatest_ver)
              {
                greatest_ver = version[1];
                sig_install_date = pregmatch(string:line, pattern:'Install Date: ([^,]+),');                
                if (!empty_or_null(sig_install_date) && !empty_or_null(sig_install_date[1]))
                {
                  sig_install_date = sig_install_date[1];
                  spad_log(message:'found greatest_ver ' + version[1] + ' and sig_install_date ' + sig_install_date + ' via line ' + line);
                }
              }
            }
          }
        }
        if (!isnull(greatest_ver))
        {
          version = greatest_ver;
          set_kb_item(name:kb_base+'DefinitionsVersion', value:version);
          date_parts = split(sig_install_date, sep:'/', keep:FALSE);
          if (!empty_or_null(date_parts) && !empty_or_null(date_parts[2]))
          {
            sig_install_date = "20" + date_parts[2] + "-";
            if (len(date_parts[0]) == 1)
              sig_install_date += "0" + date_parts[0] + "-";
            else
              sig_install_date += date_parts[0] + "-";
            if (len(date_parts[1]) == 1)
              sig_install_date += "0" + date_parts[1];
            else
              sig_install_date += date_parts[1];
          }

          set_kb_item(name:kb_base+'LastModification', value:sig_install_date);
        }
      }
      else if ('ExtensionBlacklist =' >< results[cmd5])
      {
        version = pregmatch(string:results[cmd5], pattern:"\n\s+Version = (\d\d\d\d)\;\n");
        if (!empty_or_null(version) && !empty_or_null(version[1]))
        {
          version = version[1];
          set_kb_item(name:kb_base+'DefinitionsVersion', value:version);
        }
        else
          spad_log(message:'Error: Unable to parse xprotect version from response "' + obj_rep(results[cmd5]) + '"');
      }
    }
  }
}  
if ((!isnull(results[cmd4])) && (isnull(sig_install_date)))
{
  # might be date or stat output.
  if ("rw" >< results[cmd4])
  {
    var parts = split(results[cmd4], sep:' ', keep:FALSE);
    var sig_install_date;

    if ("Jan" >< parts[1])
      sig_install_date = parts[4] + "-01-" + parts[2];
    else if ("Feb" >< parts[1])
      sig_install_date = parts[4] + "-02-" + parts[2];
    else if ("Mar" >< parts[1])
      sig_install_date = parts[4] + "-03-" + parts[2];
    else if ("Apr" >< parts[1])
      sig_install_date = parts[4] + "-04-" + parts[2];
    else if ("May" >< parts[1])
      sig_install_date = parts[4] + "-05-" + parts[2];
    else if ("Jun" >< parts[1])
      sig_install_date = parts[4] + "-06-" + parts[2];
    else if ("Jul" >< parts[1])
      sig_install_date = parts[4] + "-07-" + parts[2];
    else if ("Aug" >< parts[1])
      sig_install_date = parts[4] + "-08-" + parts[2];
    else if ("Sep" >< parts[1])
      sig_install_date = parts[4] + "-09-" + parts[2];
    else if ("Oct" >< parts[1])
      sig_install_date = parts[4] + "-10-" + parts[2];
    else if ("Nov" >< parts[1])
      sig_install_date = parts[4] + "-11-" + parts[2];
    else if ("Dec" >< parts[1])
      sig_install_date = parts[4] + "-12-" + parts[2];

    set_kb_item(name:kb_base+'LastModification', value:sig_install_date);
  }
  else
  {
    set_kb_item(name:kb_base+'LastModification', value:results[cmd4]);
    sig_install_date = results[cmd4];
  }
}

var path = NULL;
var cpe = 'x-cpe:/a:apple:xprotect';

if (os_ver[2] == 10)
  path = "/System/Library/CoreServices/XProtect.bundle";
else
  path = "/Library/Apple/System/Library/CoreServices/XProtect.bundle";


register_install(
  vendor:"Apple",
  product:"Xprotect",
  app_name: "Apple XProtect",
  path:path,
  version:version,
  cpe:cpe);


security_controls::endpoint::register(
  subtype                : 'EDR',
  vendor                 : 'Apple',
  product                : 'XProtect',
  product_version        : version,
  cpe                    : cpe,
  path                   : path,
  running                : running,
  signature_version      : version,
  signature_install_date : sig_install_date,
  signature_autoupdate   : sig_autoupdate
);

report_installs(app_name:"Apple XProtect");
