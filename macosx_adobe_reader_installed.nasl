#TRUSTED 9a5d02f8d9c45d17908c28d66d22a5fdb1d05926d8a627c31357625f1ebfeb2000c543f9b213a7deb7d5d42bf9fc04ce5474b672f9bdc7a72bcabbf809f9da755ada5ad378b9a5243b9785a9ab76a3f956867678925531db927f1622ad52405098699486399b1a940a5eb4946db1e80574e05f7d83781bb2f0ef2f76222ab1182d73afc5ae912ef0ffb5f3b2380cf127e26ce90ce5f7805203c6cef6d84715e4b717f818e80c14c9f1816b50a2540973aab0a22b06d404903424525673b0a48f45c4fba3f225e62be7391dfc513b31d79e3e2e5e1e7d771acc5bedbff04961bbf2cf89577dce208a2e45e14961b4d565cec65137c9d2d28c4f6321a5c1e21b5a4fde1b5881777a02913d61213f647221fad2a547e7b955d7ec3f61f9d79c97b05d823b52badf6bfa5780c24dc3b9cca87c8fa333e76597be13f3b99fc0605821053e28677188801f98192abc6e39dadb6517ffcc7edad38410d33013901f8f59760478c42df7fde08b59af829e2871f05f4c74303bcbd5675d8195c28678eda78a030645b1cd83e17700cb13c25875913da103b762eec2518348a58efd490474171269cfeb1ea145838ec4ef84a8dd15404ff3b68288ce05daac202e6910c74a901157aca21220f0d262aa717358deea0873c70248ee0d3b938e80ebdcaab120ab51192495a03dfe5b8d1835d4fcd042c38652709c2938d23e00416d9f7d439f
#TRUST-RSA-SHA256 36c5608c1c1dbb396328b2205e68be7648ffcb76d4a2f6a9221ca251c57d09e23d7d060ba1824dc9316cad95ceccf805039049c75873423baf3e3bd523c5a07e0bb94d6e79e5fdca2aca4905a978df52aa8c2067c0f519f21bee9795dd08e5b328f09360d63d856d2f81c81bb5bfd3de345170f030585065227aa22db5b28d689ac7587f77566ec313bba7af99c3491b3b373601799daee892b1fdc712a9256addee3dee1760b12be6bf3d838f1871e14d93d72f39378234210dd744e71a367ca35f47ced2982e103c0b20773c0e213886cdc010a554999ad181a764b7ce46f69a84f183b5e30b3d25562871869b51c6e9622798658b883270455f4f9c7199dca42a7be3b1456b110a27ee82b1c3f20ee0dd52cc7e99f24250df81de0bf161ec75aa24a7ca0ad5773399de91d002e20b525b403886dbbe718dc6505ede1ee367857bcc80992f682e9de84d72918d7e3a8a6c7221927361092f14f7f885abde26c7a520a23aac2ddfdaee24bec004c94f99792f0b530d71ddd146d2afccf02ad086350348296de606033b202d77b2936d0076a649cf45296775bf4e720f6f41b171386d35f2d8a97acdfbc23d38dfd7304ce872916dcd2edd1a4424d684e6b19e6d7e52cd70f4d0286b8cc8a699323746caafed9e7f1b9a20e258db179a736e55440d7edf46f57cd0f59c66301575373a1efb1eae1159e301348eabbba54e2dfc
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55420);
  script_version("1.38");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_xref(name:"IAVT", value:"0001-T-0524");

  script_name(english:"Adobe Reader Installed (Mac OS X)");
  script_summary(english:"Gets the Reader version from Info.plist.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains a PDF file viewer.");
  script_set_attribute(attribute:"description", value:
"Adobe Reader, a PDF file viewer, is installed on the remote Mac OS X
host.");
  script_set_attribute(attribute:"see_also", value:"https://acrobat.adobe.com/us/en/products/pdf-reader.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat_reader");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "command_builder_init.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version");

  exit(0);
}

include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");
include("macosx_func.inc");
include("install_func.inc");
include('find_cmd.inc');

function adobe_extract_version_track(plist)
{
  local_var result = [];

  local_var version_cmd =  'plutil -convert xml1 -o - \'' + plist + '\' | ' +
    'grep -A 1 CFBundleShortVersionString | ' +
    'tail -n 1 | ' +
    'sed \'s/.*<string>\\(.*\\)<\\/string>.*/\\1/g\'';

  result[0] = exec_cmd(cmd:version_cmd);

  local_var track_cmd =  'plutil -convert xml1 -o - \'' + plist + '\' | ' +
    'grep -A 1 TrackName | ' +
    'tail -n 1 | ' +
    'sed \'s/.*<string>\\(.*\\)<\\/string>.*/\\1/g\'';

  result[1] = exec_cmd(cmd:track_cmd);

  return result;
}

## Main ##

var app = "Adobe Reader";

enable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_HOST_NOT, "Mac OS X");

var kb_base = "MacOSX/Adobe_Reader";

if (islocalhost())
{
  if (!defined_func("pread")) audit(AUDIT_FN_UNDEF,"pread");
  info_t = INFO_LOCAL;
}
else
{
  sock_g = ssh_open_connection();
  if (!sock_g) audit(AUDIT_FN_FAIL, 'ssh_open_connection');
  info_t = INFO_SSH;
}

var item, tmp, dir, base_dir, plist, timeout, result, version, track, cmd;

var adobe_path_patterns = make_list('*Adobe*Reader*.app', '*Acrobat*Reader*.app', '*Adobe*Acrobat*Reader*.app');

var dirs = find_cmd(
    path_patterns:adobe_path_patterns,
    start:'/Applications',
    timeout:240,
    maxdepth:1,
    sanitize_result:TRUE
  );

if (info_t == INFO_SSH) ssh_close_connection();

if (empty_or_null(dirs)) audit(AUDIT_NOT_INST, app);
else if(dirs[0] == FIND_OK ) dirs = dirs[1];

var install_count = 0;

foreach dir (split(dirs, keep:FALSE))
{
  ## skip any other variant that doesn't match
  if (!pregmatch(string:dir, pattern:"(Adobe\sAcrobat\sReader*|Adobe\sReader*|Acrobat\sReader*)"))
    audit(AUDIT_NOT_INST, app);

  base_dir = dir - "/Applications";

  plist = dir + "/Contents/Info-macos.plist";

  result = adobe_extract_version_track(plist:plist);
  if (empty_or_null(result[0]))
  {
    plist = dir + "/Contents/Info.plist";
    result = adobe_extract_version_track(plist:plist);
  }

  version = result[0];
  track = result[1];

  if (isnull(version) || version !~ "^[0-9]+\.") version = UNKNOWN_VER;
  if (isnull(track)) track = UNKNOWN_VER;

  set_kb_item(name:kb_base+base_dir+"/Version", value:version);
  set_kb_item(name:kb_base+base_dir+"/Track", value:track);

  register_install(
    app_name:app,
    vendor : 'Adobe',
    product : 'Acrobat Reader',
    path:dir,
    version:version,
    display_version:version,
    cpe:"cpe:/a:adobe:acrobat_reader");

  install_count += 1;
}

if (install_count)
{
  set_kb_item(name:kb_base+"/Installed", value:TRUE);
  report_installs(app_name:app, port:0);
}
else audit(AUDIT_UNKNOWN_APP_VER, app);
