#TRUSTED 489e9a2389ee1beca7ed48f49492737cccd610e7600b88178b6977f2b61037edcb1848dfa6db855bd9494715572feff70cf54021beb4a90dae81716ecff4697c8d73077f436b5c9b4ccee8a3aaab45f01f946bd954f804c98ad52bf664d56fc31117cc02721a3a1be6441bdf3fa26eaf9627bad0ba291422c8baf5c926905772aa5f56b98b103fd4784c39edf44dfe86f6d7e46a9c644538546ec5d29ef34f79660507d06d135e2fee7cc4039798e14a36444173b953db935e9f1ad757954daf65e785d7a19383dc892565c8b5afb7e69808d6273e7d670acb5c17296b622fcb889a5572d3b51bd4eb98b671af8ade8287e9c7ea3a3a54d259e23665aa2cf87418ff810ddaa73bbeca73c81c94035ae7244dd0a7037cd48d4d9af7c1b8ee37ad883d59b8b3085c240deb0e204613d68d4ed3beac3121e476bd4ec7df33fa8a21ce1c6818d45efc4aa5e2f8d7c59ae9fcf8bede391b8d350d681995e9d0086d5fd872b488c13ed88ea28022daad61d53944ea801f83279ed13d5ad52e5f6eb1243609e55d6c0734891cb82d96848f8161ba607ebc2e5190d5f0edb2a29fbd007db430c74d1c9e7d65ec86e896739c08a18388befadacdad91616a4425cdfda251af8134d2dff94b3cb2e114f13e3e86b3e61395ca406144ac6a33b670f11f4f7a5235309130ce26fbb07c015f87bf12ba37eeb6f7d48c9c297ba2a7ac291e7a6a
#TRUST-RSA-SHA256 778a74bebddce77c881382641771a556dc782b13605e0d4dd0da357e5572abc25b1f4018a49ef2a09be5ebc097f7fb2a9264f23a530197ad4b6a831687de8295acdef317a352681e9e18975d23a608ea7535bd5b6a3bdb3b4950a57ba6c0cb908b38c9aad6c7a851aa8e683c6d919b1d1222fc2963dc6be2dabe064964e9fab75a3a487186478c8792e205c9ec3a4ba0ab87482f5b4a4b363cc5d0fb6c6682e9e03c316733722ebfd42aa68ddef87cc1936eec35517a73d1e094337332c41b08a376b37fbc402924166ebc76df64f5f8eb917b75495fdf3b066f18faede7e0e9ac35708996d7d506a4353b1a52e9dd4ccc6e75b6c266ddff64e0745ac531499a7b332ef675b76070ce6ddc3e6244a4a19261c500ca43391dce1bc05ecb277a112b9fa0205b84dfd3cd636d65038b91a864ee12299f7f49c5fd5c3119709e97ede6e55817570e0948d4b9a12b893044c2a6c86bc330034646c3cb0276d53b894d1eeed8599ea7a9f1a6767834ecf8adb46ca97953135012ee1d00603bea6cff53c245961311c658f8c6224c525ba1536a20bf720b21e27c49b68e2827cf50d39fb3ddb9e1c3b2a73705541a69e6b19a25e2df77c3a45b438384bf110d8b4fe5477f6dcffbd05777105ea0bb0dc534106a58f56163914723f8755563cba9b287628aad45f64515bacd962b31ec39be122cd4a2cb8eabfb4ab214a909f692476cde
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56557);
  script_version("1.29");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/28");

  script_xref(name:"IAVT", value:"0001-T-0730");

  script_name(english:"Thunderbird Installed (Mac OS X)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains an alternative email client.");
  script_set_attribute(attribute:"description", value:
"Mozilla Thunderbird is installed on the remote Mac OS X host.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/thunderbird/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version");

  exit(0);
}

include("ssh_func.inc");
include("macosx_func.inc");
include("install_func.inc");

var app = "Mozilla Thunderbird";

if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");


var kb_base = "MacOSX/Thunderbird";

var path = '/Applications/Thunderbird.app';
var plist = path + '/Contents/Info.plist';
var cmd =  'plutil -convert xml1 -o - \'' + plist + '\' 2>/dev/null | ' +
  'grep -A 1 CFBundleShortVersionString | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
var version = exec_cmd(cmd:cmd);
if (!strlen(version)) audit(AUDIT_NOT_INST, app);

set_kb_item(name:kb_base+"/Installed", value:TRUE);

if (version !~ "^[0-9]") audit(AUDIT_VER_FAIL, app);
set_kb_item(name:kb_base+"/Version", value:version);

# Set path here so if, in the future, locations
# change on Mac, we can detect and use this variable
# and KB item in version checks.
set_kb_item(name:kb_base+"/Path", value:path);
var orig_version = version;

# Check if ESR
var sw_edition = NULL;
var esr_major_versions_pattern = "^(10\.|17\.|115\.|128\.)";
if (version =~ esr_major_versions_pattern)
{
  var xul_file = path + '/Contents/MacOS/XUL';
  cmd = 'grep -ie "esr.releasechannel" '+xul_file;
  var is_esr_res = exec_cmd(cmd:cmd);

  if (is_esr_res =~ "^Binary file.*\/XUL matches")
  {
    var is_esr = " ESR";
    set_kb_item(name:kb_base+"/is_esr", value:TRUE);
    version += " ESR";
    sw_edition = 'ESR';
  }
  else
  {
    info_connect(exit_on_fail:true);
    var path_to_esr = ldnix::append_path(path:path, value:'/Contents/Resources/application.ini');
    if (ldnix::file_exists(file:path_to_esr))
    {
      var contents = ldnix::get_file_contents(file:path_to_esr);

      var esr_matches = pregmatch(string:contents, pattern:"RemotingName=thunderbird-esr");
      if (!isnull(esr_matches))
      {
        is_esr = " ESR";
        set_kb_item(name:kb_base+"/is_esr", value:TRUE);
        version += " ESR";
        sw_edition = 'ESR';
      }
    }
  }
  
}
#ESR flag is not included in app name, as ESR use was depricated, all versions are now considered part of the main branch for SEOL consideration where this is used.
register_install(
  app_name:app, 
  vendor : 'Mozilla',
  product : 'Thunderbird',
  sw_edition : sw_edition,
  path:path,
  version:orig_version,
  cpe:"cpe:/a:mozilla:thunderbird"
);

report_installs(app_name:app + is_esr);