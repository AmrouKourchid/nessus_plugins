#TRUSTED 4356f20e0d3c58b6c2f0b0d71850ffea76d02748a8a46f3408d22a15333e672f2fe71b1d00d069f0492d5cd3db1dc0e03a371fb81ed2dac4990d4965e61abbe85e4a6a6da6c5a74dab71ee9fc299d64866caacffb3933a98ebc08120b74eb7e391c6c241d1579058cbd777d2a908bdae81e0f8c58f4c725115c1ef21875d1b08e2db6fcd9e4d61e0cfd7456efe404f5d2f499cc3ebb8ce220cd37ce0af7ed57d14d5c4d63e22ccd3b77d1d29f9007ca2d66ef2bdf9a2491268aabce89547298d2137dd42d45b205367177be74df717e300f201659f66d0d89eb52e6829c7a5e434a23c08edf702a299c8476494764d7b8f24ad4919c21502365a6b2d45b9751200a45760601aca4610df501428024c9bdbf7c5b0c339824c4493426e4280eb8b591717c97fe84ace3c2eb5df55d110ed77006c01e1c7393db851e2f07151c7c0c347d9e8445c5b9703c4860141955169c260586e89916ce827ff7426c1501d71cf7518b93641ce1605434fd9a8aaefffb22c7f6c343cb701bd338c598c3bf77a21073e54217799295da005c54dd225c6ec05ce195fdace6d2cc358e0e1e3bd2f88d5bb8a94104c4cf243d117394b5be1af9ffa447ed1d88da1f6d299ccbba0344f7b51091990353582ef2b58bed577d77f7bc8e3fadd1cdbc8e156abe74ed3861c660998bf8327be63e65a80cb890aed04f12a0598d0eeba19e829389766e64d
#TRUST-RSA-SHA256 87c854a96a0c499d786eba3cee6df936ac596987f7fd0fbd26767750e4819338f2a6e0c25204c4d9d67136db56b338d3f59ebbe95cc7480b5657d33de207959604c7592f2f0565ae4f88657cb07d8a8582ea9794feaa85b3636aa95962798dd6d59114786de52ab35776307aaa0104fb6d9a48ab9888b9c87c83b439fa4d531291bcf09f65e098a031fbb6ece2d2a76bfee5bc87561b66a153afdf6affe6ac14e62cac487974984f49b1a62c6ebc5526fbf5b6d537ddb4fb1becf15b81cabaa5460cac6a323398d684e2eaedd7f6d198d5a061494873f43a96f6e2b9460ff9b5220ac31a10449a30c949034679a876d829affff021b2d5d548710727614cf7ff0deaeff5de5e83a7e8f7b9d68d63ee941f1418e582cfd983d20a4d97db3bc7955074babfa753b50eb59f9ac3fb7b428385a267d7834b63f3a745516a88e1c2171649e740f5a876848d53ea0b40688d02c06ad62c244529f2b0532ab78b19205f799c1a7d7da499938375a70c53e12f726e5236a7fc9b86d290364dccdbbad90df13efb86659e357da1529213c1effb644dec9a5a9be60954049ffb7a283450d411d3edb66d28fa7921a44e298a27e0e09a3b00ed2faf255898f618adb1a73601ddf4e8bbbe705e5d69c93c1ad414c16c484f538d0c08787a4125e63e0acbbf84eed2040831b4cb8bae77492568125b03f4d407f88d59d8eeb75d44af2bfc6910
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65924);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_name(english:"Google Picasa Installed (Mac OS X)");
  script_summary(english:"Gets Google Picasa version from Info.plist");

  script_set_attribute(attribute:"synopsis", value:"Google Picasa is installed on the remote Mac OS X host.");
  script_set_attribute(attribute:"description", value:"Google Picasa is installed on the remote Mac OS X host.");
  script_set_attribute(attribute:"see_also", value:"http://www.google.com/picasa/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:picasa");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");
include("install_func.inc");


enable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

appname = "Google Picasa";
kb_base = "MacOSX/Picasa";

path = '/Applications/Picasa.app';
plist = path + '/Contents/Info.plist';
cmd = 'cat \'' + plist + '\' | ' +
  'grep -A 1 CFBundleVersion | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
version = exec_cmd(cmd:cmd);

if (!version)
{
  cmd = 'cat \'' + plist + '\' | ' +
    'grep -A 1 CFBundleShortVersionString | ' +
    'tail -n 1 | ' +
    'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
  version = exec_cmd(cmd:cmd);
}

if (!strlen(version)) audit(AUDIT_NOT_INST, appname);

if (version !~ "^[0-9][0-9.]+$") audit(AUDIT_VER_FAIL, appname);

set_kb_item(name:kb_base+"/Installed", value:TRUE);

ver = split(version, sep:".", keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

version_ui = ver[0] + "." + ver[1] + " Build " + ver[2] + "." + ver[3];

set_kb_item(name:kb_base+"/Version", value:version);
set_kb_item(name:kb_base+"/Version_UI", value:version_ui);
set_kb_item(name:kb_base+"/Path", value:path);

register_install(
  app_name:appname,
  vendor : 'Google',
  product : 'Picasa',
  path:path,
  version:version,
  display_version:version_ui,
  cpe:"cpe:/a:google:picasa");

report_installs(app_name:appname);

