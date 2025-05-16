#TRUSTED 78bf8ed4e8abcbce7a571d6c7da568d1457609d0b992998d96e51c601605c6a5099bb9b6a7a8c552c2f57cc196414aedd90ea08d8f3afd2b6e03336ad4756f9943a8303a7f008e688bf76c90bb5f9e027237b5654f50e6cadedb186fb083fa82a9dd03d1593577420f86a410f5339613cfc9b5f9ed59904a79f89ac96ee47dea14f3128a37c3228c06e45c7caf6054980998844bf0be94849a5f0b77a25208d4bf8f6a4fe8309bd2e7934ddb79aa20b79ca7a4c885c1aa3a90dfbd7c97b6d103d82c4608e3a82d7618a1c72f4c087cac5ed9e349c792c31d769d27b53620c54905f96333b22c6d8a8f4091579381eb03e820f2bc61adfad0507b7214e550bf53d92bd1fb4c77e112d62e406eb1b968d49c0e0a5686fff93bc80a40c3f8c29c6bea236560484999cd6696acad3530be0b6a5cdf7976fa03414a8512f4b06e294a78f961936073af7cbe4749c34c45fde4460bc9495e8573bb6f148c309a845ae9e508e64ffc2c70248946692dd8631ef78a800a846703123dd03b22a60c138f5afc7bc8a79aef1c2af9461d9273164cfbec1e58c2b77ce7189b4f069ff19227506afd2c95a4052c34d1151ee7a1fcfa76cc2ea1ff45ded7f310bdc610836e3d308b13c8ae535ef96f7bdc47d2a053cf350e69088e2a7401d3a43a94a525c2be1bd67f837a638b4c17bf76f04d5a12dcc815c5f15121a25217fd9993aa20a53a73
#TRUST-RSA-SHA256 40d7c598960cf9e827b08897eac10c4d6b43a9c43b247f737271e9eb9bd2561dace4563c91e489e01cfc3a44c1706c93d986170c6b7183afaab0c8922052812673720bd894ea4b8a341415e78b866f99b307e0521c8be01aaea4092ff67b906d7d33ab51ab68c9e9c96c28d7d6e2d9469f3b59feae507a4a3b32a94acd6cc1d840bb5fc0399136e0fbd052a6598f1ab687adf6780f3fd91cba3aa449081bdd6c1d6f037830668147513c24b88e8552051f753492ceacba56a6f24fc69e2c8ced66f58d88f96be23dadcca681f61c9d27dd33fdf486c0cf8d1604dcf646dbf97467e7827f51e7d903b59ffd0736034cb062ca9fd505a26379157aaeec28d70125dd225272e38d164d6fdd0ea990a80baffa7224bfbbe16885c716c6cd13898444fb633e4749ce0ab6708edd991a21b54e05ff18bbb87e102adc8633ee3f63161d937d901ac387157397f70842db2fc1d4ecb8977616ffb5c5ac59689d019ff129c76986b905eda481a271c42e542ef615104a223367f7acfd5a87b93e48fed2434439ca4bf2f40e69c6386e04d835480f29ba0bf4f57888fb3b5158b829b4b0d0fa5c0e00ba54829b39b93009143fd0528264ac8248ef5e3668dbbf2ca941b4c2928219a6495312ccd0d62bc835ce90545fe864f490d9262b10cdaa2e843db41095d3bc538910111acc919fb7c76ed4bf6d0497fba4ff000186f2bdd9034d8027
#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);


include("compat.inc");


if (description)
{
  script_id(53843);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_name(english:"Skype for Mac Installed (credentialed check)");
  script_summary(english:"Gets Skype version from Info.plist");

  script_set_attribute(
    attribute:"synopsis",
    value:"Skype is installed on the remote Mac OS X host."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Skype, a peer-to-peer Voice Over IP application, is installed on
the remote Mac OS X host.

Due to the peer-to-peer nature of Skype, any user connecting to the 
Skype network may consume a large amount of bandwidth."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://developer.skype.com/MacSkype"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Make sure that use of this program agrees with your organization's
acceptable use and security policies."
  );
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:skype:skype");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/MacOSX/packages");

  exit(0);
}


include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");
include("global_settings.inc");
include("install_func.inc");


enable_ssh_wrappers();

packages = get_kb_item("Host/MacOSX/packages");
if (!packages) exit(0, "The 'Host/MacOSX/packages' KB item is missing.");

plist = "/Applications/Skype.app/Contents/Info.plist";
cmd = string(
  "cat '", plist, "' | ",
  "grep -A 1 CFBundleShortVersionString | ",
  "tail -n 1 | ",
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\''
);
version = exec_cmd(cmd:cmd);
if(isnull(version)) exit(0, "Skype is not installed.");
if (version !~ "^[0-9]") exit(1, "Failed to get the version - '" + version + "'.");

# nb: older versions (eg, 1.3.0.14) have their version info in a different spot.
if (version =~ "^0\.")
{
  cmd = string(
    "cat '", plist, "' | ",
    "grep -A 1 CFBundleVersion | ",
    "tail -n 1 | ",
    'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\''
  );
  version2 = exec_cmd(cmd:cmd);
  if(version2 =~ "^1\.") version = version2;
}
set_kb_item(name:"MacOSX/Skype/Version", value:version);

gs_opt = get_kb_item("global_settings/report_verbosity");
if (gs_opt && gs_opt != 'Quiet') security_note(port:0, extra:'\n  Version : ' + version + '\n');
else security_note(0);

app = "Skype";
path = "/Applications/Skype.app"; 
cpe = "cpe:/a:skype:skype";

register_install(
  vendor   : "Skype",
  product  : "Skype",
  app_name : app,
  version  : version,
  path     : path,
  cpe      : cpe
);
