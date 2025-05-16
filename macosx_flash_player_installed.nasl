#TRUSTED 7676c61695edeb68cc0194a760aa84b15a1b48052fa58640317201716b3a557cdad6e0a8178b6d271df2677048cda1e4f54fb26e2fa224f95d4c5745f506df3f9718d45d6a0d9b1e8405112c15206f5007472be06864f12f14ca50f1430cb018f2df42b35111e970d69cefaa6f88116ed0f2239b0682c0c043f387bf0f3b2b43a58b60afd0438da403b927820cc772ea86c1e86a3ea34615407275ee20b757746119fd165d70d62913d13eb3a87e226d1041d79714e9ac666657cde971bda3e0c108c5bdb88145c68c63d5e5816708bb195f686ced775f8a12f29dc53104cc4df883322c1c9107b968b1b35531c98bf8d31887555649c6a9c4b4baba6de22fa050f1448c2a67ac6edb5f23f85b2d7502261d4120a80c50a9dc2adca5e436da206f4a4faf7cc4d204d808967acaf37820b252d00dacd7a2d4b0d17ae82040ab243e90b33b4c043980a5908c18f88f8a916d56901e54f3675fa69462bca768b85d4d6d67e681db40ca3a7a38e034a16f26f34f0ef29394b2951ee9217114e22173cd2631f343667ecc4dccf1d59f4ff92df7c0ae74687e1f385ebf61110e570ba7c70cd9521d01ffe78b4ead8d85d557e262a75588324324a5bf5a9b892bde6424ad04dacaee3c577b7c0f381de7d287232520ef0c5803f33fe9ee5bcea7b12fa8b0bfb1882946045af74c1b1c4fe8dd8bb68f977f04158ee340ca867e76edd14d
#TRUST-RSA-SHA256 b1129595584cb78d6c70ce0e34c37ab0762113736d0a3e548efd0762ed501e18cd7ae053bd5a34dbfd270bc660b6abeb36d9134ba2f91ab4cc62983d5cc87d0d9096664bddc582263458fce0442053447abd366084cfc85707d15689068548c60b69cd53256486ae5c27850c13628718f0d16c88d106d4562652b74acac646adfe0ef20fd6c821f5c9658d6a275db1b6a3af92e0b2e08c8b4d4f17883680728ed2ec4efc2f899662469c9b2022eebbe1466e9f35e663abcdc3f353a33951d9feea866b1bdb55e3e7fe2df72e8637696a68afc025de45ed69441b008d5829ad7093838a07e783f40e43e7130b35f54a0b28635ca562648fb01d77d2ce56fa6f107f709bc47de68cd45325fac9db29b968174720d5812a95da7fb9332c0c1fc42fd000d8f753acc7b38031acecb2897f0467436e29ca3c1e14bbb97f1f0cd1a34cae1cc154f921b5ed6d89ff48dd9a116564ec6499748b9dd52552f97b00839ce7fc22d8b73bc1fc442a204d0004636f7e3502fc3ff1749b8c138f68bbaf4eaac4c51d734acbf904376ff32bb97c8d0b65160deb1525e6cb4b95593bb4d7b4049433b97c81b9777ac26d9ac8331a0ad7333df6da9445c2e9a7ccb8187ae59ab094085ecbbead3f4be27873071c4d242e19c93657ceb3a774564ee55f29ff5ad5400651622880fd71425f15dfdc9aa36fefcc675200b8a3a1652505df8c8c02c527
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(53914);
  script_version("1.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_xref(name:"IAVT", value:"0001-T-0519");

  script_name(english:"Adobe Flash Player for Mac Installed");
  script_summary(english:"Gets Flash Player version from Info.plist");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains a browser enhancement for displaying
multimedia content.");
  script_set_attribute(attribute:"description", value:"Adobe Flash Player for Mac is installed on the remote Mac OS X host.");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/products/flashplayer/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:flash_player");
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


include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");
include("audit.inc");
include("install_func.inc");

app = "Flash Player";

enable_ssh_wrappers();

packages = get_kb_item("Host/MacOSX/packages");
if (!packages) exit(0, "The 'Host/MacOSX/packages' KB item is missing.");

path = "/Library/Internet Plug-Ins/Flash Player.plugin";
plist = path + "/Contents/Info.plist";
cmd = string(
  "cat '", plist, "' | ",
  "grep -A 1 CFBundleShortVersionString | ",
  "tail -n 1 | ",
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\''
);
version = exec_cmd(cmd:cmd);
if (isnull(version)) exit(0, "Flash Player is not installed.");
if (version !~ "^[0-9]") exit(1, "Failed to get the version - '" + version + "'.");

set_kb_item(name:"MacOSX/Flash_Player/Path", value:path);
set_kb_item(name:"MacOSX/Flash_Player/Version", value:version);

register_install(
  app_name:app,
  vendor : 'Adobe',
  product : 'Flash Player',
  path:path,
  version:version,
  cpe:"cpe:/a:adobe:flash_player");

report_installs(app_name:app);

