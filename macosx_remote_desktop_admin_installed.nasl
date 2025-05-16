#TRUSTED 33c4824a01610d68b2b89ddfe64511af82ffb389a2c67fcf2f76d1f799743b9dd8c283ede0106a6ae9266dc120331bf43e6d1a2c40e965dd7997280bf340cf9f0c181df40db268680c633a9b38dbd21bde38a9b21e1e09dc016cb5c1418fec579a21cdc023cbd1e9a43725be7e64c7adfdda9f22e993302a11337a816a4798f542b4cc6e0fa4324743dd2cba7ed612f5ce2e232ee165c8cfc47759512b21188e2a2fe02ef082f16dc101c7c89b7383b69b9148bced94ca10bb1a2bb4678a1d56c892d8e7ea19170eb700aac5cfc1525935cd0ab6d1d3355685c0c6f913e0e6f32b80c401551f24363564f2949195d2c908b726b3babd4cf6f8445d5fd87160699d41b4cb1fd5db634be94c6fdce64e6cb89cde6616461b4f51cf05e846159d52a4367f9405ba76b50caa3e7d7c3141caa20190bb593479139e73975ce12144293176e351e50529ea0d08a0d3e71b4f2ed4a00c7620474bfebabfc1f6695632fc95e3b59212a3760566013fc1b748f1c2d36fa61a4542e8f747cc43e5bfad6a9c1d5e41e7ff82f043802f736563d055678edf9417c33b6f5a9f238b5c27058fdde4e41f9c0a632c038e3fcac7b2b1a5f589d2ea018818d2dc54c943fc31c7bf6ca8911cc7e750b853ac1dd88e6191789943bcd01aa1e070de871f135fcb4a289c495f4bc2215f14b4cc1b2268ae21ed4e31b4a1735f8f2085a4d7a75ba51f9670
#TRUST-RSA-SHA256 3dfe9578f9c78378b4142776c5fabf65c0484bb3a83b40912f4a33322b61d6740519a3c1237b7c2b6954bb3163747865958ab0a970656a1ca9ed4c7f7736e50614f1a8e1c06f83b48c1b0ba01cb5c2e7a348a06daa519f134668ae59c950c790fc4281867bd1c56fcc6fd0da086dca02452afd61815216a756cdd574459b090f0e9b1e6c14fa0dc03dbb3a26335eeb3a7b2ce9b2deb483689ed223f228e6ce3573691f04ee32a24262253fe85e8e249c7ba0f2310a85a5ae743450b152be6eecef7f7620ee9bb6def8e1bc0cac9111a2c526f7d04710583cd6abf133c63a08f13f32ba288612352cb06b2fdd00fbf1ab373905fffa7464e9356c69b06d9fd285a44cf0a156d7cac4ad8b6dd2e9b657f1f11cc1ea820f5b65feaf39ffddcea3cb4a7e922ca30a03bb488dcc198675dba51067a366c0d345ae566b445e7eb99eafac1a0ad8ce5a641089a21d5ada2dd792bb10f046bb96effe0719f61ae54ae0644817e4c09e7ed072e70461e81a545f87079221f65bc5073f27feb7dc5dce0b538749531b0a678757016b81f7ae079e2b31a1d5054a196606992c694bab1d71c4f57ed9ac43e2f783d3e923049ae4086997e1216464430139b360a6b1c74fd9413674a0a6cbed96d7df4707c791ca5c503c167f028a9f774ec8b77722069a7e18da801dfd90d3acf8406934c16c1da53ef0b2a279c014e2f4cc33ea72b0269f06
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(61620);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_name(english:"Apple Remote Desktop Admin Detection (Mac OS X)");
  script_summary(english:"Reads version from Info.plist");

  script_set_attribute(attribute:"synopsis", value:"A remote management tool is installed on the remote Mac OS X host.");
  script_set_attribute(attribute:"description", value:
"Apple Remote Desktop Admin is installed on the remote Mac OS X host.
It is a tool for managing Mac computers on a network.");
  script_set_attribute(attribute:"see_also", value:"http://www.apple.com/remotedesktop/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:apple_remote_desktop");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

app = "Apple Remote Desktop Admin";

enable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/MacOSX/Version"))audit(AUDIT_HOST_NOT, "running Mac OS X");

kb_base = "MacOSX/Remote_Desktop_Admin";

path = '/Applications/Remote Desktop.app';
plist = path + '/Contents/Info.plist';
cmd =  'plutil -convert xml1 -o - \'' + plist + '\' 2>/dev/null | ' +
  'grep -A 1 CFBundleShortVersionString | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
version = exec_cmd(cmd:cmd);
if (!strlen(version)) audit(AUDIT_NOT_INST, app);

set_kb_item(name:kb_base+"/Installed", value:TRUE);
set_kb_item(name:kb_base+"/Path", value:path);

if (version !~ "^[0-9]") exit(1, "The version does not look valid (" + version + ").");
set_kb_item(name:kb_base+"/Version", value:version);

register_install(
  vendor:"Apple",
  product:"Apple Remote Desktop",
  app_name:app,
  path:path,
  version:version,
  cpe:"cpe:/a:apple:apple_remote_desktop");

report_installs(app_name:app);

