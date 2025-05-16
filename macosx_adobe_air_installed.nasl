#TRUSTED 955c69e5319e35116c672339ca83504d981e5eb9541c93f4e0ce692c5b22ce6dae6fa6b11379d979d6f63b271056df51bfa30c092694664fb41e8e69584f294b1df2ff8934d43779521cd021cda241508c54a103180ae818085fd7ebef0e66f871d2b19171a196007d3a4a223b259a87a1a29a5e8d2f68b0f5c7e3f468199d64d339ed3f4ad1edab67cac55a26287f98bcd76b1e70871c93b334a7624d0c195b5b8473682a49e164ee75790116aead5fa66498887051c802ebc465b4bcb20c8c3d4f5a4b8662a28c991d5f30fb775e62b93c889c0db2328f41a13c6b5424f6730b4cfea12de45ed3539722579249228c91ae9d24c83150c34886767b39e0913688b86d9433d99e2629498771893b51ae6e77e68c42f92a8304f30cc22d5569c36f0f0626fb9719e553cb0b13d7164602e23b0797e2a8c37da5c160a429b0237b90510b2237cb6fedd20a4167a5dd436a605514e16676166a44933e9cc3ae6bf3afd7e93d84c0e6ab373d6a72879c02ecb14e0470ec8ec27d07795daa8b8c92c3d424a02f63df88198999aacaf5dfb5ed6bee98153db4bf9abf792f83515ca60ddc0dc5a29826f0fc80e3378c484e0697868601afa1752f8e1d2b30fda5409e19679c6dc85bc3ac097a4e4beeeb15cac6997e3da37713bbc6a1cc89b0b4daf81d2851dfb9a4bba385966bc6d5624d8514df387426e92796cc7cb8e3b7baf898cf
#TRUST-RSA-SHA256 b2e7e2aec27ea1a0439456a50bb481679908a081f51ab801c335e94e5f656514c932e9f95145bb5a71c992cab2f792a7c9ad4b96983d065be86390a2cb21ab8e018fe6a1b2ac4f97cce1b37b1e8750fb476fa7e6cfe0224d056ae9e3d7a5258f90310913b2c558d32e0b32ea3c86c3ca7e989d68c6bb87ef2b507fcaba32eb9d55453efed5eebd1e0ca400985b67dd653d7e53c3198d33e3e1087c774910aba56196c5f29d3d658eb0321b6b45ddb97f583c6ffdac04091f6a14cc47b91dbaf7f0ea0c0c7ecac48104e29f91b59228214b29b8e5e206886592a3083c04d60e8155e9194607f8e876a3ef93de38b6ae51bbff5213d12381a187370b11e22bf654ee32ae2df35cfe6f3872f6cf7e5b40d84823a9119161808b3c37f24d3b065998d822c74e78dd0a8650752afaf804f22b1ccab0aa679f2af4df2839f3686a249e8552234ec9f80f46a05fc66f244878326d7bf7d2d431d4569bbf04b9a7f9c70a02b941c22cde5e91835e50617aef1bcf849e556106f6498b5aba59f8c4a6d55b4a56fe1da29325b4a7bed0745184938cd5f867b2537e4a992235a86e74362589a9694a3a24abd69038cc8f8c77edcef51020f856bb5b2f2dee88030dec4dc506dca5c3c7989c83ea8d87a2e5d13760c380be123b76b103a7ad9f80a87ede1261006809886503c035ee97f0a5ddd033dc85c60c465982d088845525435696f246
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56960);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_name(english:"Adobe AIR for Mac Installed");
  script_summary(english:"Gets AIR version from Info.plist");

  script_set_attribute(attribute:"synopsis", value:"The remote Mac OS X host contains a runtime environment.");
  script_set_attribute(attribute:"description", value:
"Adobe AIR for Mac is installed on the remote host. It is a browser-
independent runtime environment that supports HTML, JavaScript, and
Flash code and provides for Rich Internet Applications (RIAs).");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/products/air.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:air");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");
include("audit.inc");
include("install_func.inc");

app = "Adobe AIR";

enable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");


os = get_kb_item("Host/MacOSX/Version");
if (!os) exit(0, "The host does not appear to be running Mac OS X.");


path = '/Library/Frameworks/Adobe AIR.framework';
plist = path + '/Versions/Current/Resources/Info.plist';
cmd =
  'cat \'' + plist + '\' | ' +
  'grep -A 1 CFBundleVersion | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
version = exec_cmd(cmd:cmd);
if (isnull(version)) exit(0, "Adobe AIR is not installed.");
if (version !~ "^[0-9]") exit(1, "Failed to get the version - '" + version + "'.");

set_kb_item(name:"MacOSX/Adobe_AIR/Path", value:path);
set_kb_item(name:"MacOSX/Adobe_AIR/Version", value:version);

register_install(
  app_name:app,
  vendor : 'Adobe',
  product : 'AIR',
  path:path,
  version:version,
  cpe:"cpe:/a:adobe:air");

report_installs(app_name:app);

