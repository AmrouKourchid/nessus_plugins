#TRUSTED 9a689644d4d712b070d28df1e29656f3b85eeeb8b7966504c9bbb71e3127aea8977d84e4f68132ae47a5574400752cc50601b9e64272dd3e654ed543acbcbc4435ad275f7119efca8fe08384011ff9d58010c8b93db67f44102dc508e6cb56f36a093f775a2dd541ac55058222e93e9b59939032885cdf49f6c83acab9de8da853aab586e12bbbf03cd2ceb883485085347e6f35977ea511c9098eec27961b12c174cafe4d70eee551f34f1fec04625475e47cf89993de36ebc356fdca16845d363dcacaae1c6966f053c95f389cf2f1f49e68023ac845d364ecafe3e39a92d5e6049f1978c6c16b55737d3cea3c1394521d1765fcc712b8952546e996860b519986bfb532424d5f3dcfa02654968fb563d8679bb51bea2f1b32af2689b9c0c91bde653106c20306705c2b799c575ce094819780efb528d44d1e99245d370f07feba775c491160417811bb0bdcc729a50977e1fc987f46d2d40091c9aed33531fd01bc25686dfcd82b2e998ff06ffd81ae678bef26be8f76e571247239705a679553ad05ce55f0454f8f9557310e9ca923928f6b5dfef6974c31f56b2407bb39c74594f4ad61a4cabcb58f05b156b8e514a02801207509bffbc503704313aab121933c004c8479de479ba0cd4543b1a5c2e7a2b10180c73c53d9862bf786cd500b8c159789bb54447395cd7d65fa225835819b9a8932e7d258c23826e03af149
#TRUST-RSA-SHA256 994d2f1a83f0692485ba39695314f758409add9b9cd069d2e536ea648bf260a9fd4b0609ddf05a3cc16b179535a2f15c2c939ed3b74cb36ffa92dcc0af69de2044ba1308560df9332e31115c8de4bed4986ba3235bc1776ecd8cf6cf035761e7ce52b3c860eafc73e7481d5c0ecc5da6aa1948b4e1f650c40151c1509844845271777b3a4bd9a998e8dbfeb6fb6e9c6ead7a1136840761ad0c466548f2220278115554d2f406855a2c29daeb35e7d664ffaf961b59762e47bb90436cd4bec5a547ae4f60972275e8728011fc3ca159bf60cbac3f8d9ce7d58aac25b9f76813274e5c8ba91b7243dd1e7c07daf57ee0139e1e6ed8678b9aacb60fe3dedc7761334b0077bab13c269cc9627c5752be43580ec2e8b5c44bb0da0daae660a6fe34143f2163874750f7f8ceaddcd93e4fafc0e73e07a5f9c9176fce5230cdb84aba6dd20c7ef1f82e5b89085bb96712cefba5ef489272d6c914b28bb5f3b9601267d6cf1d5ddc959b43eb693d5c19249e54ec06049864b5f810ccfe9396263dd423b76b4ce1fecaf45e486c94ffead86f08405b5c8e2f68278c1812691940312af8b494f3f2713dc0a50e52ccb7165dc3fd8d5b870178312749a9acbf0f8700cd79c81e8452f2e70479091e2049887be0d0e12d9d47a29c58b0399133eac0df05f7cecb65d0c345af58ff02ad15d1f2b167f74fd96109be763660c913f7cebd626242
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65673);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_name(english:"Novell Messenger Client Detection (Mac OS X)");
  script_summary(english:"Detects installs of Novell Messenger (formerly GroupWise Messenger) Client");

  script_set_attribute(attribute:"synopsis", value:"The remote host has an instant messaging client installed.");
  script_set_attribute(attribute:"description", value:
"The remote host has Novell Messenger (formerly GroupWise Messenger)
client installed. This is an instant messaging client based on Novell
eDirectory.");
  script_set_attribute(attribute:"see_also", value:"http://www.novell.com/documentation/novell_messenger22/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:novell:messenger");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:novell:groupwise_messenger");
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

app = "Novell Messenger Client";

enable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

kb_base = "MacOSX/Novell_Messenger_Client";

path = '/Applications/Messenger.app';
plist = path + '/Contents/Info.plist';

# Messenger.app is not very unique, so double check this is a
# Novell Product
cmd =  'plutil -convert xml1 -o - \'' + plist + '\' | grep \'string\'';
plist_string_contents = tolower(exec_cmd(cmd:cmd));
if("novell" >!< plist_string_contents && 'groupwise' >!< plist_string_contents)
  audit(AUDIT_NOT_INST, app);

cmd =  'plutil -convert xml1 -o - \'' + plist + '\' | ' +
  'grep -A 1 CFBundleVersion | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
version = exec_cmd(cmd:cmd);

if (!strlen(version)) audit(AUDIT_NOT_INST, app);

set_kb_item(name:kb_base+"/Installed", value:TRUE);

if (version !~ "^[0-9]") audit(AUDIT_VER_FAIL, app);

set_kb_item(name:kb_base+"/Version", value:version);
set_kb_item(name:kb_base+"/Path", value:path);

register_install(
  app_name:app,
  vendor : 'Novell',
  product : 'GroupWise Messenger',
  path:path,
  version:version,
  cpe:"cpe:/a:novell:messenger");

report_installs(app_name:app);

