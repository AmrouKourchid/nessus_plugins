#TRUSTED 24a1c7dbf267f53fc9fe041dedd784de81f22f5aac03bbaecca697e506a8360ec1517b43b932a327a72e910b7c8cd735b0e6af91b8c5b5706c51a7077887174038511f7deab9e5d88dc9fdc5fa24d34c97dc5698f06715309e258c176d2b47e75bcb951f53f551f35db5c7c50141167f860092b960353f5d6da2ab9829fa581fa26fe3352c76726a803a17e40f2d06aeabeada57cce4e3c62d185c65c2ef67b2e73827a8de868019dddbd510f70256e1b3831e9dc8de681f336ecb91553f7085767183f4b07ca42d789300b1a70c480cc68f3628dd8cc7817b05a09ff70ddbe03c3bc836898b4e839c20014824c9dc7c5e794accffe4b2c2e50ed4ac91a771a3d6e9cedf206bf42b80df21a748f8caa5ab37314d391d1bd19a704e59a3918a03a3ed0a8d9deb55ba3c25f6a50b2f4c89c41473410fb7b50fd9e0cf8b45067fa89bbfba0425626c7f9bf64fb0a7c04d0a37a19d22289deb9a0723b989fe02e243d35c137dc4cc169491a1ea1ecd606edcf20ebd0f7107fcfa6f075ca585e18d9b7208a378681cc64c287c27e3a8d4cb4bd3950e00ac43fac9ee040676971214d4ea8ce69ad601b2c9c6130de443ccf70ab12c5588c6df043fcccdac5a6230df6e32fd18ce393bbf5ac22a228ebae8da4414be67a9f8dc0e03c54ec9ae090070330dfa292c3bdaa9cc3395aa4466b0f2f424a8c7b4498f88e5e36d483eccc004e9
#TRUST-RSA-SHA256 8f30047883c60b8241c4247044beec4af5ff825b36989c75abd8d8919704a39d9fdfd6daf16da1e5858f442732ac8787a5af711e33c440d3a6ebe204927d330198608b03d7e9304d5c69e61ddccc6529189d56af858e30a5d70a61f01e128b54c643ef7b6f7720a8370b465d89894780a1aa286fed0e004b5e1f52f96b658c0d1994990b67790332705e9e5196f1445a085352525b8053701a9ec06f53344d5bfb354c68ac6ebaaa99d6fcff7233f9d097e8413335e74dcc6b5422c6d5eb6afdd519e33d7ee08bc48d202ef583ab11327d219330846ce1f308417209f669c32311dc558edfa95dd27d3ad7282237e54cbad5152fe14b80801c5b0eaa3d7d51b4f48863959b73f647561b28e5ad01f2acceb703623baa7b31a93171d47a07f67d13664cd4e128793df2cf5277757b941232ad41f9580475441a20f1e8291bb1b12cf4b962c30c12a0f180979a59e1172a150226f32174629bcd49d7bd2b2f061ae28a60c5bb4b7313ec1d276818a8d22613fbc424d263a238ced7934c953a85f5e2944a4cf48cc847b22890b5a4f8a51594e7dfdea08fa30ab9c4f7fa45a77f117cb93468f43fc655aa474531c840442cab2dd77049f1dabb1e854d5b9424f29f5b280cc3ce3b689adaa4ab4bb222242b5297aa6916e8a2fc48b604e2a865b4d7374e65376708f2c09d9eac08bdd577ac206588b42f11e8d992d4a5c49b42c04f
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58291);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_name(english:"Evernote Installed (Mac OS X)");
  script_summary(english:"Reads version from Info.plist");

  script_set_attribute(attribute:"synopsis", value:"A cloud-based note taking application is installed on the remote host.");
  script_set_attribute(attribute:"description", value:
"Evernote is installed on this host. It is a cloud-based suite of
software for note taking and archiving.");
  script_set_attribute(attribute:"see_also", value:"http://www.evernote.com/evernote/");
  script_set_attribute(attribute:"solution", value:
"Make sure that use of this program agrees with your organization's
acceptable use and security policies.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:evernote:evernote");
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


include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");
include("audit.inc");
include("install_func.inc");

app = "Evernote";

enable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");

os = get_kb_item("Host/MacOSX/Version");
if (!os) exit(0, "The host does not appear to be running Mac OS X.");


kb_base = "MacOSX/Evernote";


path = '/Applications/Evernote.app';
plist = path + '/Contents/Info.plist';
cmd =  'plutil -convert xml1 -o - \'' + plist + '\' 2>/dev/null | ' +
  'grep -A 1 CFBundleShortVersionString | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
version = exec_cmd(cmd:cmd);
if (!strlen(version)) exit(0, "Evernote does not appear to be installed.");
set_kb_item(name:kb_base+"/Installed", value:TRUE);
set_kb_item(name:kb_base+"/Path", value:path);

if (version !~ "^[0-9]") exit(1, "The Evernote version does not look valid (" + version + ").");
set_kb_item(name:kb_base+"/Version", value:version);

register_install(
  vendor:"Evernote",
  product:"Evernote",
  app_name:app,
  path:path,
  version:version,
  cpe:"cpe:/a:evernote:evernote"
);

report_installs(app_name:app);

