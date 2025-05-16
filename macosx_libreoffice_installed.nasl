#TRUSTED 42025b39d137213ea23697c00f37d109106a4da638e7ccc93517f0ad79f92ab95a10b8ccd95fca7e1540eda2daa29fff00cf75845358c2501fb59a348355022dc56196d6ea9649530bcd43ba9ac66c729643c0d8cf4da8a68d9aff8e65d1fa28df9622a8bffb62d02b281705b92ef361155f8bbe9e853d12c29ecc42f76e23784263aa306f29eab05ef375fa5cef90cec8d18f0705364ef0ed5d96bc63c4e407bcae4b0ffd7e7e7ec77f8906a6b498bf8ba2df3b7fee5ddb4b7c93ff9fae74c25883e6aa8155f56acc3fd56d376d6b31026e6e7b9b868fc883fbb6ab5bb7c42dcb8c4a917b092ee550d1a0f7de240b5e9957cd3d747b4d6d8ce7eddcbe5a0b46da155096b30abe0c600ed42f0ba287da9bf6fec109a30ec06deae3f7d98d61183808734d2c92c03004e282bd415a0971ac9b3a8103e8320663e9f26fab832f2e1a4ff47759593f13593267daa9b23ad943b283af08f82037ff479ff8eeb96e405969f0e06b34fc6df3ae28b18a1813863d44a481251493d6fb5c6dd0df8e9882768d7f86fc321aecc82a7c32ca5e023f45b77a7faac60e79724d93c82e76f94cb49791bf7fdcfe2dbe53328695498a49359b35ec00221ac9b894131dc55fa6f78665f775e999d4452d59e46d68fe9e5c659db54bb5f0f9eda6c8d2ea25ec6e9faa53c3c8f716c4fa0ac5779ba28da11e8990db057d1cf62bd2f752bba532ac1d
#TRUST-RSA-SHA256 2d45e942f46a8aed6366790ba43d82cb8d02064c9accab21cf898ad451e4b4184abb2cb3668101ca60a25a14f0b192eb2b2ffd47f44431bc9e7e8aeedc8611838298aede5c468988974d0d1c6738fbb6e49a8e47d526f67b443676d8bddfb447b8d7abb1aec67e8ab8b8ea62e7d8ae785f673a2af15788c7d92f58a7f81e77fb486d340d751dd7e43068f8a6c2aaa0daba99f3267d34ca6817cc6c34df2d6664a18c85a7b59c27eff7a83e12a6553bf8a8e910959e0b2cfaaef327902cb125be4218d6b32b40a788da3b0c1bca5121b002539e583b9f8f223c89c344cb5b991aa586abdb528beee7bd8e05f6e79208e1be974ab71872374977c10eb9ce0498a25be70641d7178b9a5b9e24265129188c3c68bf09f009b5ec43a792c6a99a2e283b27f7989b19c5fb97f6bacde15f91abef407221bf1f09910cb24e95bd047e37f18ef4ffc8951d832a53cd68dafb897f62e1de0d7d0fdf3cef7d3eaa8ca391ed28b79aabc8d22e342b9872e92046bf60fb90455a09144fa2baff5e1d2e857ef760743572e7393f81b4089f1b7ba8cc2025daf9433f97e2c6950467f6d95559ea8d64fece6475e184ae602ef7e167dc615ffb58e9d732e9a1eb78d99c8ff206a381d90a5e596b8257fae7e5b5e7427a0625cfc6b116232718d2502020175b187a3553dd0e4a15a9ac28d1499db57d5f303f414fa699226b882b712d86f26e9490
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55575);
  script_version("1.26");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_xref(name:"IAVT", value:"0001-T-0643");

  script_name(english:"LibreOffice Detection (Mac OS X)");
  script_summary(english:"Gets LibreOffice version from Info.plist");

  script_set_attribute(attribute:"synopsis", value:"The remote Mac OS X host contains an alternative office suite.");
  script_set_attribute(attribute:"description", value:
"LibreOffice is installed on the remote Mac OS X host.

LibreOffice is a free software office suite developed as a fork of
OpenOffice.org.");
  script_set_attribute(attribute:"see_also", value:"http://www.libreoffice.org/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:libreoffice:libreoffice");
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

app = "LibreOffice";

enable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");

os = get_kb_item("Host/MacOSX/Version");
if (!os) exit(0, "The host does not appear to be running Mac OS X.");


kb_base = "MacOSX/LibreOffice";


path = '/Applications/LibreOffice.app';
plist = path + '/Contents/Info.plist';
cmd =  'plutil -convert xml1 -o - \'' + plist + '\' 2>/dev/null | ' +
  'grep -A 1 CFBundleGetInfoString | ' +
  'tail -n 1 | ' +
  'sed \'s/[^0-9.]*\\([0-9.]*\\).*/\\1/g\'';
version = exec_cmd(cmd:cmd);

if (!strlen(version)) exit(0, "LibreOffice does not appear to be installed." + version);

set_kb_item(name:kb_base+"/Installed", value:TRUE);
set_kb_item(name:kb_base+"/Path", value:path);

if (version !~ "^[0-9]") exit(1, "The LibreOffice version does not look valid (" + version + ").");
set_kb_item(name:kb_base+"/Version", value:version);

register_install(
  app_name:app,
  vendor : 'LibreOffice',
  product : 'LibreOffice',
  path:path,
  version:version,
  cpe:"cpe:/a:libreoffice:libreoffice");

report_installs(app_name:app);

