#TRUSTED 89a9dd082adc572ca36754439a3439c6e35516098b5cea721d4bc2524df6eb2b14d8503fcf8881684713b2436146fae76aeaf365cff51dfabbf4f6b3a2f3ac2f70203319b984a4ea6a9d9043e0f67ba10541883aa779ea9fb784686e35037ad42346aecceaeb7f5c7ce6d8250caf7c0d5e73aa7eb6143b6ee30a0b9e1b81d2fca3dfc372b49e8317aa951604cc154183205de66c42b15ca2df04cf3b05c76e5c0175e989b885f0c3b70fda8e1c4871481d452b103b06aaf4f2bf838880d57691ba3e79c834dd187d6751d0a4dc4bf174645e97601129a4f0d95bc181110f6df332b117d9119106d68bc5f589b6d2415a218a681d9f86d337cba9632ea9de5b4dc4f1cf37aff898316792e5c91e9aa585215033fed0e6f1b259d8d4ee4b62d803fb2d95abe95a3fd4da37b750bf014018ec1d50a183da85a93f4300baffa7a5cfe1d42d76d7566c15c03955346a01c25b49806ffb2cae614d47e10ae86c01bf96cc5961c2b40837bb9c39d48df4e842f7b632c15f8a430b2d494242e22383b87f6198795b031be9f277a3ae3a3f01a12360953f7b06f0ee76e4eb54404cad3b4f6efe19415ddbc23c7500494705857f332461c46897a5a25c410329b621c8441d53518eec4a59b63870df394157ac96bd385670ec003d866a80f6d97752d8cb47b2bb6c75035eef98b217788d23b8e349bceb2f83b91a9978e2d5af07ee3ab778
#TRUST-RSA-SHA256 357a88b67bc9b3480e5b76eee3670826df5bdb8c036a57f9f61a33e0954c736caf1360cdc2cf2c5afabba64c2b05585f116c2a66d42ec8b7ea305f9ff76020f27b6db949927571d165bfa5215e837aa8934d78a283b4de0001ab04295d82a7f3ebbe038416624bd34356bf12523a90a7d43a9b9e2fd8811a083d9f3dc7d6af406fa256657242eda465ac8707bc788113e308f453c45d69bdf482aab9296831608ed73cb5671216e45d0ce0c1c5e59388595455802c0f2fb7ca8b9b08fa59090c67244cb21c280d2e5a03f8cdf4812892f616d93ed06beb6afa1cd68766cdd1004357b7092949bdfa45dcaca722c6da7203db25f7b2d30ccd5faf4e186c4487aeb0afce75aafdc203f4124f102b291c376c5b33825b7732237c5cec01163a75042af36b06539c539e7ff33c0f241f68f5585d6287ac090dd29a78e39ec9ce5580dadf5fe7a6701ef2473b685d92894f37102646c24d9c63cd2626901ae4f78a8a1af45ba6d6edf0e739cbdacfab4bde94981f0eec43c7873ae7899abd0b40ecd119d5eb977a7c53fc01cbcec50b1b99a5200ac63191967f7259302edefedf4f2a076d9e3d2d84385836b50772e40142f57319f45320c2c30e7e348988a33550debad1c976fcb6a0b6e24030ab9612656c77408d31301e868a9ac516e9d14bf799c688944fa0379afb7b406ec00b1d9dd4df16c034fac6c4fcaaeae245616310c1
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(59177);
  script_version("1.27");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_name(english:"Adobe Flash Professional for Mac Installed");
  script_summary(english:"Gets Adobe Flash Professional version from Info.plist");

  script_set_attribute(attribute:"synopsis", value:"The remote Mac OS X host contains a multimedia authoring application.");
  script_set_attribute(attribute:"description", value:
"Adobe Flash Professional for Mac, a multimedia authoring application,
is installed on the remote Mac OS X host.");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/products/flash.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:flash");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:flash_cs");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "command_builder_init.nasl");
  script_require_keys("Host/MacOSX/packages");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('ssh_func.inc');
include('telnet_func.inc');
include('hostlevel_funcs.inc');
include('macosx_func.inc');
include("install_func.inc");
include('sh_commands_find.inc');

app = 'Adobe Flash Professional';

enable_ssh_wrappers();

if (!get_kb_item('Host/local_checks_enabled')) exit(0, 'Local checks are not enabled.');
packages = get_kb_item_or_exit('Host/MacOSX/packages');
kb_base = 'MacOSX/Adobe Flash Professional';

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

# Get a list of install directories, given that multiple versions can be installed
err = '';
dirs = sh_commands::find('/Applications', '-xautofs', '-tenb_fstype_exclusions', '-tenb_path_exclusions', '-name', 'Adobe Flash CS*', '-mindepth', '1', '-maxdepth', '1', '-type', 'd');
if (dirs[0] == sh_commands::CMD_OK)
{
  dirs = dirs[1];
}
else if (dirs[0] == sh_commands::CMD_TIMEOUT)
{
  err = 'Find command timed out.';
}
else
{
  err = dirs[1];
}

if (info_t == INFO_SSH) ssh_close_connection();

if (!empty_or_null(err)) exit(1, err);

if (empty_or_null(dirs)) audit(AUDIT_NOT_INST, app);

install_count = 0;
foreach dir (split(dirs, keep:FALSE))
{
  base_dir = (dir - '/Applications') + '.app';

  plist = dir + base_dir + '/Contents/Info.plist';

  cmd =
    'plutil -convert xml1 -o - \'' + plist + '\' 2>/dev/null | ' +
    'grep -A 1 CFBundleShortVersionString | ' +
    'tail -n 1 | ' +
    'sed \'s/.*<string>\\(.*\\)<\\/string>.*/\\1/g\'';
  version = exec_cmd(cmd:cmd);
  if (isnull(version) || version !~ '^[0-9\\.]+') version = 'n/a';

  if (!isnull(version) && version =~ '^[0-9\\.]+')
  {
    set_kb_item(name:kb_base+base_dir+'/Version', value:version);
  }

  register_install(
    vendor:"Adobe",
    product:"Flash",
    app_name:app,
    path:dir,
    version:version,
    cpe:"cpe:/a:adobe:flash");

  install_count += 1;
}

if (install_count)
{
  set_kb_item(name:kb_base + '/Installed', value:TRUE);
  report_installs(app_name:app, port:0);
}
else exit(1, 'Failed to extract the installed version of Adobe Flash Professional.');
