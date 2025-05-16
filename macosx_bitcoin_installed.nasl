#TRUSTED 14ad9a6dca6d7740238faef3defc1490fa84069660afa380534f43571ad70fdc87b8a0331413948f01e3300b4205d74f6a6068923574e0076fd182f490aeebe0256f5b1bc1c0a63df9100a99298373ff40b077f142856c55bdd3c67b46849a0f06ca08dc6858161ffabc276b7bf7205b392d71558acd1c8463047a2ffafad1c7dca48f71ed76ec8c0d19e1b4e3fbdf81d8ea42bb74ecdf48c7d1fbe568dcd2fc7e35f748cb2708d50fd0b6db420a3a373ba7da63604b29bfa50612222b4d34c1aa997dc0d98ebe33a95e4d302509e3d423727d494b75818639ab926923c4507215193431367994caf5ffb42fe45879b4aed04f860a0f0cbeddf9ed0de32fdb3c7cd2dbc63c2085d2521b20302c48aac7b9cccd2c38645635dc6df297c20a1c2b78423cb2861e486d5e9ceb52fe0fbda3b36d85c74de2cbb98f82e87b25a42de529ce67af317c4d37c8d3bf39fa6591dd5b1dee4cc952fa9fb1059b8815fca599ce4ba6d6eb18b44d2f2f5735099fb665c59978e38d20480b49aae108f5abbdf9b25f6e59e00ec963339f8152d941e32f6aa08266efbe9da4c6778ca07955993a3491415dc0e02e1cfb7c24ee0b81e974a3b1ad9aa3bef434b87b10293b0c9f7758b23882255d5856038328eebcee337138fa6d49b3500c7a26139404e7eba079f20ff906152332744e10f8d25e8b8be3f804e87bc6f98e65390fd1f975038b3d
#TRUST-RSA-SHA256 1af084bd9be1569b13cdc8614533789f17a9d8193b0f6eda1c9365c6652a3d509eb409ec86e28e0658b44c13439901959f96b1fdce4f6c7ec522e0d04d8817b962a4c4e0d89b1669bbe372b490b02edeea286a6bd1f27d471123c2ad0a860553c3b1a7a3632a937b0868ec94d8ca41293d1bcb1559e657db7036a2dad3341fc08de5c27856403736783e2f2a2399be57b97c1b7a6dacc29adea6aec926b801ee96c17241147d191347fc3026bbfc7a9c78541f128ed59f1425f785ff592153a5153d4ac05ca9af2f14bd585220213979ad294f3a2c98597528fb9f9ff30c849ffe61ebb011557fd3e1ffbbed6a699157f850c67778bc1de03a55111d8beb98e5e1712acff8a474fcb9051bc62753cf995f7ef5ccdbccc82dd6af62918a572438b240059d90928fca283c2b15b8dc6489a1e7df46e1a66c6475486a1aca367557cf7d06718100e3236435d72950744d4de0bc03ac5a1a0720f1fffb0c19c68136c615a1103d8efa6a359a3364c840f481e84a4315e412fa72d7c56230cc85fb311fc55bb27e315c1f0ccc68fa6d5ebbd9bd2150418273a15f828bb10fcc61b21d5fc6571f1827d53bf9dcb3825ef31d321723f15aef5c5a1ba1e163f4cb9f4913e86bfcb597a5951a4204499f44e2506dbec5beb2422686ec8b31434f371fc0599104a3158785003ac3d108764b640ad96e23aff77f31248114b85c977ca29b28
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56196);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_name(english:"Bitcoin Installed (Mac OS X)");
  script_summary(english:"Gets Bitcoin version from Info.plist");

  script_set_attribute(attribute:"synopsis", value:"The remote Mac OS X host contains a digital currency application.");
  script_set_attribute(attribute:"description", value:
"Bitcoin is installed on the remote Mac OS X host. It is an open
source, peer-to-peer digital currency.");
  script_set_attribute(attribute:"see_also", value:"http://www.bitcoin.org/");
  script_set_attribute(attribute:"solution", value:
"Make sure that use of this program agrees with your organization's
acceptable use and security policies.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:bitcoincore:bitcoin_core");
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


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");
include("install_func.inc");

app = "Bitcoin";

enable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");

os = get_kb_item("Host/MacOSX/Version");
if (!os) exit(0, "The host does not appear to be running Mac OS X.");


kb_base = "MacOSX/Bitcoin";


# Identify possible installs.
#
# - look under "/Applications".
paths = make_list("/Applications/Bitcoin.app");

# - look for running processes.
cmd = 'ps -o command -ax';
ps = exec_cmd(cmd:cmd);

if (strlen(ps))
{
  foreach line (split(ps, keep:FALSE))
  {
    match = eregmatch(pattern:"^([^ ]+/Bitcoin\.app)/Contents/MacOS/bitcoin", string:line);
    if (match)
    {
      path = match[1];
      # nb: ignore instances under "/Applications".
      if ("/Applications/Bitcoin.app" >!< path) paths = make_list(paths, path);
    }
  }
}


# And now the actual installs.
install_count = 0;

foreach path (paths)
{
  plist = path + '/Contents/Info.plist';
  cmd = 'plutil -convert xml1 -o - \'' + plist + '\' | ' +
    'grep -A 1 CFBundleShortVersionString | ' +
    'tail -n 1 | ' +
    'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
  version = exec_cmd(cmd:cmd);

  if (strlen(version))
  {
    if (version !~ "^[0-9]") exit(1, "The Bitcoin version under '"+path+"' does not look valid (" + version + ").");

    set_kb_item(name:kb_base+"/"+path, value:version);

    register_install(
      app_name:app,
      vendor : 'Bitcoincore',
      product : 'Bitcoin Core',
      path:path,
      version:version,
      cpe:"cpe:/a:bitcoincore:bitcoin_core"
    );

    install_count += 1;
  }
}

if (!install_count) exit(0, "Bitcoin is not installed or running.");


# Report findings.
set_kb_item(name:kb_base+"/Installed", value:TRUE);
report_installs(app_name:app);

