#TRUSTED 4c0675bf6d176aefd7b952c4267bff0e94682ea4284bfef3ae2064c35e16637a55c5d5054a241f72bb422f679d27fbded33511a464e764a45da2556460db7a801991836c5e214fc31b0d994d4f58eb58e0b83280549a201cf93bd6eda227e77d70011030defd0da3f4af213b3bfedd3be5eb392c575f78d74aa4b9e60f2bede5fb1f8f67c2b23cd30425fadecf456bed46b12f753f6a950009f85d4947ad75ef725e266d8fb54434313c85b0a5e418ddf6967ed6a14a2606448a6d61bc3dc73f80cd79b78697a2e9d9fda9649e4b2f52a773e7cca62858eede817fa13fb4f3c712d31d3f223faa98fef799c661834c25001a3f2a9b45ff17eafb97728e3696d94ae0f6c8e03e6046725892e28beea78ed8d5a831da55051581ddb2e71a329233a1194464f30cc6db3f27116c5f5dceb604fc7fbffe7a8d9f906f8ecbff18ebc18b1e19c4b0793aefd0266194593549c2cec43e992f5b8f64239d21d127d2bcb70f3e978b0ca8991652b6d194d8f949d3331e94d268e6ca8a716b00fdea8a92fb4252be47fbc447cfd5c81fdb3636eeb5c679bdfe77318aace62cb8f53e6de6eb16458ad0d82d8c999af1c750e413eff02358cd3bb3115c10f8e10244d53649eeac2f7896559ead68f90872123c7b3a7feb3ece316dcae5d04065f8faf275b7acfe1d136f32a8845c0a32a8c882d7dc636bd4a80429bc268e18b98aadefd9cfff
#TRUST-RSA-SHA256 51d60f69752d44ac36e7d03648f16a2fdb27e0c3f24f69d2e7918f2d0f1dfe3f9e19c6c60afc947c05975531d0d5e79960deeb88063ace4dd77d29a36e16ce0f1b7753d7379f474eff76e37ced209f2645eaa3d6b9400ba9a25caa3016a28d11290d07d10537a019aa07a433a16decd92ebaeff1d80ee6bb16da4c55415094b2b72beb6c307427580463f71dff94e779af2945cca3721556ce2dac0840e8c6a2798cb263dd487e99e6827a5a8e14b957bc4dd68b96c06e26f3aea9b5d75b2c95459c549d64ba5ca4fac45d5e0e98fcb00e5fabdbb7288aee7116972c182426c313586cef0e97ce8d3a285032397785718153d1740fb6913b07dea1bec6d3242750c8988d14b1fbad3eb3b28f5f76bd37f3f7a3f20ce0690ee51000f242e690633af6f0502123e24751a49d554321061c2f30d1c9bafb0c6bea89fbab2b004d9d298b11c0fc8aa9294af6701d5506c1d38f7092f28b99a4f5bacaea618c724750ed5dbbb956682f294a82b4ab089e663f83833cc9aa0308a41bd9e44a09fadb42f04cd99b48caccd55c3bb28af37ee98815f9267b28f4d9dbe9d7680cb17d4c98afb158edf9b7fc28207db7aaa20d420250ccb66f010f07ccaec294dc152b7885606fdb5fc0cc14ae86eaa66b7d1c19bbb7241de9d190e71dc8e5eb5ba5850f1ede72a5aae5b8ef59d2e236bedafc0f681362beba8b1dc276cafd58f305e13a9d
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59822);
  script_version("1.26");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/15");

  script_xref(name:"IAVT", value:"0001-T-0915");

  script_name(english:"MacOSX Cisco AnyConnect Secure Mobility Client Detection");
  script_summary(english:"Checks if the AnyConnect client is installed");

  script_set_attribute(attribute:"synopsis", value:"There is a VPN client installed on the remote host.");
  script_set_attribute(attribute:"description", value:
"Cisco AnyConnect Secure Mobility Client (formerly known as Cisco
AnyConnect VPN Client) is installed on the remote host. This software
can be used for secure connectivity.");
  script_set_attribute(attribute:"see_also", value:"http://www.cisco.com/en/US/products/ps10884/index.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:anyconnect_secure_mobility_client");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version");

  exit(0);
}


include("ssh_func.inc");
include("macosx_func.inc");
include("install_func.inc");

enable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");

var os = get_kb_item("Host/MacOSX/Version");
if (!os) exit(0, "The host does not appear to be running Mac OS X.");

var kb_base = "MacOSX/Cisco_AnyConnect";
var appname = "Cisco AnyConnect Secure Mobility Client";

var path, plist, plist_field, cmd, version;

# 5.x check
path  = '/Applications/Cisco/Cisco Secure Client.app';
plist = '/Applications/Cisco/Uninstall Cisco Secure Client.app/Contents/Info.plist';

# Tested on 5.0.05040 and 5.1.2.42
plist_field = 'CFBundleShortVersionString';
cmd = 'if [ `grep ' + plist_field + ' "' + path + '/Contents/Info.plist" 2>/dev/null` ] ; ' +
      'then ' +
        'plutil -convert xml1 -o - \''+plist+'\' | ' +
        'grep -A 1 ' + plist_field + ' | ' +
        'tail -n 1 | ' +
        'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\' ; ' +
      'fi';
version = exec_cmd(cmd:cmd);

# 3.x check
# Check that the app is really installed
# and grab a detailed version from its
# uninstall app.
if (isnull(version))
{
  path  = '/Applications/Cisco/Cisco AnyConnect Secure Mobility Client.app';
  plist = '/Applications/Cisco/Uninstall AnyConnect.app/Contents/Info.plist';

  # this works for 3.x >= 3.1.06073
  plist_field = 'CFBundleShortVersionString';
  cmd = 'if [ `grep ' + plist_field + ' "' + path + '/Contents/Info.plist" 2>/dev/null` ] ; ' +
        'then ' +
          'plutil -convert xml1 -o - \''+plist+'\' | ' +
          'grep -A 1 ' + plist_field + ' | ' +
          'tail -n 1 | ' +
          'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\' ; ' +
        'fi';
  version = exec_cmd(cmd:cmd);
}

# 3.x < 3.1.06073 uses a slightly different plist field
if (isnull(version))
{
  plist_field = 'CFBundleVersion';
  cmd = 'if [ `grep ' + plist_field + ' "' + path + '/Contents/Info.plist" 2>/dev/null` ] ; ' +
      'then ' +
        'plutil -convert xml1 -o - \''+plist+'\' | ' +
        'grep -A 1 ' + plist_field + ' | ' +
        'tail -n 1 | ' +
        'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\' ; ' +
      'fi';
  version = exec_cmd(cmd:cmd);
}

# detect 2.x installs
if(isnull(version))
{
  path = '/Applications/Cisco/Cisco AnyConnect VPN Client.app';
  var bin_path = '/opt/cisco/vpn/bin/';
  cmd = bin_path + 'vpn -v | grep "(version" | sed \'s/.*(version \\(.*\\)).*/\\1/g\'';
  version = exec_cmd(cmd:cmd);
}

# And exit if all attempts have failed
if (!strlen(version))
  audit(AUDIT_NOT_INST, appname);

set_kb_item(name:kb_base+"/Installed", value:TRUE);
set_kb_item(name:kb_base+"/Path", value:path);

if (version !~ "^[0-9]") exit(1, "The " + appname + " version does not look valid (" + version + ").");
set_kb_item(name:kb_base+"/Version", value:version);

register_install(
  app_name:appname,
  vendor : 'Cisco',
  product : 'AnyConnect Secure Mobility Client',
  path:path,
  version:version,
  cpe:"cpe:/a:cisco:anyconnect_secure_mobility_client");

report_installs(app_name:appname);

