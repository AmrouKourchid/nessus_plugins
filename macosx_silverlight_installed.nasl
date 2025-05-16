#TRUSTED 38d62cd37a63c2e762f1ba6aa7c5deb6f735b16c78674549bf38fe795b0f784e18d7f0d1b9c63e126cb486510ef06fdca904455a3aa150990c08467f2371fec3dc60087a418b12f034195798f6ed2a3e5aa10aa8179e7680ab42eb138941d4916ba09e2ab97f6ebb5a7d66d5ddbd11bf73bd6bc1195c965bf8a6a668474426c13df33122c9a37b2d8727beccf243638e38dfe95b2c910f1b0b6a28b2eb4a18f869429d245e7904d4e2bf8b617962763db2c33b66aff3c698a3cc0f914b411b29e11323acfe1f749039de2ab77eb9960a22c49124a93dc69fd9fa095d139f50f3d0e61a7b92a4c6415c0bc9c585b93844e43428ed1d2b8f1698f310f4dcada17d7b62a5446378bd66156c87eba5aec00240ecce0e21051aab88f7b507444970f81c4781d18d5ae585b9e0d74243316df88730c5ba11a45fd6018f7120da792fffc70cc4f8ff96d1ec73499bd1ca02d8166feece049aee1ea3734ebd4ffb73b7f3b8ad229068d5be5b359e7ea57fd7752ac409fe52bc01ae9872f9ab5971e4fb992af766afcc29b996cb52875d330ef4da4459a60dc07b02ea932476b98dc39e092c2b2e12f600f446bedc5517d20caf4557336496993922b09b48b80e75fc6bca658a1900461f904d2ea4583decea395e8b7ca81446147c36b40029d2bb2e166ccb39bc6965028e534e86cba12cfb6ed28007a274faaf30af52ba42b661bcef58
#TRUST-RSA-SHA256 605e232b6def9507833ebf850cf56a57d1bdf9a25b6b2775a18b4f56f96af680402e0a92235d890b4266f5524a34e93fc6923690ef88c7c0f73102733173093d8f189f8d70cf1a5ead63137c27800fee10fe1c02bea26275c09adb848d46852da2eb446cd8ff6f334cce8dfe5626781d4b04524c4726b0eb110ddfaa9a3aeac25273e079f61960e1d6c9237866046ab97f5befbfed24f03f828e96a1d8bd7080f67b1f59e190689147290e3c766ef37f1c6e256f7dabaa810a352c161d5b855c73766d6f6518110c4e5dcd9e682f4218443d5d9cb49bf9ba18309b6977b1efa3ff6aa6a28db375ca77eefc8f7c14e18d26c4ed604c52697c3fd537f87ea9a58164d2c7d99564a9d13a1505306b751380e858fff77b67c2d29a1b75bc3721846913d4ee5b09300a2f7eb0161cb0fc50ab9317ea9a2fde1acbf6f210335374824cd7ab61eb0c4ee68f2c21e45068fe5689c540cd120f5e2c2238cecc22e123e2f7d310ba084e32e5c16c0a9b10fe18dd11d180bc775c96315bae40e2107cb765f79901acd5ad0ac6973b89c966775598b8aa12981b5e25322ff3955a4d9eed91e5215ce7d74d0618b895dd8bf439607ed11c51689257cdfb0f444ec30fe8b3d8882305f04f25a296599125a275dedff1a0f8cdcb29f4a15e7eab347eb7f9114dbd2fd7c16fe550b568934b542ac01fa665a870b3ffe50b524a5f7d8d945f369e81
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58091);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_name(english:"Microsoft Silverlight Installed (Mac OS X)");
  script_summary(english:"Reads version from Info.plist");

  script_set_attribute(attribute:"synopsis", value:"The remote host has Microsoft Silverlight installed.");
  script_set_attribute(attribute:"description", value:
"A version of Microsoft Silverlight is installed on this host.

Microsoft Silverlight is a web application framework that provides
functionalities similar to those in Adobe Flash, integrating
multimedia, graphics, animations and interactivity into a single
runtime environment.");
  script_set_attribute(attribute:"see_also", value:"http://silverlight.net/");
  script_set_attribute(
    attribute:"see_also",
    value:"https://en.wikipedia.org/wiki/Silverlight"
  );
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:silverlight");
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

app = "Microsoft Silverlight";

enable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");

os = get_kb_item("Host/MacOSX/Version");
if (!os) exit(0, "The host does not appear to be running Mac OS X.");


kb_base = "MacOSX/Silverlight";


path = '/Library/Internet Plug-Ins/Silverlight.plugin';
plist = path + '/Contents/Info.plist';
cmd =  'plutil -convert xml1 -o - \'' + plist + '\' 2>/dev/null | ' +
  'grep -A 1 CFBundleShortVersionString | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
version = exec_cmd(cmd:cmd);
if (!strlen(version)) exit(0, "Silverlight does not appear to be installed.");
set_kb_item(name:kb_base+"/Installed", value:TRUE);
set_kb_item(name:kb_base+"/Path", value:path);

if (version !~ "^[0-9]") exit(1, "The Silverlight version does not look valid (" + version + ").");
set_kb_item(name:kb_base+"/Version", value:version);

register_install(
  app_name:app,
  vendor : 'Microsoft',
  product : 'Silverlight',
  path:path,
  version:version,
  cpe:"cpe:/a:microsoft:silverlight");

report_installs(app_name:app);

