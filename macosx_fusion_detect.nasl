#TRUSTED 900c7b02c81ee80dedc1e1707ab2ca8247f7d67efef74681c38b99281778893271600e747c7bca3c7e38e266df1deb4da52ae55cf94256b632725c31b65e490319fce6decca5925dfcc389eae60f5c445df572b8ae0bf96ccab0e2ecd18b492d93251720956a74747ba4555ad290b09810cd2cd1792699ce0eb0afed46e426313e6b1b9216033b61d43bfe7a027a926f4636a80d020e4bd876fad30eb951be9cfa3fe349cd4e16c4c9d352714609a5f369cf652e26c97cd7ce29385f3a472a6072c9f064b2d25ffd29fdbf2810d13ccb28ec99bdffc16779814931135580ccc66a58361d4ea02387ec770ad5c894fef1f63ca458beadf56d415693de8d14b4ecd06d5fcbe300251668479aaefa5afbfb2b39bd6393352782db09d6fb8aba3c0e23b23bc3650d94043674ae92726b133287d666a4a5044591b92c1d933dc12783f239388bd8517e8ef256b0df7973a9127229e88b857ddd3518000f99778b59aba804b4df7884f0e47231b069232a8af8c35cb176db62418d4f94c51f2331284451f680bf3c14a8ea4368bf4048d89bc626ffc047f098a3459df9c46d5ca8c6576eec8be504e51562270c1bf2c3224565986ae1343b92d3e418b1ce16c24f4cd142bf2e7421cb2fa058fb8a7e0f502630b5985e1be7b569686e2cc65a35927047142de28d9baac01f8d13cb735f914e7642167b88cbb189576e047c7226cb0163
#TRUST-RSA-SHA256 9c0fab7295d84bb19467ef91ca2cde91e9afd3a8324e4fbe4aac3495ee27c0d69ed408535fad3132c69201968bec7cb7c013e7b05cdb059bd409603154bd19028a853d4014330b441b90d3813898cd3fcc53bfba3aa817b0ff49ffbcaa89619e5bddfdf1ca8b67994f4bd4ae709c0656981d503762d48e170560edb336d903339a72d232f68602d6cf0cf1c99466cc6a2fa596e7d5ef800e8dc8b1b1064eb21ea5aaad61b32964d9c293f4a35e255a9e0655bb5d1955d0a4fc493b35d74994be71216aa9fd92e59db57de20d285da63bb935fd104f32b5a5bd39f0cdd5113a589c258d745d3b1d736eb066fc6d8a0abd1fbea6bac825ce0c3338cdd5afd696174d50830ab3fee67e9d51c336018bd3118eb226283f6308b57fffaba9fc132f75ee40f552b651ed5a385ddfbbe95d244d9c54d53e25d69d621c4c7adc30469b843929054c9c8209f287cc2bb11b9db9d6000a8978a818bb46fde483a8e0fbfdac3e7c403a9718e6fa0bb3e452aa40b533d9f043f9a0a340b399aafe660d0c84016eb9c9d17bb59173301cf36e6cf8609bf00de8cb4de2c4e0a6e924a44c9cbafdf59471195f739221368a6c3a542bddfbaae056563b7dcb455a585e7b6266e76aec14fc491a5af67e132cc2fa1ee5310887c7311b12542cd76c98e71946df9882e58bbe565f9ea4e67470d784d622d09b4f4e068c3f88eac9bb170ef83c53aa1d
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50828);
  script_version("1.26");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_xref(name:"IAVT", value:"0001-T-0735");

  script_name(english:"VMware Fusion Version Detection (Mac OS X)");
  script_summary(english:"Checks the version of VMware Fusion");

  script_set_attribute(attribute:"synopsis", value:"The remote Mac OS X host has a copy of VMware Fusion installed.");
  script_set_attribute(attribute:"description", value:
"The remote host is running VMware Fusion, a popular desktop
virtualization software.");
  script_set_attribute(attribute:"solution", value:
"Make sure use of this program agrees with your organization's
acceptable use and security policies.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:fusion");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");
  script_copyright(english:"This script is Copyright (C) 2010-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/MacOSX/Version");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("macosx_func.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("install_func.inc");


enable_ssh_wrappers();

appname = "VMware Fusion";
kb_base = "MacOSX/Fusion/";

if (!get_kb_item("Host/local_checks_enabled"))
  audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

path = "/Applications/VMware Fusion.app";
plist = path + "/Contents/Info.plist";
cmd =  'cat \'' + plist + '\' | ' +
  'grep -A 1 CFBundleShortVersionString | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
version = exec_cmd(cmd:cmd);
if (!strlen(version)) audit(AUDIT_NOT_INST, appname);

if (version !~ "^[0-9]") exit(1, "The " + appname + " version does not look valid (" + version + ").");

set_kb_item(name:kb_base+"Installed", value:TRUE);
set_kb_item(name:kb_base+"Path", value:path);
set_kb_item(name:kb_base+"Version", value:version);

register_install(
  app_name:appname,
  vendor : 'VMware',
  product : 'Fusion',
  path:path,
  version:version,
  cpe:"cpe:/a:vmware:fusion");

report_installs(app_name:appname);

