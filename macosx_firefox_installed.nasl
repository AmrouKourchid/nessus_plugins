#TRUSTED a66e5b9f3ff4270c214052c9faffbb91de6eb383f92a7c2e3c946b783240ffceba684ed6b8ee9376b193601f02f5e7935f4061940884772c04751aed9e04144daf2a251b1d4f5e00b7e08144268ce19227d21be9eff1c355adebe072019d263983f87de74a283c7c120819f5b12d3929d93f26e47951edfea73e668e4b7c32228a43e3c161dd623a038535fa49c18b19ad2a9731a9ef7dc34a32746979be8043fc35eb37cf4923123c305189bcef4f1d6734a060fa113957126d4e17d79a474943511b2a8a9376df948a3085bb943f0e15fd0471a732dc7ff0f8cb0abefa472454b6eb73da651c187c5fb5779dd1501d0b80f59101d237d3349248fdd1bd058104fbba27d14a1649008849b1c50545f7d0c61236d91af3ca65e48a713e2451b7b4e56fa1d7f7fe03ea1e3ee39e75d6166c5bc837c8e9a065dbac12cc2ce46326ba803046f544abacb3b702488232e13ed3f2178108ab5efde243aaff522b24acb8317ee38a0de4f4c798956014da4c41ee3ccdf092be8b0bcf1195b697cf55d3063e42441070b696bac9ce9b48d8ce94329144a2a621e1ff4877709a45112f62c4657da48143a437b594f634d62041c4f6e18e8b80d8905eaf7dadd5b8312ed64fb92584ca3f49801159bd91004cc3fd49498dc321d82d1fec72be929283ac099e5e33b90d5572d08554429318daf92360f8f83ddffca60d6534f3a0633305ae
#TRUST-RSA-SHA256 204c51fdd07229e4b2565886ee2960f1b29ca124934ca924c7d455afd3f818542dcc8cdf13a6a8b8afdd1f1c1e0675576686c77a6bc310b38092e859deee28b1656dff5a24d1f5afd7b958ddb46c4eb20bd6c58255065f10a3d98f72850a14f5d66479f1ac5ff479373765ce6a6d5130d424393334b1ecf2414710726b093538c1ab2e416fb63df059f2941ac4f3a57eb0652d310153fa6412b6fe7221cd6443ba0f42197a22cc9b03d0e05d134850854d9a1b6e82b1ab26680da79c6dd81e2a2ef42a1c2e4aced27f3078126c62ffa2048199db0180334f07d4886ff2c3647b2443efbd9c67413d15dcfddebd2583421020a0b053cf01b13d168d5bb29e06a60062033aca51141b84acab1117c5bad295b612667267b21c579197b0825ad6d35cbf97ae11be73d66fb8a46e00c4685f2f8344348051fe56b64cca5b1db77d832690e3cca631ee9ceffdd967f9866240f6a748329eb108609de351fa597534a688e77609cc44557a2d3e5885a78753a259635391bf1a98d8a4d2a4dc818891c161a6c6dd74b478b84700b4672cf59b8dd7af44520c3ccd2bb1e1844a5636ff3a212869cd593d38cf1e9113adf8a314f6b6452d9718192414474c7dcea3f835ee8f1819580ef0e19eb624923a0262db8413947f2b8c3267d4cdc3d630fcb1272ff7881a702a74a09b5c1e2f52ea56471a20630fad3cda3029119c0a45f0cd6230
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55417);
  script_version("1.41");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/16");

  script_xref(name:"IAVT", value:"0001-T-0510");

  script_name(english:"Firefox Installed (Mac OS X)");
  script_summary(english:"Gets the Firefox version from Info.plist.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains a web browser.");
  script_set_attribute(attribute:"description", value:
"Mozilla Firefox is installed on the remote Mac OS X host.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/firefox/new/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version");

  exit(0);
}

include("ssh_func.inc");
include("macosx_func.inc");
include("install_func.inc");

enable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/MacOSX/Version")) audit(AUDIT_OS_NOT, "macOS / Mac OS X");

var app = "Firefox";
var kb_base = "MacOSX/Firefox";
var esr_ui = '';
var is_esr = 0;
var key_path, esr_cmd, sw_edition;

var path = '/Applications/Firefox.app';
var plist = path + '/Contents/Info.plist';
var cmd =  'plutil -convert xml1 -o - \'' + plist + '\' | ' +
  'grep -A 1 CFBundleShortVersionString | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';

## grab version
var fox_ver = exec_cmd(cmd:cmd);
if (empty_or_null(fox_ver) || !int(fox_ver)) audit(AUDIT_NOT_INST, app);

var version = pregmatch(pattern:"([0-9.]+)", string:fox_ver);
if (empty_or_null(version[1]))
  audit(AUDIT_VER_FAIL, app);
else
  version = version[1];

## Check for ESR
# is_esr will be any of :
# 0 - not ESR, no matching lines
# > 0 - ESR, more than zero matching lines
# not an integer - ERROR of some sort
var esr_cmd_array = {
  '/Contents/Resources/application.ini ':'grep -caie "^SourceRepository=.*-esr" ',
  '/Contents/MacOS/XUL ':'grep -caie "esr.releasechannel\\|/builds/slave/\\(rel-\\)\\?m-esr[0-9]\\+-" ',
  '/Contents/Resources/update-settings.ini ':'grep -caie "ACCEPTED_MAR_CHANNEL_IDS=firefox-mozilla-esr" '
};

var esr_major_versions_pattern = "^(10\.|17\.|24\.|31\.|38\.|45\.|52\.|60\.|68\.|78\.|91\.|102\.|115\.|128\.|140\.)";
if (version =~ esr_major_versions_pattern)
{
  foreach key_path (keys(esr_cmd_array))
  {
    esr_cmd = esr_cmd_array[key_path] + path + key_path;

    is_esr = exec_cmd(cmd:esr_cmd);

    if (!isnull(is_esr) && int(is_esr) && is_esr > 0)
    {
      set_kb_item(name:kb_base+"/is_esr", value:TRUE);
      esr_ui = ' ESR';
      sw_edition = 'ESR';
    }
  }
}

set_kb_item(name:kb_base+"/Installed", value:TRUE);
set_kb_item(name:kb_base+"/Version", value:version);
set_kb_item(name:kb_base+"/Path", value:path);

register_install(
  app_name:app + esr_ui,
  vendor : 'Mozilla',
  product : 'Firefox',
  sw_edition : sw_edition,
  path:path,
  display_version:version + esr_ui,
  version:version,
  cpe:"cpe:/a:mozilla:firefox");

report_installs(app_name:app + esr_ui);

