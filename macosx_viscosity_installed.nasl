#TRUSTED 04083b0595f89a5b0f326fae71b10eeca9e5cdda21e560994bf8928a6e8209fbc2ce59029511bd8ebe3bb76ac038f23eece4cbd09ba9feebd0e4a6706b56a189ac1a178cefbed96204b556ce6b17a60ad4f1107dfbadb6d6a5094cd23fa02998b2d6c0bed901566563a508cc2b67b41eebd689cff7d8de3930cade209bfb8254eb1e9f7210e93c4311c8caf28e2fbbbc2921221d71aa451c673c2c472abf3f7a1a95167cc8ba0178063533e77ce573ffc361e14bdf291cc859c5d5cb09eac5dc10e02ef145d88892496939559bb9101378f07b64d1a3e3bfe1a9e4cee45482d482313b4371034029d5b95106a332231af3ae9b80187a631c4a5afdfe1c2f2a06eac2da265ff68b3e1b286843e06d441e08e4fc80dd86f565f0f61bdbc107dca22e51373edb011dcacb4ab694f314985bbf5b73b8ca2168e4636782c6f71df9d21a211be773f769ffaf56f221b3885c27fe9d60a25521047ba6c6859a342ae28fbd5c920dfd713cc830928d072f744b3ff80c8accca235a559e89887d235aeb8090f43b1bd94417bbcfc3bca8a2a8395f6751718bd27adc5faa4d6f90ea804d6bad1ff9c1a303278fe31640c9ce8077cd72ffcbc700532fee41381c16e5af6a4efb987d03baf5c24e8e27af353e38a6e0bf6a37ab229174ccb011857236730dba83413f737f8481be73e3948d658821bfa5eac0027613994b69134937c81e6d50
#TRUST-RSA-SHA256 3eeac78e904cfa7168afe83067bac32ddc1baac9648f893aa8fecf7dc1dd5726f9747740ec4b5917e55e3426e44f4f7060129c91199c6fd999b57dde4d713c400a1ed7f7a22cea76558bde5cbc7578bed7605b6a2f9613584639a9eaf071b7df92eb4c204fb568ab6630281c54a81a98b3e3729b09b543e56343b04bcd040ec7adfbfb3ca31ecc8a5ee78dc7afdfccdfd99a2c31f986dd1bb394c2bb1cf89c4274f193ab98e3abfdbc3ab49382b3ce6cb7fd52a6a4b513b56d7236b864e5e569460e01bedee71fbba895c04565f2a9b6d5c2cc58eb148eb904618ccbb689dd4c908cea0b526d1910d16c51f8039d014d8f4fb2b7c7c42868e2be92a94eee6e33d9ba8447dedb42a5c498cfd6ebc8b741cba914cc9b7d7df66358b5d9cc96644f44cf4ab8601d59300718ce93a1996925c7129888ed0dc47a0d9de04a800e6cf713f4e55813560ec8545f3e4d6b0cae29c4cf38666e91b347c25daabae093b6bea2b5e15bb5b35600654ecd7dfa19df4ac174dedfbb6ed98252b90c679a551fa947840778c522994c08efccd98bc1d3648b88da0de400dd79cd3d82ed20689f55e7cab2b972d682a4c803ef2f2faf18fbf42a4d541f6fa13c1479440f8dfd37cee07b9e4ff7602d336b14bbf8c47298dd725eb61b761986047d6bbfb9d6c73756cf2ae10565787dba5b1d86a0c7696a8a2f6ad1d586115bf2c6c8763ee6b68b8a
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65699);
  script_version("1.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_xref(name:"IAVT", value:"0001-T-0918");

  script_name(english:"Viscosity VPN Client Detection (Mac OS X)");
  script_summary(english:"Detects Viscosity VPN Client");

  script_set_attribute(attribute:"synopsis", value:"The remote host has a VPN client installed.");
  script_set_attribute(attribute:"description", value:"The remote host has the Viscosity VPN client installed.");
  script_set_attribute(attribute:"see_also", value:"http://www.sparklabs.com/viscosity/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:sparklabs:viscosity");
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

app = "Viscosity";

enable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

kb_base = "MacOSX/Viscosity";

path = '/Applications/Viscosity.app';
plist = path + '/Contents/Info.plist';
cmd =  'plutil -convert xml1 -o - \'' + plist + '\' 2>/dev/null | ' +
  'grep -A 1 CFBundleShortVersionString | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
version = exec_cmd(cmd:cmd);
if (!strlen(version)) audit(AUDIT_NOT_INST, app);

set_kb_item(name:kb_base+"/Installed", value:TRUE);
set_kb_item(name:kb_base+"/Path", value:path);

if (version !~ "^[0-9]") audit(AUDIT_VER_FAIL, app);
set_kb_item(name:kb_base+"/Version", value:version);

register_install(
  vendor:"SparkLabs",
  product:"Viscosity",
  app_name:app,
  path:path,
  version:version,
  cpe:"x-cpe:/a:sparklabs:viscosity");

report_installs(app_name:app);

