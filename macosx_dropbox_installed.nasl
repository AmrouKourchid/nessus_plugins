#TRUSTED 33b1b51296ffd8f4b29932114565411e0ba164ab736c743139341591c1a07d8165633cfe9f6f60e5e01cdd7a006e12f137a9590277817b9d10d1ee89c1a87aa67eb6888d1b20aa9146edf3a002bb5565ea5fb4625583907936a8936b1bf40be92d6b90596d9c36b0edd095ebfe5ab563461a2d67132e75fa001a12c7395cfff5df2ca02d56ceb49771ca439b5cc7819b209da6ed5d3973f3db28f3f0affed18481cd9ad46a85e25ebcca6dc343ecefb0e07f5bf0ae68466e49e75a376be6a8a307553d301b843c496c739eaf680f474fc7a4b1f7d9cb782a32b9edde7e052241b7cd6073a03f1a660d2279eb1b61d921ba9fe48dfe246c28d0ab739fcf2f6b8e8f8b632b105eca02f6032e57a4764c133676444fdac7eafb76872aef70513f0b409203f890833f13f963dfb608ed5a51a97ac28f4c7badc9d2408bab2f467fca6c7f5697a21c022d97f9f2aee06c570c8a33ac65464d444459fcaf1bc39b5436a84da6c63a83a94fbcbd6ad7c2103a1ebdca99ce20f6edff5ab6ec8650e45824f26d91ba7ea2979529a43a78f1769ea482684f0c13e8527920c9b198b40a53f7afd61835ccbc052565a4f9b1201f167a40715dc4b689de2dcbf6fd37f159ceb7e335dc80eaecf50ceab6615d8d51ce5bcc4ee3bfc4ff6bc8412e66cff7b6a8db6668ef59882a60666d9c39052f13bc842ff086f1b33f5b72108e2c4cb75d23f0
#TRUST-RSA-SHA256 1205878df943a580f2b6ab9675d35f391a01080136b9aaef6f45fad965a8e9cb9192ad3e61cea926ad7cb90ed7229a48cdc370daa94c2ea9cfcc559c41380156565e019b1125009a0845aead7a3ac9c0dc6b74b633d2c04ff095e1d836848cc99f27b635a1d3f273f1bad376b59a0d69d52edd4fb49337cad249ecc55d621b560682215ec4009c653cdddb72ed9ab78582a6290da144947459565b475a436f15019ba71b4132786a29c127b1e0719f97caa84c48fbe381057260347ffbc3d904fb9024f281cc1a3549a0b7e117aa57641f1beec85066d7f6128e3262608bfbc1b9c5520f5714231d804c34471e1f07268f8bb49cb2d5838e7e1337d0f0ffb11eeec394c31d59f230f8cc8daf6b6b2a70543093ad80ee160bfc76e33434b12c27e9e2e9dd4e099d4df1dcc93aba35d851d72226b7959216aff05e078b12c311fc68b30fe172467eb3755eb1fc2bac31be586c5a6edad145aa9f5d73b526d1a7ea4fabc50f0491b12008ba2cbad80abda0af2ba5aeea1693700c0b5283fd0558275b8c2345e93db8f1ad6dbfa1301215b17adff26fc2418115c99e410326478cc947c357f7238aeee12d2a977b10f2eb5b6ad72a00491b9dc7241c11863c442adb3eaa5ed9ea875636e7b82560ec1bfa99592f1bb8ef01ed9c8256bac0ebb2f7d705268d98b020e7c09e6126757603c93e0f8b60b940fa86e8594dfed804210017
#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);


include("compat.inc");


if (description)
{
  script_id(55435);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_name(english:"Dropbox Installed (Mac OS X)");
  script_summary(english:"Gets Dropbox version from Info.plist");

  script_set_attribute(
    attribute:"synopsis",
    value:"There is a file synchronization application on the remote host."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Dropbox is installed on the remote Mac OS X host.  Dropbox is an
application for storing and synchronizing files between computers,
possibly outside the organization."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.dropbox.com/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Ensure that use of this software agrees with your organization's
acceptable use and security policies."
  );
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:dropbox:dropbox");
  script_set_attribute(attribute:"asset_inventory", value:"True");
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



enable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");

os = get_kb_item("Host/MacOSX/Version");
if (!os) exit(0, "The host does not appear to be running Mac OS X.");


kb_base = "MacOSX/Dropbox";


plist = "/Applications/Dropbox.app/Contents/Info.plist";
cmd =  'plutil -convert xml1 -o - \'' + plist + '\' | ' +
  'grep -A 1 CFBundleShortVersionString | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
version = exec_cmd(cmd:cmd);
if (!strlen(version)) exit(0, "Dropbox does not appear to be installed.");
set_kb_item(name:kb_base+"/Installed", value:TRUE);

if (ereg(pattern:"^Dropbox ", string:version)) version = version - "Dropbox ";
if (version !~ "^[0-9]") exit(1, "The Dropbox version does not look valid (" + version + ").");
set_kb_item(name:kb_base+"/Version", value:version);

if (report_verbosity > 0)
{
  report = 
    '\n  Path    : /Applications/Dropbox.app' +
    '\n  Version : ' + version + '\n';
  security_note(port:0, extra:report);
}
else security_note(0);
