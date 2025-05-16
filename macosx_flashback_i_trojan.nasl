#TRUSTED a1e7682b57e04f5ba908cd1cc03a2e75e1ebee651fbc641be4e874af0dec6a6cf84c3ffce9963be5058cdc1216f873a21a5e0d48c4df864909410393a638679d3acde2f83fa84a441c4bb4157cef328a0f48a03b3df637220c79f576a1dd134cb0b8cf2be3f6bc02cbce71db633822a98843fd8b2a4aa626a4cfae90d95e99b39f83bd2aa17e75ac54bb9c22f5cb4a28cf1a0f8d0969421465df88dc478c0103457544ac6cfa11788ed0616c493a968f7e1d70816eb6db8aafe9885a3281f5c951fc668867a8abe75ba5066ea1c656bc2cd474012f5eef8e819c24167169ce58d9994a3dff74dff6cea090ac3a15bf68ac07dc5fe035a2e68546bbd7774704a0d4e4a92f599aeb9be6c79f838a65e62bc5c3a0ce46cb1a627574929f95f4660e4e1448153d355f1a5ae201d44ddf3173a604d0f5f4b3e5c3162bc86c06279df1cfa6a04aad13f56251d635c6765052363f7bbd21a94065acf9a2a972b3cc039a5ffdb154391adadf83e2e889d54bc4180ee4dc52c2bbf2151a4d8db9310f6ecdb016db83843f88c52c05f8ea4a37376e40a6ce4003680f79f75422e535a9f37c88bb80fc7fdbe1b09efd70e212a473b21a8cfba57c6c25dce4986ee0377511c50c916b77fd88da88b81db8c98c79054c0012998c75735e7110a643fbfac9753dc2182db6a10bc2f37a6bf5c51231c472e0e264ec728fc338ae132804e9989fd3
#TRUST-RSA-SHA256 6417fb1bd7568d28f8f883b3652eb91696182603798defe91b823f3831bcf2ac05c9545ce0f0bc3cc19f52e63fc0d20760f8a995df0276b4ee161e025eac5b0f01f774efce786e1dd616754fab2d39d4c91c06d6cf5a85ce1a2473ff81aea433cfbb8ac5921a61945a1e36e969d754b7ce50fe876c11ecd58f3c38dadc202c17d1381ab05c8db29db9d391317055cc9c3c758481c1d6baacd647cd3da277555c753c75e0e1e583f8ac2f30cfe96b2cd147f2ce0bf8c80221960e8a3b7bd7d7c4bb9d05c9861f4f406d9041d27651d85c04282d44e4a6fe5cf4ac63b85e74b8775c6931c3c840639e0ab4b5f2cb08b5450006100faf153a910bf2604b485ec921db09c9f704fbc8510295c9f28411b51fee685917164872a19f71efedef98c1640d2f20bb5c051f2afc9da7c6e0d74b68fd187309c1575d84859609003df7d48ab05f7c425aaaac6c5200099da647e7374d3e6f3ef7a94d3c40789cececad6906119df3b0ae5ae0b5f90ecebce186e626bee1f0c71e59b2d842ddc92eb36479d38f502b9ce93305ad7dcb9db3cf8678c6eaddf9a90147d99fe1e386b138e433c44e7c9be63161c1c484db381b7a12e4c8aa285f4d13d62f79c9a8fd7a6742e0ffeb16744c0cde81d7e4c1c4b2a7b82fcd157ca52cfd5a39c4fa74c81f1936d9e8fd4f04a81827023f10b25ffdd19251f70f8348e549f7e1db8dcc0d0af00408cc
#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);


include("compat.inc");


if (description)
{
  script_id(58619);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_name(english:"Mac OS X OSX/Flashback Trojan Detection");
  script_summary(english:"Checks for evidence of Flashback");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Mac OS X host appears to have been compromised."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Using the supplied credentials, Nessus has found evidence that the
remote Mac OS X host has been compromised by a trojan in the
OSX/Flashback family of trojans. 

The software is typically installed by means of a malicious Java
applet or Flash Player installer.  Depending on the variant, the
trojan may disable antivirus, inject a binary into every application
launched by the user, or modifies the contents of certain web pages
based on configuration information retrieved from a remote server."
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.f-secure.com/v-descs/trojan-downloader_osx_flashback_a.shtml"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.f-secure.com/v-descs/trojan-downloader_osx_flashback_b.shtml"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.f-secure.com/v-descs/trojan-downloader_osx_flashback_c.shtml"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.f-secure.com/v-descs/trojan-downloader_osx_flashback_i.shtml"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.f-secure.com/v-descs/trojan-downloader_osx_flashback_k.shtml"
  );
  # http://www.intego.com/mac-security-blog/new-flashback-variant-continues-java-attack-installs-without-password/
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.nessus.org/u?7f51a6ed"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Restore the system from a known set of good backups."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Tenable research analyzed the issue and assigned a score for it.");


  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2023 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version");

  exit(0);
}

include('ssh_func.inc');
include('macosx_func.inc');
include('debug.inc');
include('command_builder.inc');

enable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");

os = get_kb_item("Host/MacOSX/Version");
if (!os) exit(0, "The host does not appear to be running Mac OS X.");


report = "";
foreach app (make_list("Safari", "Firefox"))
{
  cmd = strcat("defaults read /Applications/", app, ".app/Contents/Info LSEnvironment");
  res = exec_cmd(cmd:cmd);
  if (strlen(res) && "DYLD_INSERT_LIBRARIES" >< res)
  {
    libs = egrep(pattern:"DYLD_INSERT_LIBRARIES", string:res);
    libs = str_replace(find:'\n', replace:'\n                          ', string:libs);
    report += '\n  Command               : ' + cmd +
              '\n  DYLD_INSERT_LIBRARIES : ' + libs;
  }
}

homes = get_users_homes();

dbg::detailed_log(lvl:1, msg:'get_users_homes',
  msg_details:{
    'users home path':{'lvl':1, 'value':homes}
    }
);

if (isnull(homes)) exit(1, "Failed to get list of users' home directories.");

foreach user (sort(keys(homes)))
{
  home = homes[user];
  # Check path for unexpected chars
  if (!command_builder::validate_no_injection_denylist(home))
  {
    dbg::detailed_log(lvl:1, msg:'Exiting due to injection attempt in users home dir',
        msg_details:{
          'home dir':{'lvl':1, 'value':home}
        }
    );
    exit(1, 'Unexpected characters in current user home directory: ' + obj_rep(home));
  }

  if (home == "/var/empty" || home == "/dev/null") continue;

  cmd1 = strcat('defaults read "', home, '"/.MacOSX/environment DYLD_INSERT_LIBRARIES');
  cmd2 = strcat('ls "', home, '"/Library/LaunchAgents');
  cmd3 = strcat('ls -a1 "', home, '"/');
  res = exec_cmds(cmds:make_list(cmd1, cmd2, cmd3));
  if (!isnull(res))
  {
    if (
      strlen(res[cmd1]) &&
      "DYLD_INSERT_LIBRARIES" >< res[cmd1] &&
      "DYLD_INSERT_LIBRARIES) does not exist" >!< res[cmd1]
    )
    {
      libs = egrep(pattern:"DYLD_INSERT_LIBRARIES", string:res);
      libs = str_replace(find:'\n', replace:'\n                          ', string:libs);
      report += '\n  User                  : ' + user +
                '\n  Command               : ' + cmd +
                '\n  DYLD_INSERT_LIBRARIES : ' + libs;

    }
    if (strlen(res[cmd2]) && "com.java.update.plist" >< res[cmd2])
    {
      report += '\n  User : ' + user +
                '\n  File : ' +  home + '/Library/LaunchAgents/com.java.update.plist';
    }
    if (strlen(res[cmd3]) && res[cmd3] =~ "^\.jupdate$")
    {
      report += '\n  User : ' + user +
                '\n  File : ' +  home + '/.jupdate';
    }
  }
}


if (report)
{
  if (report_verbosity > 0) security_hole(port:0, extra:report);
  else security_hole(0);
  exit(0);
}

exit(0, "No evidence of OSX/Flashback was found.");

