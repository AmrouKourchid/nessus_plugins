#TRUSTED 5da30feff2512ca56431384f6a62411a1adbb2c4e372b7e9c8e10cf619ff993ab7c0d85bb29bb5f20c4912333b3fc049a4646048c8a4144c487eb901ceee655319a084073d16c527ba4cc7b070d6380422a7a33fe75af0ea7b5ee3658eadf09ef0d8834f398c3a53fcea983d0604c1dd9bcf1660881ec5c3df8c3da24c36da9724f7346987991ff4729e039c7a13a9d4a59bbace67a00e6c2304145e34e6e859df78f8bf0861c663509856d3560528764685d840f7b3b9b612ba88775598d261f2389439c1307d4858d82afb7a9f293608a19e35f3c1d78f092563602d3936d330216a4aeb2822005728878dc73950f7b8dfcbb2daecb24425ff5a937a83d23ed20112a49456d1acc95cde99d05cc44b61d5b9af4889b371bf5e0138f827cb203900e15f92814e38f7b3ad6396b0bd790b741bd5f8e37e7327ced8c35fb5d062f3c125a6f92b145bd9c93abd0c5244cad8c304da12e615e4e3ebe2040193bae1e2e5bf1e87b7c09d799c28b03840d07f9735425c6f2fe651f3aa9d7cd39edd2db36ee2a2f842004f44372ee4637f4d8b94390364ebae316cb174b80f5ca39d02cd9c9cef3e8338a0fef461c732e568b802f3de736c272b79048ce44d55c7eb8f429323e612b0a3c2c73a48837d9d3c4508168ca7a56a45257873c76932d49a6b162925b3089ad11a8fd398bb12498edecc02d554a8160dd7d186a4a1e1ad1cc3
#TRUST-RSA-SHA256 5e166d7aedbf0f8da4bf70653aceb64e5d59e6385898589464b0333ccf4793f61732afe316deeece9d580a0fb6f0024dd591a65fc65ad93cc0fb7416b7261e22f2182f3d6b80e31f6df9614253ea85f4600b66a8e6acd788a9af120b15c4db7aaa5d63e4147a736c4803d6e2267f8fec1a643999cb9f30508f38eca9b027782972e51a26cdf7d7b096ff039ace07e38efe4973e4bb72472aad9a955553dd5ceb457b71b4244f9384c11fa2c74474941e6e1d245a44446b28b6c4b5ddb07a584f6f60f8f535b7e3d1e72e39436cf9bb5a8c1556638067277ffc4de79cca4f0a92682b8ad92fce097e61bf0c0f32513a9d38633fa664c86d8c55bc8f1b46904e82d0b7c3f86b3d41c8ecbfa487d40c2bf1e04714a5db722a8ef505c48d008ed0cb5620f1181fe3ad221b8bfa06efd38ac2920ea24f6fe09d086eff65e07034a7b27688e29764ae77239a86eecacb564ed8a91b4d890b271789359c5ff2b182289f2a5bf4ec0a548569833e39347b0bd62778b8e376ccc7518db04086b2db93e348eadabcaabae3c998144150d5693d6a3ba1a4c5ed81d91e73119565a4d4eafbe76f1d424fe52b74faff609925f796dd45206dc1283b5f974e1100b6e2c8629b523c0e4054cbad0c74b19571a7a3fad5bda14276a787d294ca142d310d227370d76770df65008b6326cdba1a20a9f6a10c4b3abcb662345e42ca52e54a94765e03
#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);


include("compat.inc");


if (description)
{
  script_id(58812);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_name(english:"Mac OS X OSX/Sabpab Trojan Detection");
  script_summary(english:"Checks for evidence of Sabpab");

  script_set_attribute(attribute:"synopsis", value:"The remote Mac OS X host appears to have been compromised.");
  script_set_attribute(attribute:"description", value:
"Using the supplied credentials, Nessus has found evidence that the
remote Mac OS X host has been compromised by a Trojan in the
OSX/Sabpab (alternatively known as OSX/Sabpub) family of Trojans.

OSX/Sabpab is typically installed by means of a malicious Word
document that exploits a stack-based buffer overflow in Word
(CVE-2009-0563). Once installed, it opens a backdoor for a remote
attacker to upload or download files, take screenshots, and run
arbitrary commands.");
  # http://www.sophos.com/en-us/threat-center/threat-analyses/viruses-and-spyware/OSX~Sabpab-A/detailed-analysis.aspx
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2fbcf878");
  script_set_attribute(attribute:"solution", value:"Restore the system from a known set of good backups.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Tenable research analyzed the issue and assigned a score for it.");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/20");

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

homes = get_users_homes();

dbg::detailed_log(lvl:1, msg:'get_users_homes',
  msg_details:{
    'users home path':{'lvl':1, 'value':homes}
    }
);

if (isnull(homes)) exit(1, "Failed to get list of users' home directories.");

report = "";
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

  cmd1 = strcat('ls "', home, '"/Library/Preferences');
  cmd2 = strcat('ls "', home, '"/Library/LaunchAgents');
  res = exec_cmds(cmds:make_list(cmd1, cmd2));
  if (!isnull(res))
  {
    if (strlen(res[cmd1]) && "com.apple.PubSabAgent.pfile" >< res[cmd1])
      report += '\n  User : ' + user +
                '\n  File : ' +  home + '/Library/Preferences/com.apple.PubSabAgent.plist';

    if (strlen(res[cmd2]) && "com.apple.PubSabAgent.plist" >< res[cmd2])
      report += '\n  User : ' + user +
                '\n  File : ' +  home + '/Library/LaunchAgents/com.apple.PubSabAgent.plist';
  }
}
if (!report) exit(0, "No evidence of OSX/Sabpab was found.");


if (report_verbosity > 0) security_hole(port:0, extra:report);
else security_hole(0);