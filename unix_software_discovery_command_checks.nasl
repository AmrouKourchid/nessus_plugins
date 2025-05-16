#TRUSTED 4e223ea043a350e0ef691b0d1c60d9976af2136c86e2e7d045f95db16fe603ae672af098a5207e651ca2d1e40a0624bf2b4f4ece7513d9d019f43734d7fcb608f121e5ca698ceba7334243643858f23120d496985ed47d3bb59a26704f239dac4c3cc41238272e63b46ebee3992bdc4a5acedc990e59da23cd60b5c38cc447dfff0e876a6e58048a8c0ffba6afc5a8948837ffe172253f1d9df72eda1aaf69be73753edd1b7c571de4d2687a1aea3068a350c23c1ee34a241a6839fdd32abb9a56fe8b404b247a62f060f1091e78f8c8280bed0c8809211a10e416c1a63ef3a1dd9f85e7f20525ef897248e28e60b4e27f661a54be75d1f9ea6ce5ed0e0d0389cd3b298e3037cdf2683caf7aa85255e6590162b4cdcd06d44c5fc043841114c89dc281da3ffe9b31c9dbf127c8e74c0ff452e249379d415be1cb032c44170db38a47db687026144077260172eaa4da7177ace967310212ac12e57184ed97a8f2b8c9eac6ef664b4c964f25fd1de9391b76ed92e8ec7d5b1cf865cf63157eb66cd3283ac0e4307254a5b83cb51ebea191c46e3059de8b7e293901570a07b57e34be5cf35d465f2f5e9e6c8e2cd327ce75a7fe6eccb79320292d83261ebbeb07cac16295fd3626785b77e83aa15a12c519b4acd84247ba76892cbecf6adbc2a3aaa0cb3ef8b47313fa1c9261af5d0f70775ce0e4f03fb11cc698e7137b7149952b
#TRUST-RSA-SHA256 6f74d05623fe07bf336b1c3399522534b84b302b17c6a34afccfdebe325f8bc822777de318c5f2583550b5b11e6131e0fe52c9f6e3c2845ddebf6e454ce5126c72180f53e83652d7707c9fe168f7f59f4b1470b4e402155125de9d73fda761c107512441ece6ddb2cd24d25498752ba916efd890eb128e46b3fc5e1c1bf21f009561b34dffefa6e886d20c945cf5348d9fff303a12f98fe830b9c0128db59e5db8eb3cdee3b6e6265fe5a3c9fd137fdfeb8eb581f74d57033ad45e966a947698530e8ffa0d085ecb4b927098e841c5238724bbf0fdc81505ac31a6f26887ff817f9a6aec135589714427de2032362a3a864d4097fe70de7e6fc0049158da24fcd61ee0815f48c2303d8876a191abca3bc2efca1a904cc9ad7ef2c13c72a46118ffd7052392957c30b8de085630d13c2a67042fc01a61be1d117df9eb35af2aca06367c33e2bb161789d0cd46af11440c9ef7268671f1a9385d08c309f278c414f29409908fd8382744987f77f8b6f857ec16e5a26a7d2fdf676b7b9491cf30428f51393b5e44b0a0f13a5793eaffb876da94cd29570afead8de836a7b188ddcda61b4bd81273c2a30d2813f32da9d8d8f09ddc4721afe766085faeaee1d24dcb20bdfa68b69d209ccf111e26e105d18a00d08119e5b52fd364aed069406dd0786e9cc1d6e8b4f5886c494a0f1b53cad1fc3d518611f5f01683a41a7465a5a4f8
#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");
include('nessusd_product_info.inc');

if (description)
{
  script_id(152741);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/27");

  script_name(english:"Unix Software Discovery Command Checks");
  script_summary(english:
"Checks commands used for software that is not managed by the OS.");
  script_set_attribute(attribute:"synopsis", value:
"Runs local commands over SSH that are used by plugins to find and
characterize software that is not managed by the operating system.");

  script_set_attribute(attribute:"description", value:
"Nessus plugins run OS commands locally on the target host to discover
and characterize software that is not managed by the target operating
system.  This plugin runs those commands over SSH to determine whether
there is any problem that might prevent the successful discovery of
unmanaged software installations.

    Examples:
      find
      cat
      grep
      ls

Problems that could interfere with the discovery of unmanaged
software include scanning with weak permissions, incorrect chroot or
sudo configuration, and missing or corrupt executables."
);

  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/23");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl");
  script_require_ports("Host/FreeBSD/release", "Host/Solaris/Version", "Host/Solaris11/Version", "Host/AIX/version",
                       "Host/HP-UX/version", "Host/Linux", "Host/NetBSD/release", "Host/OpenBSD/release",
                       "Host/MacOSX/Version");

  script_require_keys("Host/uname");

  exit(0);
}

include('ssh_compat.inc');
include('ssh_lib.inc');
include('spad_log_func.inc');

##
# Tests the output of executing a command sequence against the
# expected result.
#
# Notes:  expect_error considers error output when exec mode is used.
#         In cases where the same pattern is used for both error and
#         command output, expect_error is set to TRUE.
##
function test_command(cmd, pattern, expect_error)
{
  if(isnull(cmd) || isnull(pattern))
    return FALSE;

  if(isnull(expect_error))
    expect_error = FALSE;

  var res = info_send_cmd(cmd:cmd);
  var err = sshlib::ssh_cmd_error_wrapper();
  sshlib::ssh_cmd_clear_error();

  #If the scan didn't use a shell handler and we expect an error
  if(expect_error && !res && err)
  {
    res = strip(err);
    err = NULL;
  }

  #Strip newlines in output. Output is split due to terminal width on some systems
  res = ereg_replace(string:res, pattern:"[\r\n]+", replace:"");

  if(res && preg(string:res, pattern:pattern, multiline:TRUE))
  {
    spad_log(message: "Successfully executed '" + cmd + "' on the target host and received the expected result '" + res + "'.");
    return TRUE;
  }

  spad_log(message: "Attempted to execute '" + cmd +
                    "', but received an unexpected result: '" + serialize(res) +
                    "' , error: '" + serialize(err) + "'.");

  var b64_cmd = base64(str:cmd);
  var b64_res = NULL;
  if(!isnull(res))
    b64_res = base64(str:res);

  if(isnull(b64_cmd))
    #Only one of these will ever get set, but it can help with debugging.
    replace_kb_item(name:"Host/unmanaged_software_checks/Failures/<error encoding command>", value:"<none>");
  else if(isnull(res) || isnull(b64_res))
    replace_kb_item(name:"Host/unmanaged_software_checks/Failures/" + b64_cmd, value:"<none>");
  else
    replace_kb_item(name:"Host/unmanaged_software_checks/Failures/" + b64_cmd, value:b64_res);

  return FALSE;
}

get_kb_item_or_exit("Host/uname");

var host;
if(!isnull(get_kb_item("Host/FreeBSD/release")) ||
   !isnull(get_kb_item("Host/NetBSD/release")) ||
   !isnull(get_kb_item("Host/OpenBSD/release")) ||
   !isnull(get_kb_item("Host/Linux")))
  host = "linux";

if(!isnull(get_kb_item("Host/Solaris/Version")) ||
   !isnull(get_kb_item("Host/Solaris11/Version")))
  host = "solaris";

if(!isnull(get_kb_item("Host/AIX/version")))
  host = "aix";

if(!isnull(get_kb_item("Host/HP-UX/version")))
  host = "hpux";

if(!isnull(get_kb_item("Host/MacOSX/Version")))
  host = "mac";

if(!host)
 audit(AUDIT_HOST_NOT, "Linux, Solaris, AIX, HP-UX or a known BSD distro");

enable_ssh_wrappers();

info_connect(exit_on_fail:TRUE);

replace_kb_item(name:"Host/unmanaged_commands_supported", value:TRUE);

#################################
# find matching
#################################
var find_expect, find_expect_err;
find_expect = "\.";
find_expect_err = FALSE;
if(host == "hpux" || host == "solaris")
{
  find_expect = "find: bad option -maxdepth";
  find_expect_err = TRUE;
}
else if(host == "aix")
{
  find_expect = "find: [^\s]+ -maxdepth is not a valid option.";
  find_expect_err = TRUE;
}

#################################
# which matching
#################################
var which_expect, which_expect_err;
which_expect = "(/which|which \(\))|which: shell built-in";
which_expect_err = FALSE;
if(host == "mac")
{
  which_expect = NULL;
}

#################################
# cat matching
#################################
var cat_expect, cat_expect_err;
cat_expect = "(?:cat \(GNU coreutils\) [\d.]+|cat: illegal option --|cat: invalid option --)";
cat_expect_err = TRUE;
if(host == "aix")
  cat_expect = "cat: Not a recognized flag: -";

#################################
# grep matching
#################################
var grep_expect, grep_expect_err;
grep_expect = "^(?:GNU )?grep(?: \((?:GNU|BSD) grep[^)]*\))? [\d.]{3}";
grep_expect_err = FALSE;
if(host == "aix")
{
  grep_expect = "grep: Not a recognized flag: V";
  grep_expect_err = TRUE;
}
else if(host == "solaris" || host == "hpux")
{
  grep_expect = "grep: illegal option -- V";
  grep_expect_err = TRUE;
}

#################################
# readlink matching
#################################
var readlink_expect, readlink_expect_err; 
readlink_expect = "(?:readlink \(GNU coreutils\)|readlink: illegal option --)";
readlink_expect_err = TRUE;
if(host == "mac" || host == "solaris" || host == "aix" || host == "hpux")
  readlink_expect = NULL;

#################################
# unzip matching
#################################
var unzip_expect, unzip_expect_err;
unzip_expect = "(?:UnZip \d\.\d|Usage: unzip)";
unzip_expect_err = TRUE;
if(host == "mac" || host == "aix")
{
  unzip_expect = NULL;
}

#################################
# strings matching
#################################
var strings_expect, strings_expect_err;
strings_expect = "(?:GNU strings|strings \()";
strings_expect_err = TRUE;

if(host == "aix" || host == "hpux" || host == "solaris")
  strings_expect = "Usage: strings \[";
else if(host == "mac")
  strings_expect = NULL;

#################################

# Test all commands, excluding "cat"
var find_cmd = tenable_utils_replacement("find");
var test_cmds = test_command(cmd:find_cmd + " . -maxdepth 0 -type d", pattern:find_expect, expect_error: find_expect_err) &&
            test_command(cmd:"ls -d .", pattern:"\.", expect_error: FALSE) &&
            (isnull(which_expect) || test_command(cmd:"which which", pattern:which_expect, expect_error: which_expect_err)) &&
            test_command(cmd:"grep -V", pattern:grep_expect, expect_error:grep_expect_err) &&
            (isnull(readlink_expect) || test_command(cmd:"readlink --version", pattern:readlink_expect, expect_error: readlink_expect_err)) &&
            (isnull(unzip_expect) || test_command(cmd:"unzip -v", pattern:unzip_expect, expect_error: unzip_expect_err)) &&
            (isnull(strings_expect) || test_command(cmd:"strings -v", pattern:strings_expect, expect_error: strings_expect_err)) &&
            (host != "mac" || (test_command(cmd:"plutil -help", pattern:"plutil: \[", expect_error:TRUE) &&
                                test_command(cmd:"sed -x", pattern:"sed: illegal option -- x", expect_error:TRUE) &&
                                test_command(cmd:"tail -x", pattern:"tail: illegal option -- x", expect_error:TRUE) &&
                                test_command(cmd:"awk", pattern:"usage: awk \[", expect_error:TRUE)));


# Test "cat" command if scanning over SSH
if (info_t == INFO_SSH)
{
  var cat_cmd = test_command(cmd:"cat --version", pattern:cat_expect, expect_error:cat_expect_err);
  test_cmds = test_cmds && cat_cmd;
}

if(test_cmds)
{
  spad_log(message: "Scanning localhost : All unmanaged software commands ran and returned the expected result.");
  replace_kb_item(name:"Host/unmanaged_software_checks", value:TRUE);
}

ssh_close_connection();
exit(0, "This plugin does not report.");
