#TRUSTED 8f7ab61b652522761c4a2ce80629098be7970258f678f068ed077d9770893efa0526dcbde809fe7c65e2954db4d3ff6f2c9932fead23b6128c64bd021a7fa8ab3251fc21abc34a1f3ac7921683381d42394b4651fc1f2ecc4ab1f07199682e9b3c5a5e708e96e65ada69a57a57e56e0250cb7a6203a59f26bcf7c3255837ddaff09db88a60a10378601baa94cd0c97bd3812339e958ea81d3c785e3a36cda4027300d236a698c5d34b167b316cc945581e1f86482063564de87f2b351f73ab9484889f08605688bd266b35f0182ba7f5584bda3c128cb92221fa7f50305334782ad669f6607cf6b8f89cf790839eb277039dceb93ae18b2730447fb37e24595f9f685d5f4568552cc1f282376774bbd2370ca8fa51f433b7d9fc92bc7fc921b920c7124072c76e32175689b8701a70cc2bc2e4e8ab1ba0c900d6204991391c51122bb72623d3bf439e7f6f67e7b76158bbb6fbbfd2fd22fdf725fbe1970ee9acfe88d8e7eca1230cefbc8991a739da50c393d27dcdd8ac8c8170a4ebcdda49141a204ecf5b70265df33e859bfc1a03c69eed85cc86e46758ef53b1f122ea6ae9c954c509b13ef3b89753f00bc9bd61576d3e14f243fd30fb5e45990d11d57c10942a52a76b5ff1512ef72d274e90e5affff3017f203ea51b8451e0dea655fb36825a69db2c6e0f68fe04d1f02d25369f7a52414dad0978e615b7605874663123
#TRUST-RSA-SHA256 2b1fd4828ce6aab48d703a824b67d447dda5f37d29022244a79227f9cd6a5d53377ae8fee87713753783fa48ff1eef8184795bd296db5481be0b8861756049eb5fa7e3a9a248f8972fcd218306f032d0d0a56d6f7bf218579fc269cab1c2c38902823693a6623a82d25b78dca720b11fb19586218e1dbf11e36cc2eaafbd285707647548d2db7f07ed01e64ed3950646bcf340952b3246eb5cb96747d60d60c8aeeba4a9c77119d04b012642f7057e43f895634c9a0ed47070ce47ecd376830e3e1d1a5dbe4bc63aed7d460d2ae843c47d32dc00893bd669015e7dd27f8fb81f1d7550361c24ec79bb93315cf9d3b5060373691ace83250cbdb08356f3098120d65f1862f0169e19e1c822134866bc262bdd429f1ca62fd060749f0bda464c92be1a2297bd2676e9f617c442b3d825cc2d22e1ed2088d3ccb2281c37e72c146525e6be29ae2493cdc1874798da4cf9df57c258f5417f71eebcfce4124dcd858c14b3bef41a30e8654ab7f6aa16a55b268e9ca61ed9126ce31991fc0c2cdeba57ef38af8a8b04365c54531be2c0de2ca68da580536d501e0d569cc0ef0cb13acb3f6f45893c8d1180dcf17f5ed231b5574768810e4b8691d62ac061f12e3e08e1f1fb70bd8368aad2c9ad160424c50d9fcd211fd46b98322b6f57022f7061646bdce22244d047682d41f2596ed82b376b3d3d0baaa95203b7ea355fa30fe7f915
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(69514);
  script_version("1.25");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/24");

  script_cve_id("CVE-2012-0397");
  script_bugtraq_id(52315);
  script_xref(name:"IAVB", value:"2012-B-0027");

  script_name(english:"RSA SecurID Software Token Converter Buffer Overflow");

  script_set_attribute(attribute:"synopsis", value:
"The remote Linux host has an application that may be affected by a
buffer overflow condition.");
  script_set_attribute(attribute:"description", value:
"RSA SecurID Software Token Converter prior to version 2.6.1 is
affected by an overflow condition. A boundary error occurs when
handling XML-formatted '.sdtid' file strings. By convincing a user to
run the converter with a crafted file, an attacker can execute
arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2012/Mar/att-16/esa-2012-013.txt");
  script_set_attribute(attribute:"solution", value:
"Update to version 2.6.1 or higher.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-0397");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:rsa:securid_software_token_converter");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "command_builder_init.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/uname");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include("global_settings.inc");
include("audit.inc");
include("misc_func.inc");
include("ssh_lib.inc");
include("hostlevel_funcs.inc");
include("telnet_func.inc");
include("sh_commands_find.inc");


enable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled"))
  audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if ("Linux" >!< get_kb_item_or_exit("Host/uname"))
  audit(AUDIT_OS_NOT, "Linux");

fixed_ver = "2.6.1";
grep_template = "sed 's/\x00/ /g' '%%%' | egrep -oa -- '-(android|iphone) -o -p -v [0-9]+\.[0-9]+(+\.[0-9]+)? \%s'";

ret = info_connect();
if (ret == 0)
  audit(AUDIT_SVC_FAIL, "SSH", sshlib::kb_ssh_transport());

info_t = INFO_SSH;
sock_g = ret;

find_args = make_list('/bin', '/sbin', '/usr/bin', '/usr/sbin', '/usr/local/bin', '/usr/local/sbin');
if (thorough_tests)
{
  find_args = make_list(find_args, '/root', '/home');
}

find_args = make_list(find_args, '-xautofs', '-tenb_fstype_exclusions', '-tenb_path_exclusions', '-maxdepth', '4', '-type', 'f', '-name', 'TokenConverter*');

find_output = sh_commands::find(args:find_args, timeout:60);

if (find_output[0] == sh_commands::CMD_OK)
{
  find_output = find_output[1];
}
else if (find_output[0] == sh_commands::CMD_TIMEOUT)
{
  exit(1, 'Find command timed out.');
}
else
{
  exit(1, find_output[1]);
}

audit_report = 'Fixed version is ' + fixed_ver + '.\n';
vuln_report = "";
vulnerable = FALSE;
instances_found = 0;

filenames = make_list();
if (!isnull(find_output))
  filenames = split(find_output, sep:'\n');

foreach filename (filenames)
{
  # Remove newline
  filename = chomp(filename);

  # Skip blank lines
  if (filename == "")
    continue;

  # Skip filenames that don't match a strict whitelist of characters.
  # We are putting untrusted input (directory names) into a command that
  # is run as root.
  if (filename =~ "[^a-zA-Z0-9/_-]")
    continue;

  grep_cmd = str_replace(find:"%%%", replace:filename, string:grep_template);
  grep_output = info_send_cmd(cmd:grep_cmd, nosudo:FALSE);
  if (isnull(grep_output))
    continue;

  if (grep_output !~ "-o -p -v")
  {
    audit_report += filename + ' does not look like a TokenConverter executable.\n';
    continue;
  }

  # This could fail if grep on the remote host doesn't operate like we expect
  matches = pregmatch(pattern:"-v ([0-9]+\.[0-9]+(\.[0-9]+)?) ", string:grep_output);
  if (isnull(matches) || isnull(matches[1]))
    continue;

  instances_found++;
  ver = matches[1];

  if (ver_compare(ver:ver, fix:fixed_ver, strict:FALSE) != -1)
  {
    audit_report += filename + ' is version ' + ver + '.\n';
    continue;
  }

  vulnerable = TRUE;
  vuln_report += '\n  Path          : ' + filename +
                 '\n  Version       : ' + ver +
                 '\n  Fixed version : ' + fixed_ver +
                 '\n';
}

if (info_t == INFO_SSH)
  ssh_close_connection();

not_found_report = "RSA SecurID Software Token Converter does not appear to be installed.";

if (!thorough_tests)
{
  not_found_report +=
    " Note that Nessus only looked in common locations (/bin, /sbin, etc.) for
    the software. If you would like Nessus to check home directories in addition
    to the common locations, please enable the 'Perform thorough tests'
    setting and re-scan.";
}

if (instances_found == 0)
  exit(0, not_found_report);

if (!vulnerable)
  exit(0, audit_report);

security_hole(port:sshlib::kb_ssh_transport(), extra:vuln_report);
