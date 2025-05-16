#TRUSTED 2d8aac61d71d1c5781f6b29362aac65238f9d938246e4307cc7f40619261d260ac7cc89d6dcafcf49da0c3ed19146a98dff650d3b0ad028e8925718c739dc7785f300508c9475a484568934d1fec11a1e4f8ba45735475ca4ce6af95b62ad0c6c46c96d4131d7b3f996b95a1d49374badb6b88625b25e10977e7bf95f794cd07087164ea0ce5e6bca056fafb53875e063a805084323643559e7a2cc955bab37dba2cb686e38f768d6db1d6349ee870b506ad6ccbbb813d769eea84f2b15b5f87a151a435be01691a60485208a230d5fbf0468594efa0ff4ae380d99105ab97d8b1d1573ea9b5a68fb9e0236b5d749710c600d3f0b8d10eed70d73a0d39aede6c9d55d2974c93906d3a5a4a67f1987818c9915c406270710ea2c9041bd183d7420f2b0147a407d84a9302139b5c9edbf021f0773a7e21382d20c89ec85c65562aef0d83122109acea56f7879ff619171e85dc2943ab996d022c5c39b7b5caa93b4c07e63ca29899013cc6618a828d523c7edce848b969ae7016aa4366cebf042c2e5d392d500f87243ea7f6f3ef90ad9a5f60d4e3c7417b0eed6e48cbe96acc269bce34b9cf3af9fda1624cd29117aaee4511e132b0afb12574f635f18f49a6365f4bfdc22f14e0e0388464f9fbb1c7ac21d784a8a0fa31b66d3bbcf71d45833d430b9542baef5307237f0cc04b1c3e9d6aba46373c62809d8c85ea69de75874d
#TRUST-RSA-SHA256 a879f4a29300375d037f24f974bd9617504a5f3f44ea25c630abff869f7ced8d450ee91466018ba837ab5712bf00302f80bce63afdcac64522a06f732bcfc32dced31cad96d6a6a31d96490f71ddfe7668f0283d6884cfac9579ae0331568b95744b28cbe2b6c717e6f413312232af08ce6499dd4e300acde5bad56f6f04f39399f1c3c967cbfc93ac861c5c5a728544a1baef6ca109fc4e4bcc80379d1280576f1cf147da0196ea585bf7a8eeef930542eeae83529d8660ee2d289e8a4ab85cee919bfdf0a0fb352f5f524e1a405269636650ccc9b03ef2f2bcce6638ba12798bcb69fb4bbb948a2a2691bf7e60a617c57b46056d0ca14f167d00454891d8d2020b98b63e283cf39f2d9a185cc5a804c3809849fdc047a991409b037a2a16fe5534c08e831736440d92987c86eb8e7c46db7de4a10862095410db1ad5699f2b1070fcd33a4a1e2bf11394f161279edbeccd30dc2e46b3ae6d016f0a7aafce910bac59eae4e7aca37e1da66d8cee7a4b97cf3416055339c16cb781fb466ccac27290f42e748c92a253d9c09f4fe4b243358f6086a0bf64ad13736ebe4ec6e297c3a9ee96ff3ababf7b46f9b6d1ad40bab630339a2d111ac9092d39b11f8fc95062631d3cd3ca00701cbf35ab3bc91a8087b6d8ff2bcf249d1694f9cf0fa8e7f0af5182f969daec564fad632a2a034ab411cd974d0dc20326fd25d626cdce56f6
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(69347);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_cve_id("CVE-2012-5679", "CVE-2012-5680");
  script_bugtraq_id(56922, 56924);

  script_name(english:"Adobe Camera Raw Plugin Multiple Vulnerabilities (Mac OS X)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a software plugin installed that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of the Adobe Camera Raw plugin installed on the remote host
is affected by the following vulnerabilities :

  - A flaw exists when processing an LZW compressed TIFF
    image that can be exploited to cause a heap-based buffer
    underflow via a specially crafted LZW code within an
    image row strip. (CVE-2012-5679)

  - An integer overflow error exists when allocating memory
    during TIFF image processing that can be exploited to
    cause a heap-based buffer overflow via specially crafted
    image dimensions. (CVE-2012-5680)

These vulnerabilities can be exploited by tricking a user into opening a
specially crafted file and could allow an attacker to execute arbitrary
code.");
  script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2012-31/");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb12-28.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Camera Raw Plug-In 6.7.1 / 7.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-5680");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/12/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:bridge");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:photoshop");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:camera_raw");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "command_builder_init.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");
include("macosx_func.inc");
include("sh_commands_find.inc");


enable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

if (islocalhost())
{
  if (!defined_func("pread")) audit(AUDIT_FN_UNDEF,"pread");
  info_t = INFO_LOCAL;
}
else
{
  sock_g = ssh_open_connection();
  if (!sock_g) audit(AUDIT_FN_FAIL, 'ssh_open_connection');
  info_t = INFO_SSH;
}

err = '';
dirs = sh_commands::find('/Library/Application Support/Adobe/Plug-Ins', '-xautofs', '-tenb_fstype_exclusions', '-tenb_path_exclusions', '-name', 'CS[56]', '-mindepth', '1', '-maxdepth', '1', '-type', 'd');
if (dirs[0] == sh_commands::CMD_OK)
{
  dirs = dirs[1];
}
else if (dirs[0] == sh_commands::CMD_TIMEOUT)
{
  err = 'Find command timed out.';
}
else
{
  err = dirs[1];
}

if (info_t == INFO_SSH) ssh_close_connection();

if (!empty_or_null(err)) exit(1, err);

if (empty_or_null(dirs)) audit(AUDIT_NOT_INST, 'Adobe Photoshop Camera Raw');

report = '';

foreach dir (split(dirs, keep:FALSE))
{
  plist = dir + '/File Formats/Camera Raw.plugin/Contents/Info.plist';

  cmd =
    'plutil -convert xml1 -o - \'' + plist + '\' | ' +
    'grep -A 1 CFBundleVersion | ' +
    'tail -n 1 | ' +
    'sed \'s/.*<string>\\(.*\\)<\\/string>.*/\\1/g\'';

  version = exec_cmd(cmd:cmd);
  if (!isnull(version))
    version = str_replace(find:'f', replace:'.', string:version);

  not_vuln_list = make_list();
  if (!isnull(version) && version =~ '^[0-9\\.]+$')
  {
    if (version =~ "^6(\.|$)" && ver_compare(ver:version, fix:"6.7.1", strict:FALSE) == -1)
      fix = "6.7.1";
    else if (version =~ "^7(\.|$)" && ver_compare(ver:version, fix:"7.3", strict:FALSE) == -1)
      fix = "7.3";

    if (fix != '')
    {
      report += '\n  Path              : ' + dir +
                '\n  Installed version : ' + version +
                '\n  Fixed version     : ' + fix + '\n';
      if (!thorough_tests) break;
    }
    else not_vuln_list = make_list(not_vuln_list, version);
  }
}

if (report != '')
{
  if (report_verbosity > 0) security_hole(port:0, extra:report);
  else security_hole(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "Adobe Photoshop Camera Raw",
           join(not_vuln_list, sep:'/'));
