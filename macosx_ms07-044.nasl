#TRUSTED 8925667a37446c6dade80ae23afc45133a02950c67daf64d77f0ea0b01848cbb4880f71ecd998a79d56fa0571bfd4d7c787e2a26cf1afe475f75ff0dbb0b7aa237fbb728080e490a76ecb27f543bbc1272207a70b496f4690eb9f77a828c798f61e7c7e7c9e2fdbb697431c2c36f598ae05016c000874f0c4a93173e4a788e4aefabd53c643a755569950a44beb3b25539cd21bcc58a2cd6962094334449a7a160e6e9f28b900455e90995469aa10f7cda1ca15c5e0a8fec2d120f15efd7bab9836ebd60f398232dd6033c902fe0f51792690787b05ab04f1c67fbddd4f0d63b7f3253499559e1b5fa8ea0918687c5b0a58ca1d5783770746bf39668a1560d3ebb55fa9405343e547e915f4cea1add65c93b64918e762dc073f3757b3051168687559ff8a80368c9989846eca10c5e6a8a20ee64c61e0e6b0fcc488213f0edc6159b30b7280c681d66dcbeb34b8bb866da09a1393d5ffd89903aba554cda10e2369062e55646f1f94dab0b106dfb83372ac34573761bb19a1b75d95a195ff6acc83e5326f6830cbad097b617d7db75167f84e8601a3e2272c5c9ad727b7b63d564e95bba13f13e172aae0a298436c7ef0b59bdc46c2002696cfaab4806f37858fde4f481dfb4ac75165e9853d1d8632e9ba62419b1593400bd4db0ef3718920559e6f996caa93d696c2d7767f57296a49d26fbe981ff01ff0d30e06f6a1ba113
#TRUST-RSA-SHA256 17a5cedd37cf5310a7d9c1f65a79a3e259a168322dd737e538da2ce1420ad9fafd5ddfcdc6cf750afe2fe6f9766b1db28684e3e204d1290ce8e89c2aaf00006c39f6c80f0d834f9cf097103c95112be49bb4e17609ee5b37c8b8093d28a5620c35d7449d809fe1b2b996f272af5a33d7fffd61e7d99ca031a08cb14607f8af5ca151c70d6883f38e93f2b65d3780b51551de13eb246640fab3b81cf83731deaac5f3eb7b43a3359b5494355d66ca9220cd451444ebfe9325a441ae30f8475f529d636f53f4e17d4c5ab61d3d7980bfdde6a19aa949e1514b767bd06511a0d0ddd3c661469a29ca35d7017d5fb01956ec33d3452346c83a4baf618720e07bb9aba4fa233a5202e7ab63df4e06650e76ed6cb707620decc3df46a0873e41b1f761c92b41fb11d7f0f89d63eb0c6b185a286c1feb2a2fe132f00788632f1339df2535c35fa5e793d869fb968af61166561ec4adee596a26659bcee78bf1d20c39a80e485d4f68d6841fbc2beda29495c9fbe12dbb43a71bf23e9f522b31d306640bbfd3bb478a6f93f3ad2b78f6dbeace7612507cb6adbd36d11bc516ae6ea16b10701a8108cd9050dee599e94877a43fd885d1365fe989fc782bf242d3a04cd313fed54ad9114463fb6a008602fd1f979da7f16ab6b686ed6e023b5e290569ce4bca1489dbc49417ca9c921f80103df4879a32989fae7b1a682c6ae3e57462daed
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(50053);
  script_version("1.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/24");

  script_cve_id("CVE-2007-2224", "CVE-2007-3890");
  script_bugtraq_id(25280, 25282);
  script_xref(name:"MSFT", value:"MS07-043");
  script_xref(name:"MSFT", value:"MS07-044");
  script_xref(name:"MSKB", value:"921503");
  script_xref(name:"MSKB", value:"940965");

  script_name(english:"MS07-043 / MS07-044: Vulnerabilities in Microsoft Office Could Allow Remote Code Execution (921503 / 940965) (Mac OS X)");
  script_summary(english:"Check version of Microsoft Office");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by
multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Microsoft Office 2004
for Mac that is affected by several vulnerabilities.

If an attacker can trick a user on the affected host into opening a
specially crafted Office file or viewing a specially crafted web page,
these issues could be leveraged to execute arbitrary code subject to
the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms07-043");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms07-044");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a patch for Office 2004 for Mac.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2007-3890");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119,189);

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/08/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2004::mac");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2010-2024 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/MacOSX/packages");

  exit(0);
}


include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");



enable_ssh_wrappers();

function exec(cmd)
{
  local_var buf, ret;

  if (islocalhost())
    buf = pread_wrapper(cmd:"/bin/bash", argv:make_list("bash", "-c", cmd));
  else
  {
    ret = info_connect();
    if (!ret) exit(1, "info_connect() failed.");
    buf = info_send_cmd(cmd:cmd);
    if (info_t == INFO_SSH)
      ssh_close_connection();
  }
  return buf;
}


packages = get_kb_item("Host/MacOSX/packages");
if (!packages) exit(0, "The 'Host/MacOSX/packages' KB item is missing.");

uname = get_kb_item("Host/uname");
if (!uname) exit(1, "The 'Host/uname' KB item is missing.");
if (!egrep(pattern:"Darwin.*", string:uname)) exit(1, "The host does not appear to be using the Darwin sub-system.");


# Gather version info.
info = '';
installs = make_array();

prod = 'Office 2004 for Mac';
cmd = GetCarbonVersionCmd(file:"Microsoft Component Plugin", path:"/Applications/Microsoft Office 2004/Office");
version = exec(cmd:cmd);
if (version && version =~ "^[0-9]+\.")
{
  version = chomp(version);
  if (version !~ "^11\.") exit(1, "Failed to get the version for "+prod+" - '"+version+"'.");

  installs[prod] = version;

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  fixed_version = '11.3.7';
  fix = split(fixed_version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(fix); i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(fix); i++)
    if ((ver[i] < fix[i]))
    {
      info +=
        '\n  Product           : ' + prod +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fixed_version + '\n';
      break;
    }
    else if (ver[i] > fix[i])
      break;
}


# Report findings.
if (info)
{
  gs_opt = get_kb_item("global_settings/report_verbosity");
  if (gs_opt && gs_opt != 'Quiet') security_hole(port:0, extra:info);
  else security_hole(0);

  exit(0);
}
else
{
  if (max_index(keys(installs)) == 0) exit(0, "Office 2004 for Mac is not installed.");
  else
  {
    msg = 'The host has ';
    foreach prod (sort(keys(installs)))
      msg += prod + ' ' + installs[prod] + ' and ';
    msg = substr(msg, 0, strlen(msg)-1-strlen(' and '));

    msg += ' installed and thus is not affected.';

    exit(0, msg);
  }
}
