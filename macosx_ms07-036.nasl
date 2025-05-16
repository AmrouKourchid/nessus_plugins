#TRUSTED 659a0972fd8bc84f4e835c152207833ffac21496aa69de00ec2f7174a2d8923bcc5c2b4d2a2e8a0975b7e6cfa6d9e65811a3aebd6dbde08857f617e73bdffcda6845e2590dfa36549820c076e0130b056ddaaac876840b843b99c97b7de4e1da4f704b01229d703b915edfc78da51a71c9bcfb22309067e0d549bab19b690bb4f73508b47365ebdb56e01199b21e5284af4537eebb98ca597c7f765c90ca6558bde9d2fe2d7c16ff5ffffe2a183b5c86851f7494418f0f6bdd5fabeaed963c280943ad84ee0c6c6fb96c1132fce8df5162bc6313c0a54404e056c1ab2b02f334da63ae1761f240642da8c9af0da5ae7a0e2337e91658f23a947986c0d07722dce680d3c79d33054544937b293384aa4d07459540c91fd47a0dcbdaf42ad639dec35c312231ae648d89fa906edd6c606b672d70f5217296fdfc7084e2532ede317dd9b49a3a008a6d87f5f7102548fb6eeae3fd19ecb612316d98f69e466dc5d8aa379784ca01394ca47e1fc7db7e5354abae2f151ea7b5f9f9553299eb7174ef5ecad0f61c5dd61cc24806582ce4ba780152bbc3f4b3a6eb8479b7d1882c857bb7209a5a6763693cbd0bbc39c3cc18d76d857bf77f6a11ac81b7c43ddcd6ef1f905dd12277b08e4281cc3ea10167e7d46c7bc82fad48616637d6859287d980fd83b606652612ddbff6b0a18f044d1b5b167f1bef1f9bd2430106055326140956
#TRUST-RSA-SHA256 0338c44ba77df77a5543846e049157af517b4a2f5cf233d02bd24c16db638f73f75e1095c969e60aafc0b5930cdebe349785f0a41408d6bc053c49504dc87d6bdcf09bd0cae8b8524da9ba00d42728d26e6240319be19c9e3a1c765dd5dce8104cda979baa0a31d9edff7381ed61eb813f4fae2cf31da30c8698873c57b9b9d87c89abd271d1f74da20e7819499b423f2ac245cb35202752890e8f74078978268a659bb2385d6ef0286f9700cdde4eff2143fa40b65eb41207afe4e65e7dac445d4b3364308a59b2b80fb852a0d4bb3d2ef84099c47323575d219f5061a44d424985743adceefc4015bf04c572eab70449af6b73ce68a31fd32f69fff30f2cf484e594f4084f9ae619404f03484d5c98b4a4dcd82fba53866abf03961566f7e30dabc99213e07e5d7e88733cd8a21b008775f5ea8ccda484e83bfbf74b8f4152de5ed600fff4b85709bf16f16c2ea26ba4b72d9d96253f1664e2c49e2a559a10c641fb74ed57ed13366501b19b49f7ec80b3f539444c919b1a8b4d4bd3bb352d84e595abf47935f94a3e48fda96e4218da8d11780ac1623cb75355e42e8df17e7815ce307e4cf8aff7f31b4be29246d80063e943a8e29719bdc3805c9d1944248f4ecfb4d4d5b2a40eae313bda14f88ecdff6852b1c19b2d21b30424f16b662f12dded3abfa0c1ec571d7bfbe442b5a3d544b4e86a93325b7d6dc1626f9250f4
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(50052);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/24");

  script_cve_id("CVE-2007-3030");
  script_bugtraq_id(24803);
  script_xref(name:"MSFT", value:"MS07-036");
  script_xref(name:"MSKB", value:"936542");

  script_name(english:"MS07-036: Vulnerability in Microsoft Excel Could Allow Remote Code Execution (936542) (Mac OS X)");
  script_summary(english:"Check version of Microsoft Office");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by a
remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Microsoft Office 2004
for Mac that is affected by a memory corruption vulnerability.

If an attacker can trick a user on the affected host into opening a
specially crafted Excel file, these issues could be leveraged to
execute arbitrary code subject to the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms07-036");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a patch for Office 2004 for Mac.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2007-3030");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/07/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/07/10");
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

  fixed_version = '11.3.6';
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
