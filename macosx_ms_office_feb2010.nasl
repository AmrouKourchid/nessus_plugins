#TRUSTED 8835f88ed29f8af3d63be4dba64e63577ff6bba97f8508f8d7b69ccc25f157ccca3810b6c1a83348bff868d6f66b109e0d19dbf1b932830eec99f0c4d83c807d6b93afe675dc08c77545124fd6adc2829c544cfd6e9143b5252aa29c0631f6f5005aa944aba1255ff6ff024c493a874c745778afcba3705b98acc82a33a0136fec2071a622328ee9f3601e480a53ddba2d38a50b2fc57fb4caa90710fefbeb942e6b332b414e09a44f38bb73491af37bece3ec73ec9694c164e718bd7ca149ad341273258aecff40fe2c430244d9e2326fdc79cefef9add77ee233fa6bb28a6543abc31a1d710099be7e08f68ac6adcb55eaf336bf8f483bc302b8bc75964945a407c54413367f65e7abb40e1f483add9d53f077e11f15aa11852e07def8024c246d9409bbe5bd24d6bb3e2fc25e8a00751d4385e5a3d133f98e269e69ddfc1f8b54771703b1b56153a34caeb4092f36b93af67942c293bd784ffd17f3844d0d98ea9cd4ce3e08b43d9a88ffbfcb30db257b73e2918190d37f02c99fa707a3cf6cfd8016059803489fc15d1923e765a96c83b076e4809e7c9bf3d689da66fd5ad651727bf84321a8123d3bd4271f04e2786253b3a8e82ecf5f64e9d65018041ae7c7b16b9749387a4f1a23f3620dfe65f38ee9e076a8844c8a992d139a805a47017f111dff5d4d1289370d423c77b4312dcead3ee774dc91d59db79e47e1bc0b
#TRUST-RSA-SHA256 07740883636bfee4956820ed3fd8ca6a2e9447365ecd1a0bb4e247a5089fe8bc4877be007044040157843b92c282c107f05b828b37d018ebcdd933cfc2689ec6546e523c4572d218eaf69e0a6d90bcc302cda4fb946cd37040c6c6dfb04d6ca428b291742c72dfeb33d952b1ed7bb7ab4dc915904954b01bcb38f3a2a0729776a30adab59eb1e9140cb1cec2afbd11852ad163a11f601790d66eed60d7956b6d88070a3c79a799f8983e468b2d941e7401949ed4468497a9dd70f3d07aed9fb03dcede97768cc76d6ed23e9643cbfe38a402b57066194e534d39125f273acb0622a139e0e1bbb9af76f2482cd7cc8d2b6663487dc4a977f3b547318db2a96bced2eacfc561b5eb580debb15425216bf172b921f6d3ff77766d7e4f213ea03d33fe3607ee80375cb1edf3de983118367de223fd6c132e4a3c74938ec9919f99830c95fbcae23df76a8f856f51150f6524e592a48a878677f0cc2f0f6ef1c39270928ba5aacd2ebff69a53abc7b0b606a21b4b239bb10901a88ad427c7ab7a2a160b8668d89685a946776ece5c4e5bcdae6c41d23641fa2a9f896757dd809f6597144e367b25337a49a6ab5c5a7e0759999e6971e485948ca0bd74991b157b0dc6197b4bb374024896284584abaa8b2e2b0c4390133213e24f016615688036f8ae3dea44185b5e496fd3295a796625b6ac7ec4a51764adc4444df9468dff58634c
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(50064);
  script_version("1.27");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/24");

  script_cve_id("CVE-2010-0031", "CVE-2010-0243");
  script_bugtraq_id(38073, 38103);
  script_xref(name:"MSFT", value:"MS10-003");
  script_xref(name:"MSFT", value:"MS10-004");
  script_xref(name:"MSKB", value:"975416");
  script_xref(name:"MSKB", value:"978214");
  script_xref(name:"MSKB", value:"979674");

  script_name(english:"MS10-003 / MS10-004: Vulnerabilities in Microsoft Office Could Allow Remote Code Execution (978214 / 975416) (Mac OS X)");
  script_summary(english:"Check version of Microsoft Office");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by
multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Microsoft Office that
is affected by several vulnerabilities.

If an attacker can trick a user on the affected host into opening a
specially crafted Office or PowerPoint file, these issues could be
leveraged to execute arbitrary code subject to the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms10-003");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms10-004");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Office 2004 for Mac.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2010-0243");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2004::mac");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2010-2024 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/MacOSX/packages", "Host/uname");

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
if (!packages) exit(1, "The 'Host/MacOSX/packages' KB item is missing.");

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

  fixed_version = '11.5.7';
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
  if (max_index(keys(installs)) == 0) exit(0, "Office for Mac 2004 is not installed.");
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
