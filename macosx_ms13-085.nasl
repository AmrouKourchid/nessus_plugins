#TRUSTED 8283f4b88c9e79c1dde3cb69ed53cecbed7dbfa765a0803f40064ff9106dc9bfc848506682e6c998aabecafe0f72b34668b370b396cfa6561ab9c994497b1a677eb1d35ec173fa43be5e01c8e9f9d5d4eb689bce76ea44c6872538c01d4f1f3dc7c258130c9054f3f7c5f8bcdbca0c47ab8f36fc31d6592b74970fbab69bb545433457b9e3f85669f035b01c122308682ea9b9a80988791b0a70b69ccabd83c2e769874a1501c9404c9cef56d24db6048c04ff6bdd6a4264f5e68ce3317e1cc54d7c963b288d8125afb725165ce8d49ae634e0c04ae9de3aed40575a1c6a0e86702e734372a305eaba2f874437d3eb2b64fceb302d0bd94f7024a4b0b725988cd1bc72fc42086b6794af07371b426dc3208d31d50ab13502423274f17e8081b9bd5119b982a602e937663407297a23c7492b75c489fe0afea84c9ab45e88ebe6c7223f6e050abcfb1d81a830066006bfdfe70f0362e8a745cfd3f2bb182f121d1ce763da9d6b5832802830f86de16fb66609716ea1c92ab3b0ea8d66ad1ea990e949d5d9c030d3cdb8dccd2c9659ad7675825d3998bb9c8ce0061fad3491bd2217719b69e82307931362eb61da72c016da8e55de7465d9a9bc1da7b1b647be77ef3131b2c61d7ca5eafbb7e3ebdcfda53dc62e783f5cec12e7c983517196fe0acd77332a6e39ce5b8dac7e1ebe30e5a5fb7fa034a42a7ad54b2e88332372e669
#TRUST-RSA-SHA256 700adc9ce473f2141a76174c80c6cc0070b3e8aa5a071115896d5037d4deff2fed80984e97fac63156a28c3046de8508c175d93838b2a248eccbfd88cc2505c0e81998989fc9deb0adfe9fa91f76fe568dbaae501872529976c19ab1668ebb70f6b81e9c7bbce72916c72476e4e7a7de49fbbc4c61bb4b1a752fb3766eaf12e30047feeabf1b5cf07abda81c2f470a40202fc9a7c2b33f276efed919531eeeb8983d8edc94675f619655f5dbfc35b3854d7761229a053c989d579245b9bd4aac8c307c298519c3d032822f359d26b152047699368a3018dbe6bf8bdec50a47b760d3e351ee03659b19b0886d59af463302767f34907fb94a280408e89adb0d7ba86f369b401afa89fb76865dd3822a9cc5495759e1eab2dab54106a2a7ebcfd584474473b596f12e921be9759352cbfb78a545bbf20191531e2e32ef23d50b6250a8cdc9fa5973409dba34071fa6bfb032af1228fd94f33528a2008dacd5b63cc9620ef50623cb7f3264799dc5e5b6f9a65680d16d18f5108e9c7cbe54f18a5d00630ced2e44ebf826a0b9398da9c0518742bc193ee95bd49f1ea72dbfc0fa44022bc261a761c5fafa412c67e8d4cf81318c86a9b32cd415f648e58e71d14ca65f04ffbdc3daf3ca2c33581738f8606ed79f8798284b1f60a18b22023be4bc33185db701d56e4039673b320d1a29bf54cabe074baa2b1138af4d55cf723217c2
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70340);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_cve_id("CVE-2013-3889", "CVE-2013-3890");
  script_bugtraq_id(62824, 62829);
  script_xref(name:"MSFT", value:"MS13-085");
  script_xref(name:"MSKB", value:"2889496");

  script_name(english:"MS13-085: Vulnerabilities in Microsoft Excel Could Allow Remote Code Execution (2885080) (Mac OS X)");
  script_summary(english:"Check version of Microsoft Office");

  script_set_attribute(
    attribute:"synopsis",
    value:
"An application installed on the remote Mac OS X host is affected by a
remote code execution vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Mac OS X host is running a version of Microsoft Excel that
is affected by two memory corruption vulnerabilities.

If an attacker can trick a user on the affected host into opening a
specially crafted Excel file, it may be possible to leverage these
issues to execute arbitrary code, subject to the user's privileges."
  );
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms13-085");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a patch for Office for Mac 2011.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2011::mac");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2023 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");



enable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");


# Gather version info.
info = '';
installs = make_array();

prod = 'Office for Mac 2011';
plist = "/Applications/Microsoft Office 2011/Office/MicrosoftComponentPlugin.framework/Versions/14/Resources/Info.plist";
cmd =  'cat \'' + plist + '\' | ' +
  'grep -A 1 CFBundleShortVersionString | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
version = exec_cmd(cmd:cmd);
if (version && version =~ "^[0-9]+\.")
{
  version = chomp(version);
  if (version !~ "^14\.") exit(1, "Failed to get the version for "+prod+" - '"+version+"'.");

  installs[prod] = version;

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  fixed_version = '14.3.8';
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
  if (report_verbosity > 0) security_hole(port:0, extra:info);
  else security_hole(0);

  exit(0);
}
else
{
  if (max_index(keys(installs)) == 0) exit(0, "Office for Mac 2011 is not installed.");
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
