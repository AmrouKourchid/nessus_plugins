#TRUSTED 073d3aebcbaf71344617ca7043b85c9914bd8f79497b54fae2c0e5dc537228ab83580ae145b49f98497c3ee4e537ffa4ae73d97cbe5a0a15c8b80ff73119e97aca175645e93cd8216a605b9d17c62eb0c55a7337783ed73311851917c61667cea1f516563ad95a438e7f51b047fe2da80dbf24149aeb706c3448b33408f1ce91cd7838376102c675f85c3e5a51308cdbee89f4dc3487cf6a63591f15b402dabaff0c8855cda12ec15e6e759285f064c809dd5e289e37702d0cdba4600f7addd7d05ea94ce06aceab490958443c3c815f4779053dba11bcf021bdece271f7cbb3e10e8d4ada39974f1bd15197eaee686ecd6499a37c22cc3753cfa210cf18dc1f062bfebe3358ec698229d04d15c13fd1095f3c7b43f264f3e27c2d53deb2f735ff197f37818c09f3fdb33d19d1605c79871648f1b4e4fc6ab9ceafe1b6a78d9223cb86cf997fdc91e143c7dd8aa16a7871e982a2abe13d35de7e248bdb7151e2e2194be7e9c7413e22af98f34a8ca3b1f97e1b5b675dcf08e28ade7e670933d13732265c9c6ac6532c3c5b5ed5b408430f493eb485437ccb38769e2020bd87f95ef254a74ecc29227f31b851c4f97511e62b01c4af9873542b436f5a78688bbe12f346f87341ef153de0ed11d8fcda2fe2bb74b4865128592a6d902b65daefb4deadd4cb6a03cbb56f91ea742121d827b4d5443bd28d88689f31d8dc02a73f43
#TRUST-RSA-SHA256 30cfb0f07368aa8593923e784670d8aec0fcd50843b4730ba765ceb607214997350014625c4510edf815db78cf7386eba9c3fec9d89e8fe66eec9febab5336ab89bc48417651dd70eb4fed033192098dfdfff97bfe1186a6c61d4d62c3d7a886b1acd2dceba1cd114557174578daf9d9c97bfb63b2335b1cb61f65f4c21491b7a950a118c3c3911e55369a4724ad8fcc16c111986f210e6514acc152994e86bb724e3272ed62cfd96c0204e836f65098b2aadbbda61d603ce5806a237ce5fda85a1b0d3ef32c0e13b738850e0ffe84a4b186e64afc590daac36fb3fa3e6b714d95910c8ab1121de1381f4feb92a775f417a792b51a9e47a58bf0a86eba13e9f7a29cc974c38dc505afa6633b24c4a797ce19fb320b4b2010c49ecc43edaf817fbee1cbd7d06721c13e29536e285635efc427e113d5a002634497a0fdea4faa2481a7e598ed70d905310870e4df20a2970049c0530c3e9b065abe9a8d5de56ef35bbaab4f780ac5b4150de598c7f24b319c17577281c224c0cf99b4c94b105c4e33b7718de789ca1cee0a26df1ead51432cb5a4f9010b23a3b52088fd5455825aba22bb6df52a4bf612e3da0c513661e08198351f7f1015159df96a8f527979836e08dfc3801741aa7c15ffed447124dd503498c35e4a0725216f63aa3ba0bdaf9fc404538b8aa1734eab75762d9fd2e4c3c29f73ec6ccec26d1ec4ffa40b53e0
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78436);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_cve_id("CVE-2014-4117");
  script_bugtraq_id(70360);
  script_xref(name:"MSFT", value:"MS14-061");
  script_xref(name:"MSKB", value:"3004865");

  script_name(english:"MS14-061: Vulnerability in Microsoft Word and Office Web Apps Could Allow Remote Code Execution (3000434)");
  script_summary(english:"Checks the version of Microsoft Office.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by a
remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Microsoft Word that
is affected by a remote code execution vulnerability due to a flaw in
parsing Word documents. This vulnerability can be triggered by
tricking a user into opening a specially crafted Word document.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms14-061");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a patch for Office for Mac 2011.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2011::mac");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2023 Tenable Network Security, Inc.");

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

  fixed_version = '14.4.5';
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
