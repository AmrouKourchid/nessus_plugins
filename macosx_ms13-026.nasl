#TRUSTED 3dd1cccbe1d18be952be146213c39b98681f15f4b7eaa43042028ff46c21f048bc99886ac82eaf2509a184af6356daeddb1837d981d4b86671a77fe439fa831ad6fa9a9c55c38d3510599f4c2e1f02803c69760f4c199ee9f0c1446e4ae2ac7e6b8e3aff89182471b3b6e40b82d8ce2074f4261f23a3cc3920407110aafa9e87840e8068c92e8df59f2bf2a3ecfdb37913a6e6b79a59e7b36f78be297d101303136d248a93063fc7200063426148d2300596f663127746d849065edd4ab2e635d9342011616cd0d358e9699304dafa98c1d3d8773fadd46b19952fe0981171e2144b260873ad86f4850a51d942242e109515612967c85abfce3fb0b9973739e7a5037e09b2fc482f0f31f13b2a019eacbfe6ed94815ea1d2aabdcffca161056d2dd1daa43a52d434419353469debffeefc971a890c71756786555430a9a3426cccc3d016d621a2d34330ae51ef1bb49d671bf027da9333f2ac4020c7444fe95dcc6dd154acc07f4e199d416eb3a9bb41ec5eacc798d9562486b32f7c56b346b6cd74224f93de56260e7c5d6a8534b7dc7b538df1070122fe02bc5b933faac7ea97648b1e9deb0abf64db3bed5b4e29e5a73812acb636d13507b0759cd14f2ee3f3ec23b184155f4ae75340f719299b41331fb30aefca33112f0cb47d9209bad8b73114f5dfb650904f02e89c1ec268ecf31993131751d02c498c76edc66efb18
#TRUST-RSA-SHA256 2c3d1df1885faecb5aee4a05e5a0eb6944ce1e0903841cdb11a00a05d05d5133213b2e7b29bf671f6779309c129309621c8fd948e448f1bbe21613c11b6643dcf977945328cd736b5e79b288f351fcf1a3c0d9cd5261f2ecd0d66e0df0279f302d0028b36aa38d274072bc6f17deabcd5346fadbff0ce37e195ec0349ab7287210acd08fb4c27e79fceef8c207faa6646b0e9ec5c84d5ef616a4bcbab2007eb6a9ba20f49cf2069b310d87377ce6c0216436b843959342cb82e907ff097eed8540168fd87e01f3352dd960a41dc16762088f6922ff6b68670ba6755f0957c4d6356b28e11b5f1663a5632c72224e8e2beb1d8175fbb889ef742a09defa55b3e09fc4aff72a2ac2a9367ca5f4b00839056257d9e6eb3147f1afb5cad71eab192da5b7999d92d3dc2bddda24f4cd51131ba2a482d990624a2eb461646e5abdc9354f41fa1aedf4b74306343955cbbfb990c391c9cde94b81a863e12d92ad21909f8350d4ece52d75ece5f52613de41a550c32406fb5089e91fb8e4465e59706c7ea59e4840c63d22ae577ca238e81da063caade0bec173150ccf7827c6efcb911cfbad09f5be44eb8141a69605193dd9dc02099d4314817deac4814bcc367b64945ae4d711d841f36a32a04fa2fecc27e7b900f6f4702d0dfe010feeaa70bc94a1c6551a7a0ba74b891dc075e6e8accf8d875771c02dd21dfa857bfe434ec911b9
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65217);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_cve_id("CVE-2013-0095");
  script_bugtraq_id(58333);
  script_xref(name:"MSFT", value:"MS13-026");
  script_xref(name:"MSKB", value:"2817449");
  script_xref(name:"MSKB", value:"2817452");

  script_name(english:"MS13-026: Vulnerability in Office Outlook for Mac Could Allow Information Disclosure (2813682) (Mac OS X)");
  script_summary(english:"Check version of Microsoft Office");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by an
information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Microsoft Outlook
that allows content from a remote server to be loaded without user
interaction when a user previews or opens a specially crafted HTML
email message.  This could allow an attacker to verify that an account
is actively used and that the email had been viewed.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms13-026");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released patches for Office for Mac 2011 and Office 2008
for Mac.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-0095");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2008::mac");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2011::mac");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");



enable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");

os = get_kb_item("Host/MacOSX/Version");
if (!os) exit(0, "The host does not appear to be running Mac OS X.");


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

  fixed_version = '14.3.2';
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

prod = 'Office 2008 for Mac';
plist = "/Applications/Microsoft Office 2008/Office/MicrosoftComponentPlugin.framework/Versions/12/Resources/Info.plist";
cmd =  'cat \'' + plist + '\' | ' +
  'grep -A 1 CFBundleShortVersionString | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
version = exec_cmd(cmd:cmd);
if (version && version =~ "^[0-9]+\.")
{
  version = chomp(version);
  if (version !~ "^12\.") exit(1, "Failed to get the version for "+prod+" - '"+version+"'.");

  installs[prod] = version;

  fixed_version = '12.3.6';
  if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
  {
    info +=
      '\n  Product           : ' + prod +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + '\n';
  }
}


# Report findings.
if (info)
{
  if (report_verbosity > 0) security_warning(port:0, extra:info);
  else security_warning(0);

  exit(0);
}
else
{
  if (max_index(keys(installs)) == 0) exit(0, "Office for Mac is not installed.");
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
