#TRUSTED 30594de53d5fa0eb4ed8d216bd9b24c93bec8ab9002deac26e3059266ff31fbed52be2aecceb6b7bd2628b890e2ec04eda7ecb658b489a9c70b2edcdeaaa06d6d0d370c3853b16fb60ed5da9b6f7d2ccea0e3e34334eef3a7db3581c5af660f7c99f840cfffca4e2968cc4fc03c30bc5b2aaf80af4bed9eadb16024b0c3ff65fd9dfd38e400aa068ec77987eb4a93d208c3e73cfe10bd5db57e30ae9c715fb54a39dbc260b4e7893863b139a9293da7c9e15432f5369042bd8febff80b20562c6142003feea1881dba2ac14375d0ff4d8de733534a735e60c5efdd429a115068f1870e57dd0d06c994d619cce4302f1bca6fb57be8313e18064d20a2f522e9f996aa57823ce4fa74144e05d0b59936553ce56751177cf5cb887fd69c36254bad0722e934c2dfe3a554e7d257b0c90d59ac52794f61b11be8772af0e1ca4d2156e283d2ce42d0392224134d19e549f9b08214febdb7b707b92b3cfa32802129a0d64ebb954ec014cbb32233ececff5acb4a23b4b3e555c0069bce267ac95cb22239821b5231f54ec4489c08eaced1f81b52980c324d24b54b27e7da4be238fa3d2976852556912e1130295bb42a420617fe4105e4694464da64b5597bb9df79fbc5f05a98c3a9898c1d9587c770ffcba8ffbbcc73843fb7dbbc7b68527f6fb7b012a8ec8dd5f07b5bd22d49d81dd5a9426da9dae92bb6cf9d9dcd680a18b09422
#TRUST-RSA-SHA256 1bbfff77efa6c35e0a2d14c0e56f51da7539d00f7356988d1a65d66d5c38c611c86d2609a88c6cd2709bf3ad6ebb551b3f0b422f25fa994d449f42aa360a4f4f5f5c0656c4cdb0927b5114a12bca174294be4e3ba66ba38f6a9b03d2f1f365cb67462c5d121a292115e3ea45c44923b60835e5497a984dcd0a1f604ce75d72b0de272e46e6e86a66d16ab05924cf7f2acffe4c8cee50acadf308544aa09d27a927864ff0a2111f2e9b85b0fda5345cb8427eb53aed3361f271ccf3b4aa32c757f6e5317075882903b07031bf58a4729f52cf9145e1f8b23c955bb69c2d9d824d48c2f570050034c29b4af7c845560cc823e4239b6e187c628c7d18c6c331c4e6e8c032a5291e46a873a38026b7401f4fea94ca5f55cb0b50dcaf7a070bdd2d6297d02f8017eb2fc7748a592b429668d89b3da83eb117b1f2e97ec170f0fc04a11c4cd122732bd8323a94515d653f1e0c537977fd3a8d8f246524da6ece84ede00f209128d92ffa4022c6bea29d1309d41eca0a7af3868b9e5f6e9d9a25efdebb71f30bd34687a5278e788a3053c3da2bcdf90990cbe8641ceedc11fbd459ce7c39bd50a36c7067a3c986ab43f71e4923fe54c81a8b33b49c364ae856e221bb76ef0073fd36b5cc076bda9fb7dabdb6b06e704cbdc1f2ea7d0214ebe0390352be77387b3e7944bc450f888bf44185e1557bc16bde26fabfbbdbe4033d584841a4
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69839);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_cve_id("CVE-2013-1315", "CVE-2013-3158", "CVE-2013-3159");
  script_bugtraq_id(62167, 62219, 62225);
  script_xref(name:"MSFT", value:"MS13-073");
  script_xref(name:"MSKB", value:"2877813");

  script_name(english:"MS13-073: Vulnerabilities in Microsoft Excel Could Allow Remote Code Execution (2858300) (Mac OS X)");
  script_summary(english:"Check version of Microsoft Office");

  script_set_attribute(
    attribute:"synopsis",
    value:
"An application installed on the remote Mac OS X host is affected by
multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Mac OS X host is running a version of Microsoft Excel that
is affected by the following vulnerabilities :

  - Two memory corruption vulnerabilities exist due to the
    way the application handles objects in memory when
    parsing Office files. (CVE-2013-1315 / CVE-2013-3158)

  - An information disclosure vulnerability exists due to
    the way the application parses XML files containing
    external entities. (CVE-2013-3159)

If an attacker can trick a user on the affected host into opening a
specially crafted Excel file, it may be possible to leverage these
issues to read arbitrary files on the target system or execute
arbitrary code, subject to the user's privileges."
  );
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms13-073");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a patch for Office for Mac 2011.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2011::mac");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

  fixed_version = '14.3.7';
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
