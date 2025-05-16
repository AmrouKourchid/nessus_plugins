#TRUSTED 91024c2fb2afe4bb8851098681653cf8a20264ae0749f4a449f6f9b0b00c0eacc60db757b67708ead5840bce7ab261dd37d7e2f5db51910451833608bc3ee4d30c410cd31b0de3e0bef3d9de09e4e9ea3456e0f01aa1648759819e7d9d6a68765ae0be3fee553618e6f157d7252a5ff96dbdd638f50c61b476b84636f2217f383133e82e7c4cf13be54584b7259520b6bfea6625104f8c456c58920a098dcd6a84e9014424cd7e628617fb92284d69279b13b056654cb04346f8d041092619260112e6125ea46eef10de7dce774b7bfedd8989af2ae231a8d0f1c488e1819768530601521b141e1c0698aa1d6f5155075a6a2c458b21461f96b0b3ec32cc9442d5439f7de39304b47c7089e41378d11668e27e1e90a3418ab453a13fe2844c183bf1afc0120d25800bd82abfc692fac0a0d550d5290e342e0737d8e351b20ad53a49d51621652899a5da1cf201b44f34d52c75ef0bb9ccb8c7a532f1d59bac6170cfbb03c25e4f23a5e1e491ae5eafad616f523d5cf4a2a39b48229ee71edfe31631d3c38a253f720510708f34bec5eefebccaaf591b120256ec1689162a8d454174e1fa3a8e9cbd322a93c8e495f1e02e9499b1f7d4ba37da19c0f7ef6b67a71557938384c87236fe8672bd7105abda725389cf3b4e1d33294d6be417a743e4243bc849721b56f6b0bd5a67b043e9c71c0bedc93c22c42ad16967bfc90bd738
#TRUST-RSA-SHA256 04be2975d2850aea3eb29fc19bfc93b4677cedca922a3dfda4c076645939213b832dbaf2ddf8286ac934e8631965f161fef9c531463f6cd7183e50eae732d168bc03471228b91005abecf9ecf76baaccdd902c53be2ff05ae665df8181d0199be55ef0a40cc2f4153aa2320e017e20728efe02d0c772a8461dbe56d4f436adaa00adf22bfa84d6b1ea5ca0bf27ac200b4290675461aced49b826bd46679175498a348e92d65d186f99a915ed4eff3144616bf0b46898ec6a6a9991ff8cf6d1fb58b0396bb49208c77dfc7a33c539e5ac987483577e441436678b2dbe8b4732463ccfad69830adfce7f75e43ae5a5dbeda7dfcfbfca96c41ddcbf4ab23602193178d7cc57c0dc72b73831625ecc1c9409f9b9d50373df680a70ddd505b70d7d2f9a365f6ab418253e9541dff5795ccd33710e4b2577e92001eb49e40a6c8495142c626f0f14933a71c0585681c117144ce11eff7358cd5e76ba903c8c6d28d15c791e3e039f12519d04f3be94ccaf0195f83d5dff7f65d4f005530c16469d693a07fc96069462f7326b6b4dcd172050b9c04124e091d9ecb7a2a8cc72a648337dc22620274b3c82c9edf6e57e0457e5c913846b8366bee1731ef68fdcaa2c84b0836da5f4e897d52ac234fc7f125a5b0e04bb89eebac0a0c9c680c6745663dafe066bb68e38a1e124603bb0b6c845260b8bd96d417eb0ac85c413c74bf805c914
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85878);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_cve_id("CVE-2015-2520", "CVE-2015-2523");
  script_bugtraq_id(76561, 76564);
  script_xref(name:"MSFT", value:"MS15-099");
  script_xref(name:"IAVA", value:"2015-A-0214");
  script_xref(name:"EDB-ID", value:"38214");
  script_xref(name:"EDB-ID", value:"38215");
  script_xref(name:"MSKB", value:"3088501");

  script_name(english:"MS15-099: Vulnerabilities in Microsoft Office Could Allow Remote Code Execution (3089664) (Mac OS X)");
  script_summary(english:"Checks the version of Microsoft Office.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by
multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host has a version of Microsoft Office installed
that is affected by multiple remote code execution vulnerabilities due
to improper handling of objects in memory. A remote attacker can
exploit these vulnerabilities by convincing a user to open a specially
crafted file in Microsoft Office, resulting in the execution of
arbitrary code in the context of the current user.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms15-099");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released patches for Office for Mac 2011 and for Office
2016 for Mac.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2011:mac");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2016:mac");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel_for_mac:2011");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel_for_mac:2016");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

# Gather version info for Office 2011
info = '';
installs = make_array();
office_2011_found = FALSE;

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
  if (version !~ "^14\.")
    exit(1, "Failed to get the version for "+prod+" - '"+version+"'.");

  office_2011_found = TRUE;
  installs[prod] = version;

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  fixed_version = '14.5.5';
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

# Checking for Office 2016. The same path for the overall install
# doesn't exist for 2016, so we need to check each app, as each one
# is listed as needing an update to 15.14.

apps = make_list(
         "Microsoft Outlook",
         "Microsoft Excel",
         "Microsoft Word",
         "Microsoft PowerPoint",
         "Microsoft OneNote");
fix_2016 = "15.14.0";

office_2016_found = FALSE;
foreach app (apps)
{
  plist = "/Applications/"+app+".app/Contents/Info.plist";
  cmd =
    'plutil -convert xml1 -o - \'' + plist + '\' | ' +
    'grep -A 1 CFBundleShortVersionString | ' +
    'tail -n 1 | ' +
    'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
  ver_2016 = exec_cmd(cmd:cmd);

  # check all of the applications
  if (!strlen(ver_2016))
    continue;

  office_2016_found = TRUE;
  if(ver_2016 =~ "^15\." &&
     ver_compare(ver:ver_2016, fix:fix_2016, strict:FALSE) < 0)
  {
    vuln[app] = ver_2016;
  }
}

if (office_2016_found)
{
    foreach app (keys(vuln))
    {
      info +=
        '\n  Product           : ' + app +
        '\n  Installed version : ' + vuln[app] +
        '\n  Fixed version     : ' + fix_2016 + '\n';
    }
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
  msg = '';
  is = 'is';

  if (! office_2016_found && ! office_2011_found)
    audit(AUDIT_NOT_INST, "Office for Mac 2011/2016");
  if (office_2011_found)
  {
    msg = "Office for Mac 2011";
  }
  if (office_2016_found)
  {
    if (office_2011_found)
    {
      msg += " and ";
      is = "are";
    }
    msg += "Office 2016 for Mac";
  }

  exit(0, msg + " " + is + " not vulnerable.");
}
