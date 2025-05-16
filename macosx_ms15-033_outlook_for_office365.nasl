#TRUSTED 741420f51d0741afa64401bb2b1791c95f56adfe2ec357d39f3bbf6cd34a9478321223c5efbaec19b696dcb30698feb09de9e6485262786c16550e31d8f0f9977f71b447fb9fa1c7626a80451a57a6d140c2b81d37501af98ce33374dfb73a68a204ba9d353ee3fb55e2863d9869506f443472fdef306b635ff2c716158096e11d5d58883455c6d942ee0d448624c473c56cc7156405caaf99e20db686144cccd65f00f9ad97acff64de3d3a50f52e3d8b2d1dec7e34364b57a0b8398b4d35f771915ba16455534f4faa9a991dff07214a4bc67ec5138d1f0532642e24e6e9728fe790faa482022c3977f68605fb2a26d0a51b61c10687ddce49f57dfc7d7866becf0b67b1b1ad612c4d54d6bdeba37afbeb9739706b7457c2f8758e794b1481da527069d463c973b90b059110866cd7a82d84d1a3033534cb88976d345103ca88887b018eeee52ca6a7dc9df3294e06712b75923ff852a0f847206f29f7d67e3c543f07bd4c130f9aa8722965e72fe0ce53d4df558045212fd263f586ce2375c56ca762713fcbc0abed2efb844ce5ed000a001b74477a4936767037464ed887a9a97cccf062cd9d037322246a04e2bb1f3ce0b69cd97be391849f1947a42dbfa2ca8a44526e9a900838a0dd0bea093240ae712e57f226f73051be57400e48abb00a4b635010f6b1021eafbaafa11a2a8ab31ab96244815f002031c92a3defbc
#TRUST-RSA-SHA256 a28df1aed1877ec1e2e2fb728e1388f5704f64d056d97286e81d7a75867bafb7440b5f0b0d0f8125032a40ea41a37af7337ad7b974ec912b27edd3408bdc6c1deada08e0515bc33968723d4e48193d903100f4824c84e683cf9121814ac4df4afa24122a0cdb80da0a8a753b1c1f2acac85cef5d5fcca421569ae8a6b0419ccbdf946c00ee201d19103db6a642e435e3a69389bd2e873ac83065d11db36da9090171b638ab57e622af58c00c8b949c5bc6f98f1d2a1a7e3d965a5a6a59a0e59144e231e60536874ce59fb9ae95105446570b872986b403ae0eca8c93c1e6bb540afacf27c1f8386e0c6d2e2221ec25fe7062fb77a77a39a0c63f0ca93bf85264f4836acec64dc08ea0a95bac058736c2b3c94b25c333418fb375b1e0aa409ec6bdf9a527df1dc217ce92ebd86287f9f242569900aa5f70d3364c84e81a6d67fcd818bed9c52398dcec6fc4326ab3c6a0b8e5f1a108b8986511ba03c8e9ff3091a7b8f41cef81e1b7b751d60258909e2e7826c6d19ff57baac416df57865e5527e8fc263a24964f2583a068985c00e355850ea2ed2b0a1e289ad4b64665d87b5019136f30c7fbf890cd4460fb748aa4791478a9ae48a49830f6721490ab3f90401902fe7ca87fb3a53aa60d6e796f07754232b763b6e5cefbad5cfa7c6e5437503a7773972e49c5fa2bf1aad7e386cc6c39dd254c79ece145bb3ab2a79c4e35ed
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(82768);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_cve_id("CVE-2015-1639");
  script_bugtraq_id(73991);
  script_xref(name:"MSFT", value:"MS15-033");
  script_xref(name:"IAVA", value:"2015-A-0090-S");
  script_xref(name:"MSKB", value:"3055707");

  script_name(english:"MS15-033: Vulnerabilities in Microsoft Office Could Allow Remote Code Execution (3048019)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by a
cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host has a version of Microsoft Outlook
for Mac for Office 365 installed that is affected by a cross-site
scripting vulnerability due to improper sanitization of HTML strings.
A remote attacker can exploit this issue by convincing a user to open
a file or visit a website containing specially crafted content,
resulting in execution of arbitrary code in the context of the current
user.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms15-033");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a patch for Outlook for Mac for Office 365.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:microsoft:outlook_for_mac_for_office_365");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2011:mac");
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

# Gather version info.
info = '';
installs = make_array();

prod = 'Outlook for Mac for Office 365';
plist = '/Applications/Microsoft Outlook.app/Contents/Info.plist';
cmd =  'plutil -convert xml1 -o - \'' + plist + '\' | ' +
  'grep -A 1 CFBundleShortVersionString | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
version = exec_cmd(cmd:cmd);
if (version && version =~ "^[0-9]+\.")
{
  version = chomp(version);
  if (version !~ "^15\.") exit(1, "Failed to get the version for "+prod+" - '"+version+"'.");

  installs[prod] = version;

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  fixed_version = '15.9';
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
  set_kb_item(name:"www/0/XSS", value:TRUE);
  if (report_verbosity > 0) security_warning(port:0, extra:info);
  else security_warning(0);

  exit(0);
}
else
{
  if (max_index(keys(installs)) == 0) audit(AUDIT_NOT_INST, prod);
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
