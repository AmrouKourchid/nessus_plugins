#TRUSTED 9ad6e3c6d011a31c53dcbc0655769a6cc100bb0e6918276531ea1b2c7b9cd220eae7aa8b0c69ac7ddb73be0763bd489058d15836a31d66a93970d6bba2dcf9f0966c6a342627f44a991ac9246e0df2d8e9cccf14e37fa171aeddcd143985612b8ce07d0d97e4ceec99e7388614ae463c609181381d6394f08fd661d69c840cf4b1db78c2d7c3649bb48a2c163073993601cfb0bc50ce748afec050e808d3d79c520272698eaba761f4bd8b45b557d8e98c49397e1a42d42a0ec32cf597260681df41e1f774880f4c60ba0de2abd5e1f901aed9d2d4dbaeb1935e0faff62890ade0395cefd0d37b582f02965799f9bb415254fd6a2b69bc4ca63a48ff9aea664b8ad197ad2fe1bf07c09dea7b7fb621907baf78a9219c229b95f6486cc0d98d22b4b676bc087199b42e4ce13e24544c57c99c58c6c18132bfc0510c1315159113fee9b8bed18c67a9b2c0728c0f2cb0bc30406088bc5936a069349fbba270cd26f178999be082f0e160ca3a64566e3aae634ff1c12d91207762ca15fa7fba06ffda10311d2656def2e28ce07a626b3733df06230bc00492ed9af3c73c2a46523ab5d4ee0d752b40108e4e720c00b56a9811d4b84241e5bdf50105a4eb0044162369b996b591c19d06891a2030e26a8a4868593f78fd052526a39c450220f18ef9d609137e09d22fe8bc92ad1e8bb090efdd54b9d3546ee5a51d30685f7e2056d9
#TRUST-RSA-SHA256 a7383c6fa422ae93e1be3520caf3bf9dd523652362fbcc002959db8b319ce01446514d59facc4c9e27aae9cf66ed9475b90fabfc37cfa20f18e8a9accf00e22d2e583f9ad3751b67d7d2d152882bccf74a7ff0626d1e343cb247cc02f9bed76d2bdea0409e081879803910e0c66ac583cd83a412a701323c1de7dd14658ffa9dc43848317aed687f32cf39c76bb6ff2110e310464d2acb51ff942ea19bf4c866745728494c81b76b91da586e5669ae107c76d2232d7dec1cc59f759fd95b9f89857ddf58f15bfb4a6a9cc9cd003edc1f6638acab4a23e14ca8bf2438c0d0c132959ade94322acc2bd343cbbf75291a939e99bb9d1824f5c24f21e19c410e9b7b931d886f3d7a667c71dcac8d10d2218180f0499bec5257aa8000283ab8270636596f651435738fff25e1cf4d865ef3cca7a64c6d17b9038ed5b98dd819bff8141202f769def6889b05b42a9c3e091c0abc1c10f20db765822e8eceecc370e337196d138f943c50fec72127f74af489c3964279a983ebb3dc5e1e8a3f1fed896730aea5a04de000c87ed5f29c8118ca3ed90dfbf1204e6d83ebf12e4ec23e2b54d605a3d4e75c3a9e7487b940135facf8fd918cbc92152b2cc68419e3db6fc980989474b8fa9fb16ec4f9efa66a495faf6c4cb120398e9e70ef7abd2adc57d5591c5822743f1a3b5e46288450938409a26519a193316c4d5ab22ff2e907913bb0
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(52587);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/24");

  script_cve_id(
    "CVE-2010-4422",
    "CVE-2010-4447",
    "CVE-2010-4448",
    "CVE-2010-4450",
    "CVE-2010-4454",
    "CVE-2010-4462",
    "CVE-2010-4463",
    "CVE-2010-4465",
    "CVE-2010-4467",
    "CVE-2010-4468",
    "CVE-2010-4469",
    "CVE-2010-4470",
    "CVE-2010-4471",
    "CVE-2010-4472",
    "CVE-2010-4473",
    "CVE-2010-4476"
  );
  script_bugtraq_id(
    46091,
    46386,
    46387,
    46391,
    46393,
    46394,
    46395,
    46397,
    46398,
    46399,
    46400,
    46402,
    46403,
    46404,
    46406,
    46409
  );

  script_name(english:"Mac OS X : Java for Mac OS X 10.5 Update 9");
  script_summary(english:"Checks version of the JavaVM framework");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has a version of Java that is affected by multiple
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Mac OS X host is running a version of Java for Mac OS X
10.5 that is missing Update 9.  As such, it is affected by several
security vulnerabilities, the most serious of which may allow an
untrusted Java applet to execute arbitrary code with the privileges of
the current user outside the Java sandbox."
  );
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT4563");
  # http://lists.apple.com/archives/security-announce/2011/Mar/msg00002.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c22bc603");
  script_set_attribute(attribute:"solution", value:"Upgrade to Java for Mac OS X 10.5 Update 9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2010-4473");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/02/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2024 Tenable Network Security, Inc.");

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
  local_var ret, buf;

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


# Mac OS X 10.5 only.
if (!egrep(pattern:"Darwin.* 9\.", string:uname)) exit(0, "The remote Mac is not running Mac OS X 10.5 and thus is not affected.");

plist = "/System/Library/Frameworks/JavaVM.framework/Versions/A/Resources/version.plist";
cmd =
  'cat ' + plist + ' | ' +
  'grep -A 1 CFBundleVersion | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
version = exec(cmd:cmd);
if (!strlen(version)) exit(1, "Failed to get the version of the JavaVM Framework.");

version = chomp(version);
if (!ereg(pattern:"^[0-9]+\.", string:version)) exit(1, "The JavaVM Framework version does not appear to be numeric ("+version+").");

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# Fixed in version 12.8.0.
if (
  ver[0] < 12 ||
  (ver[0] == 12 && ver[1] < 8)
)
{
  gs_opt = get_kb_item("global_settings/report_verbosity");
  if (gs_opt && gs_opt != 'Quiet')
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 12.8.0\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else exit(0, "The remote host is not affected since JavaVM Framework version "+version+" is installed.");
