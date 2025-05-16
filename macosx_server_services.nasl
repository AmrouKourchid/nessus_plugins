#TRUSTED 737474d5bdfd96f39cc00657c100bed1d33e6abf778e3569da0ba6d77567a77c792d458ec4730cd3e2a669f863e5a43e1c3e9bec3a64874396ca13abd9c4fb5557748dfcc7bdbe9ce5831f6854f42a32734641ae179836e0006697d76398e943df61f358beeac32f74742d17013ea9ea330643e1d8e9284c67fbb2539918ff2d85022773907a74c80c8497a1990d98d56a81a373ca7074dc1dfb81c8560758d2ba91cd1ce43eba25c8319a9ee22275e3931fcd58107535473e1e3b572178a7227d5ba2f2b01691212111873816cd3ae6ad5f6c56eb7de15746b0c73e5882e9cd4b2c3f6e54a4f54a1767d402fda23749199da2159ef7c32fbb9f181d98781315a36e0c03cf2281597a6bbd3eb927a4cc23982cf504e8437c38b16a9345018e692242742079b72c79ef61d3c192b27426ba61ea8eb559b78ecf298b7e6e6e6b73229f38d545afa5697272b252da7144d0b2d742d341d5349758e731a795a2a27467903f88ce2412840382fc8b7655957c070d63f3441f43ba8825970ec1df8b191d5995dfff32cfefcb87ba06ac88ea4c4084f413b9ec895098c7c85a5bae27837a292755f38e32528660d337b303e15dca4dace733f110d676184f0a2514610a1254d48c366646c6115a2744b05fc7c1b618ff5f3510f5eea86604957f6b2ab25aea3cc4ea8ee9251a615ea998b177e9247453f3f89200f054501938a71cecbf
#TRUST-RSA-SHA256 1abd0e1ff747f26f01d1e7b801c16ce1aba9c3643586d8ab0e860c8d2d5209aac7c428f08e375ec5f77162f15eec800a819262a1ddbcc1a7f0abca109363c19d8ec2a055c0fb9d1399bda5a44670fd99f2822e421ad2a988d88b12b2969a047b49d41c5cbf6e22e8a70ac94dac6ec72dacaccdcc9795e87f5551d733570d7cb22e08a7fe1cf40954bb59ba5509723150b733fe200d28c742599ccf7b7d686dc41d956bdfacffe1c6ead41d1ee5ebf219fded7e46e8775643cf664236edffe8e6bccad9d01db3ef7dd984af9567ea10ef5be5d0d7bc21031ee26835b58821c82c40022db74fdf55f9203f07000d67492fd3f92a505fcc51b79b2fd27bdd6c9aecb5cd93b12d72bb676ae2fce6023b2cdb1b54fc7eb093d33b3d199414baae95fb82707eaf957f3affdbbfd0a36949d0b9872ef31faa3c3433acbdccaa81379a951afe05dc563f23b6a747d7deb342cf8441e7495f9e1e63492d3f3c47cdb592f2d9d0c084a88909b3c1405dd8e04aa6694301911635941e4766035ccdc4d73b755386120cba160f863a5f2c83a322350bb9917728c51ff9c81a3081fdbac43d46a3614cadc0e915b2d293637dde7fb9174134c2e63cfee4d409d9d887de5fcd2951884f8d9f30ba19dab8ee4952668b19a9786983e0a4c4fa0e81a8d4fa70a9b9883db6eb1b783e9ba3b769a5024fbbbff3a1533a1c7963d61ad7730440e6088a
#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);


include("compat.inc");


if (description)
{
  script_id(50680);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_name(english:"Mac OS X Server Service List");
  script_summary(english:"Report list of installed services");

  script_set_attribute(
    attribute:"synopsis",
    value:
"This plugin enumerates services enabled on a Mac OS X Server host or
a host running OS X Server."
  );
  script_set_attribute(
    attribute:"description",
    value:
"By connecting to the remote host via SSH with the supplied
credentials, this plugin queries the Mac OS X Server administrative
daemon and enumerates services currently running on the system."
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Review the list of services enabled and ensure that they agree with
your organization's acceptable use and security policies."
  );
  script_set_attribute(attribute:"risk_factor", value:"None" );
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:mac_os_x_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2010-2023 Tenable Network Security, Inc.");

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


# Get the system version.
version = "";

# nb: OS X Server is an external app starting with 10.7.
if (ereg(pattern:"Mac OS X 10\.[0-6]([^0-9]|$)", string:os))
{
  cmd = '/usr/sbin/system_profiler SPSoftwareDataType';
  buf = exec_cmd(cmd:cmd);
  if (isnull(buf)) exit(1, "Failed to run '"+cmd+"'.");

  foreach line (split(buf, keep:FALSE))
  {
    match = eregmatch(pattern:"^ +System Version: (.+)$", string:line);
    if (match)
    {
      version = match[1];
      break;
    }
  }
  if (!strlen(version)) exit(1, "Failed to extract the System Version from the output of '"+cmd+"'.");

  # eg, "Mac OS X Server 10.6.8 (10K549)"
  if ("Mac OS X Server" >!< version) exit(0, "The host is not running Mac OS X Server.");
}
else 
{
  plist = "/Applications/Server.app/Contents/Info.plist";
  cmd = 
    'plutil -convert xml1 -o - \'' + plist + '\' | ' +
    'grep -A 1 CFBundleShortVersionString | ' +
    'tail -n 1 | ' +
    'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
  version = exec_cmd(cmd:cmd);
  if (!strlen(version)) audit(AUDIT_NOT_INST, "OS X Server");

  # eg, "2.1.1"
}


kb_base = 'MacOSX/Server/';
set_kb_item(name:kb_base+'Version', value:version);


# Get a list of services.
cmd = 'serveradmin list';
buf = exec_cmd(cmd:cmd);
if (!buf) exit(1, "Failed to run '"+cmd+"'.");

svcs = "";
foreach line (split(buf, keep:FALSE))
{
  if (
    ereg(pattern:"^[a-zA-Z0-9]+$", string:line) &&
    "accounts" != line &&
    "config" != line &&
    "filebrowser" != line &&
    "info" != line
  ) svcs += " " + line;
}
if (!svcs) exit(1, "'serveradmin list' output failed to list any services that can be queried: " + buf);


cmd = 'for s in ' + svcs + '; do serveradmin status $s; done';
buf = exec_cmd(cmd:cmd);
if (isnull(buf)) exit(1, "Failed to run '"+cmd+"'.");

info = "";
foreach line (split(buf, keep:FALSE))
{
  if (match = eregmatch(pattern:'^([^:]+):state *= *"?([^"]+)', string:line))
  {
    svc = match[1];
    status = match[2];
    set_kb_item(name:kb_base+svc+"/Status", value:status);
    info += '  - ' + svc + crap(data:" ", length:15-strlen(svc)) + ' : ' + status + '\n';
  }
}
if (!info) exit(1, "'serveradmin list' output does not contain any service info: " + buf);


# Report findings
if (report_verbosity > 0) security_note(port:0, extra:'\n'+info);
else security_note(0);
