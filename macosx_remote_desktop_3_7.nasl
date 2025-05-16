#TRUSTED 37cdad14f8d6f36691f1f53e739c8830af345ffb1d478dfc8553afba537fee7a4754f244ca458d86cc912c5a55c9190a89e0addd02c20c62760760ecd41aff5ab1b6744373a76c30726a87d9d3bbf8d8690b508d4761b7bf7c17028a6b8457bac1dfe06b9f0056df44effdd89070ad019849219fe4cd21a7b608a9fa6bdbbce8a4f8f35da523ae6ab0265d6fcc8c74d48d1aca08e0b630951dfd4a7a3e01c338f192e28813b756bcb0cc38fdd219a5a2128cd8c8a7267d8483422b2fdf6bd3cad9d9f196dcc0c19ea442dbe2816fa42616144087d1b8f1a5086a210c71d1fc01fb1da9adb40c7d9fd4cab490b761d25857ac9e456ccc0845413cf634971031bbf54872661325d6233934e14e7edfe995744c6b2606c5e873fd98356f2d7490ca93238cef2fed864175a662037bdb2015861afaaa6da9c3a1a27f954ea412d797196652f19ebb8336c7f67db0aea6c06494fd342beeb10ef9dac97f807e20e7e3438180a51c799e3bb5cf3bf4f336b77bdc14b4d21f63780b1533587df00ae3f8efb596e4721cbc98a0dd4ceb0540bafababb1abb3513a875b623e5933a57c83d91185cb17bc382123ce5d46a92c18c63743a7e3e247dffb904b4a27cb156b7db856c20d1fef8dfe90fe1d0550a0e444a3ac9a0a1c5cfc50329aaa295d058740c5784a51289d637a72e1e6962bfd3cc06f3481d6acf421237b225bf7befba674f
#TRUST-RSA-SHA256 1dceab3310909e2f0ca237862341ffb51ba7f3597eca1a5e9230ffe73a63c4ffaa4b8b99be536f4716b4af84b1b98ce1e01cb27071dbd977496686f5c7afd92b2ff2e5a43f31e6023ed133ff8f74cce4ecb23a3bfce18951ab6ae2a9b3368e39e9eed5482f46d927fdc0f00e86a7c9aa035f9d85f03be2f60d3ceb77914cee1456bc014f2d10c210e99240e9d6c8d772974897c47ac7218590d11a4de598c38ac300e529ce0c39128bd51069c2795d6535a1c3651479a541054245173b293c297a9c0453e311dfce64578fdb2b13d186ce241027dcf6505c5b283db8f1b7cf8422d17e46e1087dc43f3846d38914ae7061ffb88e3f2634dfeff5430cf4ebab5dde1e5d1d66bd38876b1d79071c5648e656af6040d852fd58b0c43478db7da3f91a70fca1801e7a387251e8da691957e5ce9bb840afb9c486ce3e772fc7bb35f8b4b1dfcbe7b2bd53bc1d323b1c72bc61c328679573a22ab5e237f2008fa41e330519a462a9f2464f1c068bfa308a734c723611f3aceb716a5073b224ad42cadb51fecc13bc18713e45dd968d486a196f42d07e75b811d8f78d54f986a8d41adddf32fe1011adeccc7b613bd31bb33f44484369fa10b1bf790ed94e6ab418badbcf464fda6760783b33f95ca9c3a2fa140b15f6e3669caeb5b6f0087f3948f0a71eeabad01337607a0e9889d63ed41131f7c0ac63427c41ef5330ada7e4d72ca7
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(70609);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_cve_id("CVE-2013-5135", "CVE-2013-5136", "CVE-2013-5229");
  script_bugtraq_id(63284, 63286);
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2013-10-22-6");
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2013-10-22-7");

  script_name(english:"Apple Remote Desktop < 3.5.4 / 3.7 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Reads version from Info.plist");

  script_set_attribute(attribute:"synopsis", value:
"The Mac OS X host has a remote management application that is
potentially affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the Apple Remote Desktop install on the
remote host is earlier than 3.5.4 / 3.7.  As such, it is potentially
affected the following vulnerabilities :

  - A format string vulnerability exists in Remote 
    Desktop's handling of a VNC username. (CVE-2013-5135)

  - An information disclosure vulnerability exists because
    Remote Desktop may use password authentication without
    warning that the connection would be encrypted if a
    third-party VNC server supports certain authentication
    types. Note that this does not affect installs of
    version 3.5.x or earlier. (CVE_2013-5136)

  - An authentication bypass vulnerability exists due to a
    flaw in the full-screen feature that is triggered when
    handling text entered in the dialog box upon recovering 
    from sleep mode with a remote connection alive. A local
    attacker can exploit this to bypass intended access
    restrictions. (CVE-2013-5229)");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5997");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5998");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2013/Oct/msg00007.html");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2013/Oct/msg00008.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple Remote Desktop 3.5.4 / 3.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-5135");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:apple_remote_desktop");
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
if (!get_kb_item("Host/MacOSX/Version"))audit(AUDIT_HOST_NOT, "running Mac OS X");

plist = '/System/Library/CoreServices/RemoteManagement/AppleVNCServer.bundle/Contents/Info.plist';
cmd =  'plutil -convert xml1 -o - \'' + plist + '\' | ' +
  'grep -A 1 CFBundleShortVersionString | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
version = exec_cmd(cmd:cmd);
if (!strlen(version)) audit(AUDIT_NOT_INST, "Apple Remote Desktop Client");

if (version !~ "^[0-9]") exit(1, "The version does not look valid (" + version + ").");


if (
  ereg(pattern:"^3\.[0-4]($|[^0-9])", string:version) ||
  ereg(pattern:"^3\.5\.[0-3]($|[^0-9])", string:version) ||
  ereg(pattern:"^3\.6(\.[0-9])?($|[^0-9.])", string:version)
)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Installed version : ' + version + 
      '\n  Fixed version     : 3.5.4 / 3.7' +
      '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "Apple Remote Desktop Client", version);
