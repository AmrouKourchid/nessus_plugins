#TRUSTED 1d61af8f28e631e25299603173e741ce6df15a4ade4adce28254dcd76f6440a6698420775fa12374e24755fe08450a95475756a8460dbbded683da1bdae50ef2762afb1efdf1333205064ac6a3d48e0d0f33deab11ac388480f5d70d50769cb18674229ba471388f62abea3d4eb6e1017d4fbf4a35e3ae3e0dd78aa71f4d5f5a0a4dee003d445832a7a379d67f1bc500704ad7adf19d9f4f4de8540e1b66ebe1a7c00839fdd3728e251c00be5f04ceaef3f82ae5b3a7f7830fb73699b5d7a82faf2d6dcd8499ef4fe2331b71780f7909a570da879bcc4602294f6edf807c7107a5c4e0f424ac5cd77ad476d84350dd1c2fc5ce14c9bff0065b8c5e636b5b3eb010c01b2c2ef2b1438d40e4eaf95a1b2d9501a053a964cb309c4a6b1c55b152a10ed8a5cfdad56e6aaecd2446565b47b8559c06ed69729dd4a1b8fd6f5774043b0406eee9f0c02a261133ef77eb6917b2eb1fee4de691fd50010741748014c686e4a001b27a3af0b10561fe3e3b2e52ceddaf3cb265a884f3d54e726be476dc826fe0a4c365f298f0e2e0a585e3586b1064a120258676e4d80ac12670bae8a1aa36e3cc033104e897a3c7ac1daf88ef7b558473e430428e6b910352ebb547e1e705aa89d1637e75284eccd381a3cc0f526f82ac2d254bd15ead6222cc17897aa4f53dc06ce9f37238e981d69c9c527f4b930fa82201c4f7eb47e3f7962b6189fb
#TRUST-RSA-SHA256 611eddc13f9f0e1303f10194458a6de28ed7acc1127483b960a62b206a00503def448e276699203c72d48bc1cd8f8b6cefc8fb3aa252361e1abfc5f34da708c6e6a272277a05488e408ee2f3ef41ae4d4a5a2a712ca9aa733f9162b60099f51fb41d42a5073ac856e25d962ac0144da14b71cf01e99ec6c7315988f05eda2629be9e60237f58275437ba31769300130cb184f74a1558a12a25ebdfd1a07b8ef8081350ae9dd087b13e43ef132e4ffc426089b7534502ee32fce6e3e14adb132b4e085ed219663e176850a3bbe0870e51a82456b412b5c500c28a980c3f6eb0b6514a715fffd890a4e452d1c6d8a32d67780ccbe27e5b3a29622b128024433769a0ee84bd6a269c172b1c6d4b29cdb75bf53e21732d275569f6ac09344a6915e3489fe4860e0bab1566536e431080719df692504be0c3362c2d7b28b4b41694bdbbb4e6efb1ac975d5ac4a38fdf6bc7e7b16af3e62f02351cd9b49c4a81a70821142bd59323bc74e93df001da5d640d604e70a63edb510b3d889d2ad82096d35df723a3807bac0f5da4c223ad11a089ca7d73732e7dbe605961b7792ba9a313cb11e9afd92806e452597199d95ae7b0bd3111153a52cbdde09aa8d2148fd2c4c8ff3bfebc484349afb2218d8d2c6485f64bda1f79da6589411cf760f64af7e72fe978080409ec7e58c14768ca80db48d3cb369f9f8a432cf0bcbea15ca1bc2f69
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(70301);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_cve_id("CVE-2013-5163");
  script_bugtraq_id(62812);
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2013-10-03-1");

  script_name(english:"Mac OS X 10.8 < 10.8.5 Supplemental Update");
  script_summary(english:"Check the version of Mac OS X");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host is missing a Mac OS X security update that fixes a
local security bypass vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running a version of Mac OS X 10.8 that is missing
the OS X v10.8.5 Supplemental Update.  This update fixes a logic issue
in verification of authentication credentials by Directory Services,
which could otherwise allow a local attacker to bypass password
validation."
  );
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5964");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2013/Oct/msg00000.html");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/528980/30/0/threaded");
  script_set_attribute(attribute:"solution", value:"Install the OS X v10.8.5 Supplemental Update.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/04");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
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
if (!ereg(pattern:"Mac OS X 10\.8([^0-9]|$)", string:os)) audit(AUDIT_OS_NOT, "Mac OS X 10.8");
if (!ereg(pattern:"Mac OS X 10\.8($|\.[0-5]([^0-9]|$))", string:os)) exit(0, "The remote host uses a version of Mac OS X Mountain Lion later than 10.8.5.");


# Get the product build version.
plist = "/System/Library/CoreServices/SystemVersion.plist";
cmd =
  'plutil -convert xml1 -o - \'' + plist + '\' | ' +
  'grep -A 1 ProductBuildVersion | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
build = exec_cmd(cmd:cmd);
if (
  !strlen(build) ||
  build !~ "^12F[0-9]+$"
) exit(1, "Failed to extract the ProductBuildVersion from '"+plist+"'.");


if (build =~ "^12F([0-9]|[1-3][0-9]|4[0-4])$")
{
  if (report_verbosity > 0)
  {
    report = '\n  Product version                 : ' + os +
             '\n  Installed product build version : ' + build +
             '\n  Fixed product build version     : 12F45' +
             '\n';
    security_warning(port:0, extra:report);
  }
  else security_warning(0);
}
else exit(0, "The host has product build version "+build+" and is not affected.");
