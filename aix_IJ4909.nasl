#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(209560);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/23");

  script_cve_id("CVE-2023-3341");

  script_name(english:"AIX (IJ4909)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AIX host is missing a security patch.");
  script_set_attribute(attribute:"description", value:
"The version of AIX installed on the remote host is prior to APAR IJ4909. It is, therefore, affected by a vulnerability
as referenced in the IJ4909 advisory.

  - The code that processes control channel messages sent to `named` calls certain functions recursively
    during packet parsing. Recursion depth is only limited by the maximum accepted packet size; depending on
    the environment, this may cause the packet-parsing code to run out of available stack memory, causing
    `named` to terminate unexpectedly. Since each incoming control channel message is fully parsed before its
    contents are authenticated, exploiting this flaw does not require the attacker to hold a valid RNDC key;
    only network access to the control channel's configured TCP port is necessary. This issue affects BIND 9
    versions 9.2.0 through 9.16.43, 9.18.0 through 9.18.18, 9.19.0 through 9.19.16, 9.9.3-S1 through
    9.16.43-S1, and 9.18.0-S1 through 9.18.18-S1. (CVE-2023-3341)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/7099313");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/apar/IJ4909");
  script_set_attribute(attribute:"solution", value:
"Please apply the appropriate interim fix per APAR IJ4909.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-3341");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/09/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"AIX Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/AIX/lslpp", "Host/local_checks_enabled", "Host/AIX/version");

  exit(0);
}

include('aix.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if ( ! get_kb_item('Host/AIX/version') ) audit(AUDIT_OS_NOT, "AIX");
if ( ! get_kb_item('Host/AIX/lslpp') ) audit(AUDIT_PACKAGE_LIST_MISSING);

if ( get_kb_item('Host/AIX/emgr_failure') ) exit(0, 'This iFix check is disabled because : ' + get_kb_item('Host/AIX/emgr_failure') );

var constraints = [
    {'release': '3.1', 'ml': '04', 'sp': '10', 'patch': 'IJ49093s7', 'package': 'bos.net.tcp.bind', 'minfilesetver': '7.2.5.100', 'maxfilesetver': '7.2.5.101'},
    {'release': '3.1', 'ml': '04', 'sp': '10', 'patch': 'IJ49093s7', 'package': 'bos.net.tcp.bind', 'minfilesetver': '7.2.5.200', 'maxfilesetver': '7.2.5.200'},
    {'release': '3.1', 'ml': '04', 'sp': '21', 'patch': 'IJ49093s7', 'package': 'bos.net.tcp.bind', 'minfilesetver': '7.2.5.100', 'maxfilesetver': '7.2.5.101'},
    {'release': '3.1', 'ml': '04', 'sp': '21', 'patch': 'IJ49093s7', 'package': 'bos.net.tcp.bind', 'minfilesetver': '7.2.5.200', 'maxfilesetver': '7.2.5.200'},
    {'release': '3.1', 'ml': '04', 'sp': '31', 'patch': 'IJ49093s7', 'package': 'bos.net.tcp.bind', 'minfilesetver': '7.2.5.100', 'maxfilesetver': '7.2.5.101'},
    {'release': '3.1', 'ml': '04', 'sp': '31', 'patch': 'IJ49093s7', 'package': 'bos.net.tcp.bind', 'minfilesetver': '7.2.5.200', 'maxfilesetver': '7.2.5.200'},
    {'release': '7.2', 'ml': '05', 'sp': '05', 'patch': 'IJ49093s7', 'package': 'bos.net.tcp.bind', 'minfilesetver': '7.2.5.100', 'maxfilesetver': '7.2.5.101'},
    {'release': '7.2', 'ml': '05', 'sp': '05', 'patch': 'IJ49093s7', 'package': 'bos.net.tcp.bind', 'minfilesetver': '7.2.5.200', 'maxfilesetver': '7.2.5.200'},
    {'release': '7.2', 'ml': '05', 'sp': '06', 'patch': 'IJ49093s7', 'package': 'bos.net.tcp.bind', 'minfilesetver': '7.2.5.100', 'maxfilesetver': '7.2.5.101'},
    {'release': '7.2', 'ml': '05', 'sp': '06', 'patch': 'IJ49093s7', 'package': 'bos.net.tcp.bind', 'minfilesetver': '7.2.5.200', 'maxfilesetver': '7.2.5.200'},
    {'release': '7.2', 'ml': '05', 'sp': '07', 'patch': 'IJ49093s7', 'package': 'bos.net.tcp.bind', 'minfilesetver': '7.2.5.100', 'maxfilesetver': '7.2.5.101'},
    {'release': '7.2', 'ml': '05', 'sp': '07', 'patch': 'IJ49093s7', 'package': 'bos.net.tcp.bind', 'minfilesetver': '7.2.5.200', 'maxfilesetver': '7.2.5.200'}
];

var flag = 0;
foreach var constraint (constraints) {
    var release = constraint['release'];
    var ml = constraint['ml'];
    var sp = constraint['sp'];
    var patch = constraint['patch'];
    var package = constraint['package'];
    var minfilesetver = constraint['minfilesetver'];
    var maxfilesetver = constraint['maxfilesetver'];
    if(aix_check_ifix(release: release, ml: ml, sp: sp, patch: patch, package: package, minfilesetver: minfilesetver, maxfilesetver: maxfilesetver) < 0) flag++;
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : aix_report_get()
  );
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected - AIX");
