#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(232951);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/28");

  script_cve_id("CVE-2024-56346", "CVE-2024-56347");
  script_xref(name:"IAVA", value:"2025-A-0200");

  script_name(english:"AIX : Multiple Vulnerabilities (IJ53757)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AIX host is missing a security patch.");
  script_set_attribute(attribute:"description", value:
"The version of AIX installed on the remote host is prior to APAR IJ53757. It is, therefore, affected by multiple
vulnerabilities as referenced in the IJ53757 advisory.

  - IBM AIX 7.2 and 7.3 nimsh service SSL/TLS protection mechanisms could allow a remote attacker to execute
    arbitrary commands due to improper process controls. (CVE-2024-56347)

  - IBM AIX 7.2 and 7.3 nimesis NIM master service could allow a remote attacker to execute arbitrary commands
    due to improper process controls. (CVE-2024-56346)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/7186621");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/apar/IJ53757");
  script_set_attribute(attribute:"solution", value:
"Please apply the appropriate interim fix per APAR IJ53757.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-56347");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-56346");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"AIX Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'release': '3.1', 'ml': '04', 'sp': '31', 'patch': '(IJ53757m7a|IJ53757m7b)', 'package': 'bos.sysmgt.nim.client', 'minfilesetver': '7.2.5.0', 'maxfilesetver': '7.2.5.203'},
    {'release': '3.1', 'ml': '04', 'sp': '31', 'patch': '(IJ53757m7a|IJ53757m7b)', 'package': 'bos.sysmgt.nim.master', 'minfilesetver': '7.2.5.0', 'maxfilesetver': '7.2.5.204'},
    {'release': '3.1', 'ml': '04', 'sp': '31', 'patch': '(IJ53757m7a|IJ53757m7b)', 'package': 'bos.sysmgt.sysbr', 'minfilesetver': '7.2.5.0', 'maxfilesetver': '7.2.5.203'},
    {'release': '3.1', 'ml': '04', 'sp': '41', 'patch': '(IJ53757m8a|IJ53757m8b)', 'package': 'bos.sysmgt.nim.client', 'minfilesetver': '7.2.5.0', 'maxfilesetver': '7.2.5.203'},
    {'release': '3.1', 'ml': '04', 'sp': '41', 'patch': '(IJ53757m8a|IJ53757m8b)', 'package': 'bos.sysmgt.nim.master', 'minfilesetver': '7.2.5.0', 'maxfilesetver': '7.2.5.204'},
    {'release': '3.1', 'ml': '04', 'sp': '41', 'patch': '(IJ53757m8a|IJ53757m8b)', 'package': 'bos.sysmgt.sysbr', 'minfilesetver': '7.2.5.0', 'maxfilesetver': '7.2.5.203'},
    {'release': '3.1', 'ml': '04', 'sp': '50', 'patch': '(IJ53757m9a|IJ53757m9b)', 'package': 'bos.sysmgt.nim.client', 'minfilesetver': '7.2.5.0', 'maxfilesetver': '7.2.5.203'},
    {'release': '3.1', 'ml': '04', 'sp': '50', 'patch': '(IJ53757m9a|IJ53757m9b)', 'package': 'bos.sysmgt.nim.master', 'minfilesetver': '7.2.5.0', 'maxfilesetver': '7.2.5.204'},
    {'release': '3.1', 'ml': '04', 'sp': '50', 'patch': '(IJ53757m9a|IJ53757m9b)', 'package': 'bos.sysmgt.sysbr', 'minfilesetver': '7.2.5.0', 'maxfilesetver': '7.2.5.203'},
    {'release': '7.2', 'ml': '05', 'sp': '07', 'patch': '(IJ53757m7a|IJ53757m7b)', 'package': 'bos.sysmgt.nim.client', 'minfilesetver': '7.2.5.0', 'maxfilesetver': '7.2.5.203'},
    {'release': '7.2', 'ml': '05', 'sp': '07', 'patch': '(IJ53757m7a|IJ53757m7b)', 'package': 'bos.sysmgt.nim.master', 'minfilesetver': '7.2.5.0', 'maxfilesetver': '7.2.5.204'},
    {'release': '7.2', 'ml': '05', 'sp': '07', 'patch': '(IJ53757m7a|IJ53757m7b)', 'package': 'bos.sysmgt.sysbr', 'minfilesetver': '7.2.5.0', 'maxfilesetver': '7.2.5.203'},
    {'release': '7.2', 'ml': '05', 'sp': '08', 'patch': '(IJ53757m8a|IJ53757m8b)', 'package': 'bos.sysmgt.nim.client', 'minfilesetver': '7.2.5.0', 'maxfilesetver': '7.2.5.203'},
    {'release': '7.2', 'ml': '05', 'sp': '08', 'patch': '(IJ53757m8a|IJ53757m8b)', 'package': 'bos.sysmgt.nim.master', 'minfilesetver': '7.2.5.0', 'maxfilesetver': '7.2.5.204'},
    {'release': '7.2', 'ml': '05', 'sp': '08', 'patch': '(IJ53757m8a|IJ53757m8b)', 'package': 'bos.sysmgt.sysbr', 'minfilesetver': '7.2.5.0', 'maxfilesetver': '7.2.5.203'},
    {'release': '7.2', 'ml': '05', 'sp': '09', 'patch': '(IJ53757m9a|IJ53757m9b)', 'package': 'bos.sysmgt.nim.client', 'minfilesetver': '7.2.5.0', 'maxfilesetver': '7.2.5.203'},
    {'release': '7.2', 'ml': '05', 'sp': '09', 'patch': '(IJ53757m9a|IJ53757m9b)', 'package': 'bos.sysmgt.nim.master', 'minfilesetver': '7.2.5.0', 'maxfilesetver': '7.2.5.204'},
    {'release': '7.2', 'ml': '05', 'sp': '09', 'patch': '(IJ53757m9a|IJ53757m9b)', 'package': 'bos.sysmgt.sysbr', 'minfilesetver': '7.2.5.0', 'maxfilesetver': '7.2.5.203'}
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
