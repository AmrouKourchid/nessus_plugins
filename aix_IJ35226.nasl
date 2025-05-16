#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory efs_advisory.asc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155454);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/23");

  script_cve_id("CVE-2021-29861");

  script_name(english:"AIX (IJ35226)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AIX host is missing a security patch.");
  script_set_attribute(attribute:"description", value:
"The version of AIX installed on the remote host is prior to APAR IJ35226. It is, therefore, affected by a vulnerability
as referenced in the IJ35226 advisory.

  - IBM AIX 7.1, 7.2, and VIOS 3.1 could allow a non-privileged local user to exploit a vulnerability in EFS
    to expose sensitive information. IBM X-Force ID: 206085. (CVE-2021-29861)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/apar/IJ35226");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/6516786");
  script_set_attribute(attribute:"solution", value:
"Please apply the appropriate interim fix per APAR IJ35226.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-29861");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"AIX Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'release': '3.1', 'ml': '01', 'sp': '21', 'patch': 'IJ35226m2a', 'package': 'bos.rte.security', 'minfilesetver': '7.2.4.0', 'maxfilesetver': '7.2.4.3'},
    {'release': '3.1', 'ml': '01', 'sp': '25', 'patch': 'IJ35226m2a', 'package': 'bos.rte.security', 'minfilesetver': '7.2.4.0', 'maxfilesetver': '7.2.4.3'},
    {'release': '3.1', 'ml': '01', 'sp': '30', 'patch': 'IJ35226m3a', 'package': 'bos.rte.security', 'minfilesetver': '7.2.4.0', 'maxfilesetver': '7.2.4.3'},
    {'release': '3.1', 'ml': '01', 'sp': '40', 'patch': 'IJ35226m4a', 'package': 'bos.rte.security', 'minfilesetver': '7.2.4.0', 'maxfilesetver': '7.2.4.3'},
    {'release': '7.2', 'ml': '04', 'sp': '02', 'patch': 'IJ35226m2a', 'package': 'bos.rte.security', 'minfilesetver': '7.2.4.0', 'maxfilesetver': '7.2.4.3'},
    {'release': '7.2', 'ml': '04', 'sp': '03', 'patch': 'IJ35226m3a', 'package': 'bos.rte.security', 'minfilesetver': '7.2.4.0', 'maxfilesetver': '7.2.4.3'},
    {'release': '7.2', 'ml': '04', 'sp': '04', 'patch': 'IJ35226m4a', 'package': 'bos.rte.security', 'minfilesetver': '7.2.4.0', 'maxfilesetver': '7.2.4.3'}
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
      severity   : SECURITY_NOTE,
      extra      : aix_report_get()
  );
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected - AIX");
