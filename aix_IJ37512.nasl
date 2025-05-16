#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory caa_advisory2.asc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158518);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/23");

  script_cve_id("CVE-2021-38996", "CVE-2022-22350");

  script_name(english:"AIX : Multiple Vulnerabilities (IJ37512)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AIX host is missing a security patch.");
  script_set_attribute(attribute:"description", value:
"The version of AIX installed on the remote host is prior to APAR IJ37512. It is, therefore, affected by multiple
vulnerabilities as referenced in the IJ37512 advisory.

  - IBM AIX 7.1, 7.2, 7.3, and VIOS 3.1 could allow a non-privileged local user to exploit a vulnerability in
    CAA to cause a denial of service. IBM X-Force ID: 220394. (CVE-2022-22350)

  - IBM AIX 7.1, 7.2, 7.3, and VIOS 3.1 could allow a non-privileged local user to exploit a vulnerability in
    the AIX kernel to cause a denial of service. IBM X-Force ID: 213076. (CVE-2021-38996)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/apar/IJ37512");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/6560390");
  script_set_attribute(attribute:"solution", value:
"Please apply the appropriate interim fix per APAR IJ37512.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22350");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"AIX Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'release': '3.1', 'ml': '02', 'sp': '10', 'patch': 'IJ37512s1a', 'package': 'bos.cluster.rte', 'minfilesetver': '7.2.5.0', 'maxfilesetver': '7.2.5.1'},
    {'release': '3.1', 'ml': '02', 'sp': '10', 'patch': 'IJ37512s1a', 'package': 'bos.cluster.rte', 'minfilesetver': '7.2.5.100', 'maxfilesetver': '7.2.5.101'},
    {'release': '3.1', 'ml': '02', 'sp': '21', 'patch': 'IJ37512s2a', 'package': 'bos.cluster.rte', 'minfilesetver': '7.2.5.0', 'maxfilesetver': '7.2.5.1'},
    {'release': '3.1', 'ml': '02', 'sp': '21', 'patch': 'IJ37512s2a', 'package': 'bos.cluster.rte', 'minfilesetver': '7.2.5.100', 'maxfilesetver': '7.2.5.101'},
    {'release': '7.2', 'ml': '05', 'sp': '01', 'patch': 'IJ37512s1a', 'package': 'bos.cluster.rte', 'minfilesetver': '7.2.5.0', 'maxfilesetver': '7.2.5.1'},
    {'release': '7.2', 'ml': '05', 'sp': '01', 'patch': 'IJ37512s1a', 'package': 'bos.cluster.rte', 'minfilesetver': '7.2.5.100', 'maxfilesetver': '7.2.5.101'},
    {'release': '7.2', 'ml': '05', 'sp': '02', 'patch': 'IJ37512s2a', 'package': 'bos.cluster.rte', 'minfilesetver': '7.2.5.0', 'maxfilesetver': '7.2.5.1'},
    {'release': '7.2', 'ml': '05', 'sp': '02', 'patch': 'IJ37512s2a', 'package': 'bos.cluster.rte', 'minfilesetver': '7.2.5.100', 'maxfilesetver': '7.2.5.101'}
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
