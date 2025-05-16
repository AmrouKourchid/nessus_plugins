#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234448);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/15");

  script_cve_id("CVE-2024-47102", "CVE-2024-52906");

  script_name(english:"AIX : Multiple Vulnerabilities (IJ52977)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AIX host is missing a security patch.");
  script_set_attribute(attribute:"description", value:
"The version of AIX installed on the remote host is prior to APAR IJ52977. It is, therefore, affected by multiple
vulnerabilities as referenced in the IJ52977 advisory.

  - IBM AIX 7.2, 7.3, VIOS 3.1, and 4.1 could allow a non-privileged local user to exploit a vulnerability in
    the TCP/IP kernel extension to cause a denial of service. (CVE-2024-52906)

  - IBM AIX 7.2, 7.3, VIOS 3.1, and 4.1 could allow a non-privileged local user to exploit a vulnerability in
    the AIX perfstat kernel extension to cause a denial of service. (CVE-2024-47102)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/7179826");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/apar/IJ52977");
  script_set_attribute(attribute:"solution", value:
"Please apply the appropriate interim fix per APAR IJ52977.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-52906");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/12/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
    {'release': '7.3', 'ml': '01', 'sp': '02', 'patch': 'IJ52977s2a', 'package': 'bos.net.tcp.client_core', 'minfilesetver': '7.3.1.0', 'maxfilesetver': '7.3.1.5'},
    {'release': '7.3', 'ml': '01', 'sp': '02', 'patch': 'IJ52977s2a', 'package': 'bos.perf.perfstat', 'minfilesetver': '7.3.1.0', 'maxfilesetver': '7.3.1.1'},
    {'release': '7.3', 'ml': '01', 'sp': '03', 'patch': 'IJ52977s3a', 'package': 'bos.net.tcp.client_core', 'minfilesetver': '7.3.1.0', 'maxfilesetver': '7.3.1.5'},
    {'release': '7.3', 'ml': '01', 'sp': '03', 'patch': 'IJ52977s3a', 'package': 'bos.perf.perfstat', 'minfilesetver': '7.3.1.0', 'maxfilesetver': '7.3.1.1'},
    {'release': '7.3', 'ml': '01', 'sp': '04', 'patch': 'IJ52977s4a', 'package': 'bos.net.tcp.client_core', 'minfilesetver': '7.3.1.0', 'maxfilesetver': '7.3.1.5'},
    {'release': '7.3', 'ml': '01', 'sp': '04', 'patch': 'IJ52977s4a', 'package': 'bos.perf.perfstat', 'minfilesetver': '7.3.1.0', 'maxfilesetver': '7.3.1.1'}
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
