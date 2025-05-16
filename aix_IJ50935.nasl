#%NASL_MIN_LEVEL 80900
#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory kernel_advisory7.asc.
#

include('compat.inc');

if (description)
{
  script_id(195309);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/23");

  script_cve_id("CVE-2024-27273");

  script_name(english:"AIX (IJ50935)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AIX host is missing a security patch.");
  script_set_attribute(attribute:"description", value:
"The version of AIX installed on the remote host is prior to APAR IJ50935. It is, therefore, affected by a vulnerability
as referenced in the IJ50935 advisory.

  - IBM AIX's Unix domain (AIX 7.2, 7.3, VIOS 3.1, and VIOS 4.1) datagram socket implementation could
    potentially expose applications using Unix domain datagram sockets with SO_PEERID operation and may lead
    to privilege escalation. IBM X-Force ID: 284903. (CVE-2024-27273)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/apar/IJ50935");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/7150297");
  script_set_attribute(attribute:"solution", value:
"Please apply the appropriate interim fix per APAR IJ50935.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-27273");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/10");

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
    {'release': '7.3', 'ml': '01', 'sp': '01', 'patch': 'IJ50935m1a', 'package': 'bos.mp64', 'minfilesetver': '7.3.1.0', 'maxfilesetver': '7.3.1.4'},
    {'release': '7.3', 'ml': '01', 'sp': '02', 'patch': 'IJ50935m2a', 'package': 'bos.mp64', 'minfilesetver': '7.3.1.0', 'maxfilesetver': '7.3.1.4'},
    {'release': '7.3', 'ml': '01', 'sp': '03', 'patch': 'IJ50935s3a', 'package': 'bos.mp64', 'minfilesetver': '7.3.1.0', 'maxfilesetver': '7.3.1.4'}
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
      severity   : SECURITY_WARNING,
      extra      : aix_report_get()
  );
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected - AIX");
