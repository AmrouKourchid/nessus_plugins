#%NASL_MIN_LEVEL 80900
#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory sendmail_advisory4.asc.
#

include('compat.inc');

if (description)
{
  script_id(195310);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/23");

  script_cve_id("CVE-2023-51765");

  script_name(english:"AIX (IJ50432)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AIX host is missing a security patch.");
  script_set_attribute(attribute:"description", value:
"The version of AIX installed on the remote host is prior to APAR IJ50432. It is, therefore, affected by a vulnerability
as referenced in the IJ50432 advisory.

  - sendmail through 8.17.2 allows SMTP smuggling in certain configurations. Remote attackers can use a
    published exploitation technique to inject e-mail messages with a spoofed MAIL FROM address, allowing
    bypass of an SPF protection mechanism. This occurs because sendmail supports <LF>.<CR><LF> but some other
    popular e-mail servers do not. This is resolved in 8.18 and later versions with 'o' in srv_features.
    (CVE-2023-51765)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/apar/IJ50432");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/7148150");
  script_set_attribute(attribute:"solution", value:
"Please apply the appropriate interim fix per APAR IJ50432.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-51765");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/11");
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
    {'release': '7.3', 'ml': '01', 'sp': '01', 'patch': 'IJ50432s3a', 'package': 'bos.net.tcp.sendmail', 'minfilesetver': '7.3.1.0', 'maxfilesetver': '7.3.1.0'},
    {'release': '7.3', 'ml': '01', 'sp': '02', 'patch': 'IJ50432s3a', 'package': 'bos.net.tcp.sendmail', 'minfilesetver': '7.3.1.0', 'maxfilesetver': '7.3.1.0'},
    {'release': '7.3', 'ml': '01', 'sp': '03', 'patch': 'IJ50432s3a', 'package': 'bos.net.tcp.sendmail', 'minfilesetver': '7.3.1.0', 'maxfilesetver': '7.3.1.0'}
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
