#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory kernel_advisory6.asc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(187995);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/01");

  script_cve_id("CVE-2023-45169", "CVE-2023-45171", "CVE-2023-45173", "CVE-2023-45175");
  script_xref(name:"IAVA", value:"2024-A-0021");

  script_name(english:"AIX 3.1 TL 3 : kernel (IJ49202)");
  script_summary(english:"Check for APAR IJ49202");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote AIX host is missing a security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-45175 IBM AIX
could allow a non-privileged local user to exploit a vulnerability in
the TCP/IP kernel extension to cause a denial of service. IBM AIX
could allow a non-privileged local user to exploit a vulnerability in
the NFS kernel extension to cause a denial of service. IBM AIX could
allow a non-privileged local user to exploit a vulnerability in the
pmsvcs kernel extension to cause a denial of service. IBM AIX could
allow a non-privileged local user to exploit a vulnerability in the
kernel to cause a denial of service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://aix.software.ibm.com/aix/efixes/security/kernel_advisory6.asc"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Install the appropriate interim fix."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-45175");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix:3.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/11");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"AIX Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/AIX/lslpp", "Host/local_checks_enabled", "Host/AIX/version");

  exit(0);
}



include("audit.inc");
include("global_settings.inc");
include("aix.inc");
include("misc_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if ( ! get_kb_item("Host/AIX/version") ) audit(AUDIT_OS_NOT, "AIX");
if ( ! get_kb_item("Host/AIX/lslpp") ) audit(AUDIT_PACKAGE_LIST_MISSING);

if ( get_kb_item("Host/AIX/emgr_failure" ) ) exit(0, "This iFix check is disabled because : "+get_kb_item("Host/AIX/emgr_failure") );

flag = 0;

if (aix_check_ifix(release:"3.1", ml:"03", sp:"21", patch:"IJ49202m2a", package:"bos.mp64", minfilesetver:"7.3.1.0", maxfilesetver:"7.3.1.3") < 0) flag++;
if (aix_check_ifix(release:"3.1", ml:"03", sp:"21", patch:"IJ49202m2b", package:"bos.mp64", minfilesetver:"7.3.1.0", maxfilesetver:"7.3.1.3") < 0) flag++;
if (aix_check_ifix(release:"3.1", ml:"03", sp:"30", patch:"IJ49202m3a", package:"bos.mp64", minfilesetver:"7.3.1.0", maxfilesetver:"7.3.1.3") < 0) flag++;
if (aix_check_ifix(release:"3.1", ml:"03", sp:"30", patch:"IJ49202m3b", package:"bos.mp64", minfilesetver:"7.3.1.0", maxfilesetver:"7.3.1.3") < 0) flag++;
if (aix_check_ifix(release:"3.1", ml:"03", sp:"40", patch:"IJ49202s4a", package:"bos.mp64", minfilesetver:"7.3.1.0", maxfilesetver:"7.3.1.3") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:aix_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
