#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory libxml2_advisory4.asc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(174454);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/31");

  script_cve_id("CVE-2022-40303", "CVE-2022-40304");

  script_name(english:"AIX 7.2 TL 5 : libxml2 (IJ45056)");
  script_summary(english:"Check for APAR IJ45056");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote AIX host is missing a security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-40304
https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-40304 Gnome
ibxml2 could allow a remote attacker to execute arbitrary code on the
system, caused by a dict corruption flaw. By persuading a victim to
open a specially-crafted file, an attacker could exploit this
vulnerability to execute arbitrary code on the system. Gnome libxml2
could allow a remote attacker to execute arbitrary code on the system,
caused by an integer overflow in the XML_PARSE_HUGE function. By
persuading a victim to open a specially-crafted file, an attacker
could exploit this vulnerability to execute arbitrary code on the
system."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://aix.software.ibm.com/aix/efixes/security/libxml2_advisory4.asc"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Install the appropriate interim fix."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-40304");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix:7.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/19");
  script_set_attribute(attribute:"generated_plugin", value:"former");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (aix_check_ifix(release:"7.2", ml:"05", sp:"03", patch:"(IJ45056m4a|IJ47597m4a|IF47597m6a)", package:"bos.rte.control", minfilesetver:"7.2.5.0", maxfilesetver:"7.2.5.5") < 0) flag++;
if (aix_check_ifix(release:"7.2", ml:"05", sp:"03", patch:"(IJ45056m4a|IJ47597m4a|IF47597m6a)", package:"bos.rte.control", minfilesetver:"7.2.5.100", maxfilesetver:"7.2.5.102") < 0) flag++;
if (aix_check_ifix(release:"7.2", ml:"05", sp:"03", patch:"(IJ45056m4a|IJ47597m4a|IF47597m6a)", package:"bos.rte.control", minfilesetver:"7.2.5.200", maxfilesetver:"7.2.5.201") < 0) flag++;
if (aix_check_ifix(release:"7.2", ml:"05", sp:"04", patch:"(IJ45056m4a|IJ47597m4a|IF47597m6a)", package:"bos.rte.control", minfilesetver:"7.2.5.0", maxfilesetver:"7.2.5.5") < 0) flag++;
if (aix_check_ifix(release:"7.2", ml:"05", sp:"04", patch:"(IJ45056m4a|IJ47597m4a|IF47597m6a)", package:"bos.rte.control", minfilesetver:"7.2.5.100", maxfilesetver:"7.2.5.102") < 0) flag++;
if (aix_check_ifix(release:"7.2", ml:"05", sp:"04", patch:"(IJ45056m4a|IJ47597m6a|IF47597m6a)", package:"bos.rte.control", minfilesetver:"7.2.5.200", maxfilesetver:"7.2.5.201") < 0) flag++;
if (aix_check_ifix(release:"7.2", ml:"05", sp:"05", patch:"(IJ45056m5a|IJ47597m6a|IJ50602m7a)", package:"bos.rte.control", minfilesetver:"7.2.5.0", maxfilesetver:"7.2.5.5") < 0) flag++;
if (aix_check_ifix(release:"7.2", ml:"05", sp:"05", patch:"(IJ45056m5a|IJ47597m6a|IJ50602m7a)", package:"bos.rte.control", minfilesetver:"7.2.5.100", maxfilesetver:"7.2.5.102") < 0) flag++;
if (aix_check_ifix(release:"7.2", ml:"05", sp:"05", patch:"(IJ45056m5a|IJ47597m6a|IJ50602m7a)", package:"bos.rte.control", minfilesetver:"7.2.5.200", maxfilesetver:"7.2.5.201") < 0) flag++;
if (aix_check_ifix(release:"7.2", ml:"05", sp:"06", patch:"(IJ45056m6a|IJ47597m6a|IJ50602m7a)", package:"bos.rte.control", minfilesetver:"7.2.5.0", maxfilesetver:"7.2.5.5") < 0) flag++;
if (aix_check_ifix(release:"7.2", ml:"05", sp:"06", patch:"(IJ45056m6a|IJ47597m6a|IJ50602m7a)", package:"bos.rte.control", minfilesetver:"7.2.5.100", maxfilesetver:"7.2.5.102") < 0) flag++;
if (aix_check_ifix(release:"7.2", ml:"05", sp:"06", patch:"(IJ45056m6a|IJ47597m6a|IJ50602m7a)", package:"bos.rte.control", minfilesetver:"7.2.5.200", maxfilesetver:"7.2.5.201") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:aix_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
