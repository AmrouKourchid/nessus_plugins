#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory bind_advisory22.asc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(169315);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/01");

  script_cve_id("CVE-2022-2795", "CVE-2022-3080", "CVE-2022-38177", "CVE-2022-38178");

  script_name(english:"AIX 7.3 TL 0 : bind (IJ44427)");
  script_summary(english:"Check for APAR IJ44427");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote AIX host is missing a security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-38178 ISC BIND
is vulnerable to a denial of service, caused by a memory leak in the
DNSSEC verification code for the EdDSA algorithm. By spoofing the
target resolver with responses that have a malformed EdDSA signature,
a remote attacker could exploit this vulnerability to cause named to
crash. ISC BIND is vulnerable to a denial of service, caused by an
error when stale cache and stale answers are enabled, option
stale-answer-client-timeout is set to 0 and there is a stale CNAME in
the cache for an incoming query. By sending a specially-crafted
request, a remote attacker could exploit this vulnerability to cause
named to crash. ISC BIND is vulnerable to a denial of service, caused
by a small memory leak in the DNSSEC verification code for the ECDSA
algorithm. By spoofing the target resolver with responses that have a
malformed ECDSA signature, a remote attacker could exploit this
vulnerability to cause named to crash. ISC BIND is vulnerable to a
denial of service, caused by a flaw in resolver code. By flooding the
target resolver with queries, a remote attacker could exploit this
vulnerability to severely degrade the resolver's performance,
effectively denying legitimate clients access to the DNS resolution
service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://aix.software.ibm.com/aix/efixes/security/bind_advisory22.asc"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Install the appropriate interim fix."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-38178");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix:7.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/27");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (aix_check_ifix(release:"7.3", ml:"00", sp:"01", patch:"IJ44427m2a", package:"bos.net.tcp.bind_utils", minfilesetver:"7.3.0.0", maxfilesetver:"7.3.0.2") < 0) flag++;
if (aix_check_ifix(release:"7.3", ml:"00", sp:"02", patch:"IJ44427m2a", package:"bos.net.tcp.bind_utils", minfilesetver:"7.3.0.0", maxfilesetver:"7.3.0.2") < 0) flag++;
if (aix_check_ifix(release:"7.3", ml:"00", sp:"03", patch:"IJ44427s3a", package:"bos.net.tcp.bind_utils", minfilesetver:"7.3.0.0", maxfilesetver:"7.3.0.2") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:aix_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
