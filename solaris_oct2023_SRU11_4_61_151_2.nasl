#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(183516);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/20");

  script_cve_id("CVE-2023-22129");

  script_name(english:"Oracle Solaris Critical Patch Update : oct2023_SRU11_4_61_151_2");

  script_set_attribute(attribute:"synopsis", value:
"The remote Solaris system is missing a security patch from CPU Oct2023.");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by a Denial of Service vulnerability which could be exploited
by a low privileged attacker with logon to the infrastructure where Oracle Solaris executes.");

  script_set_attribute(attribute:"solution", value:
"Install the Oct2023 CPU from the Oracle support website.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpuoct2023cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuoct2023.html");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-22129");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Solaris Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris11/release");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item("Host/Solaris11/release");
if (isnull(release)) audit(AUDIT_OS_NOT, "Solaris11");


var fix_release = "11.4-11.4.61.0.1.151.2";

var flag = 0;

if (solaris_check_release(release:fix_release, sru:"11.4.61.151.2") > 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:solaris_get_report2());
  else security_warning(0);
  exit(0);
}
audit(AUDIT_OS_RELEASE_NOT, "Solaris", fix_release, release);
