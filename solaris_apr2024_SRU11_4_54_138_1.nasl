#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(193488);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/18");

  script_cve_id("CVE-2024-21059");

  script_name(english:"Oracle Solaris Critical Patch Update : apr2024_SRU11_4_54_138_1");

  script_set_attribute(attribute:"synopsis", value:
"The remote Solaris system is missing a security patch from CPU Apr2024.");
  script_set_attribute(attribute:"description", value:
"The version of Solaris installed on the remote host is prior to 11.4.54.138.1. It is, therefore, affected by a
vulnerability as referenced in the solaris11_apr2024_SRU11_4_54_138_1 advisory.

  - Vulnerability in the Oracle Solaris product of Oracle Systems (component: Utility). The supported version 
    that is affected is 11. Difficult to exploit vulnerability allows low privileged attacker with logon to the 
    infrastructure where Oracle Solaris executes to compromise Oracle Solaris. While the vulnerability is in 
    Oracle Solaris, attacks may significantly impact additional products (scope change). Successful attacks of 
    this vulnerability can result in takeover of Oracle Solaris. (CVE-2024-21059)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported 
version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpuapr2024csaf.json");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2024.html");
  script_set_attribute(attribute:"solution", value:
"Install the Apr2024 CPU from the Oracle support website.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-21059");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Solaris Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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


var fix_release = "11.4-11.4.54.0.1.138.1";

var flag = 0;

if (solaris_check_release(release:fix_release, sru:"11.4.54.138.1") > 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:solaris_get_report2());
  else security_warning(0);
  exit(0);
}
audit(AUDIT_OS_RELEASE_NOT, "Solaris", fix_release, release);
