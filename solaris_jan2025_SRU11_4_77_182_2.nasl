#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(214657);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/17");

  script_cve_id("CVE-2025-21551");
  script_xref(name:"IAVA", value:"2025-A-0052-S");

  script_name(english:"Oracle Solaris Critical Patch Update : jan2025_SRU11_4_77_182_2");

  script_set_attribute(attribute:"synopsis", value:
"The remote Solaris system is missing a security patch from CPU Jan2025.");
  script_set_attribute(attribute:"description", value:
"The version of Solaris installed on the remote host is prior to 11.4.77.182.2. It is, therefore, affected by a
vulnerability as referenced in the solaris11_jan2025_SRU11_4_77_182_2 advisory.

  - Vulnerability in the Oracle Solaris product of Oracle Systems (component: File system). The supported
    version that is affected is 11. Easily exploitable vulnerability allows high privileged attacker with
    logon to the infrastructure where Oracle Solaris executes to compromise Oracle Solaris. Successful attacks
    of this vulnerability can result in unauthorized creation, deletion or modification access to critical
    data or all Oracle Solaris accessible data and unauthorized ability to cause a hang or frequently
    repeatable crash (complete DOS) of Oracle Solaris. (CVE-2025-21551)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpujan2025csaf.json");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujan2025.html");
  script_set_attribute(attribute:"solution", value:
"Install the Jan2025 CPU from the Oracle support website.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:M/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-21551");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/01/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Solaris Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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


var fix_release = "11.4-11.4.77.0.1.182.2";

var flag = 0;

if (solaris_check_release(release:fix_release, sru:"11.4.77.182.2") > 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:solaris_get_report2());
  else security_warning(0);
  exit(0);
}
audit(AUDIT_OS_RELEASE_NOT, "Solaris", fix_release, release);
