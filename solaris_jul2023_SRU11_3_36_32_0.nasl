#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle CPU for jul2023.
#
include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(178629);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/16");

  script_cve_id("CVE-2023-22023", "CVE-2023-31284");
  script_xref(name:"IAVA", value:"2023-A-0370-S");

  script_name(english:"Oracle Solaris Critical Patch Update : jul2023_SRU11_3_36_32_0");
  script_summary(english:"Check for the jul2023 CPU");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Solaris system is missing a security patch from CPU
jul2023."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This Solaris system is missing necessary patches to address critical
security updates :

  - Vulnerability in the Oracle Solaris product of Oracle
    Systems (component: Device Driver Interface). The
    supported version that is affected is 11. Easily
    exploitable vulnerability allows low privileged attacker
    with logon to the infrastructure where Oracle Solaris
    executes to compromise Oracle Solaris. Successful
    attacks of this vulnerability can result in takeover of
    Oracle Solaris. Note: CVE-2023-22023 is equivalent to
    CVE-2023-31284. CVSS 3.1 Base Score 7.8
    (Confidentiality, Integrity and Availability impacts).
    CVSS Vector:
    (CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H).
    (CVE-2023-22023)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.oracle.com/epmos/faces/DocumentDisplay?id=2960446.1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.oracle.com/docs/tech/security-alerts/cpujul2023cvrf.xml"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.oracle.com/security-alerts/cpujul2023.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Install the jul2023 CPU from the Oracle support website."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-31284");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/20");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris11/release");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/Solaris11/release");
if (isnull(release)) audit(AUDIT_OS_NOT, "Solaris11");


fix_release = "0.5.11-0.175.3.36.0.32.0";

flag = 0;

if (solaris_check_release(release:"0.5.11-0.175.3.36.0.32.0", sru:"11.3.36.32.0") > 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:solaris_get_report2());
  else security_warning(0);
  exit(0);
}
audit(AUDIT_OS_RELEASE_NOT, "Solaris", fix_release, release);
