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
  script_id(178626);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/26");

  script_cve_id("CVE-2021-33621", "CVE-2022-41723", "CVE-2022-41724", "CVE-2022-41725", "CVE-2022-4743", "CVE-2022-4904", "CVE-2023-1992", "CVE-2023-1993", "CVE-2023-1994", "CVE-2023-24021", "CVE-2023-24532", "CVE-2023-24534", "CVE-2023-24536", "CVE-2023-24537", "CVE-2023-24538", "CVE-2023-28755", "CVE-2023-28756", "CVE-2023-31047", "CVE-2023-32205", "CVE-2023-32206", "CVE-2023-32207", "CVE-2023-32211", "CVE-2023-32212", "CVE-2023-32213", "CVE-2023-32214", "CVE-2023-32215", "CVE-2023-33657");

  script_name(english:"Oracle Solaris Critical Patch Update : jul2023_SRU11_4_58_144_3");
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
security updates :"
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
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-32215");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/20");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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


fix_release = "11.4-11.4.58.0.1.144.3";

flag = 0;

if (solaris_check_release(release:"11.4-11.4.58.0.1.144.3", sru:"11.4.58.144.3") > 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:solaris_get_report2());
  else security_hole(0);
  exit(0);
}
audit(AUDIT_OS_RELEASE_NOT, "Solaris", fix_release, release);
