#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle CPU for jan2019.
#
include("compat.inc");

if (description)
{
  script_id(121223);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/18");

  script_cve_id("CVE-2018-3639", "CVE-2018-3646", "CVE-2019-2437");

  script_name(english:"Oracle Solaris Critical Patch Update : jan2019_SRU11_4_3_5_0 (Foreshadow) (Spectre)");
  script_summary(english:"Check for the jan2019 CPU");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Solaris system is missing a security patch from CPU
jan2019."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This Solaris system is missing necessary patches to address critical
security updates :

  - Vulnerability in the Oracle Solaris component of Oracle
    Sun Systems Products Suite (subcomponent: Kernel). The
    supported version that is affected is 11. Easily
    exploitable vulnerability allows unauthenticated
    attacker with network access via TCP to compromise
    Oracle Solaris. Successful attacks of this vulnerability
    can result in unauthorized ability to cause a hang or
    frequently repeatable crash (complete DOS) of Oracle
    Solaris. (CVE-2019-2437)

  - Vulnerability in the Oracle Solaris component of Oracle
    Sun Systems Products Suite (subcomponent: Kernel). The
    supported version that is affected is 11. Difficult to
    exploit vulnerability allows low privileged attacker
    with logon to the infrastructure where Oracle Solaris
    executes to compromise Oracle Solaris. While the
    vulnerability is in Oracle Solaris, attacks may
    significantly impact additional products. Successful
    attacks of this vulnerability can result in unauthorized
    access to critical data or complete access to all Oracle
    Solaris accessible data. (CVE-2018-3646)

  - Vulnerability in the Oracle Communications LSMS product
    of Oracle Communications Applications (component:
    Kernel). Supported versions that are affected are
    13.0-13.3. Easily exploitable vulnerability allows low
    privileged attacker with logon to the infrastructure
    where Oracle Communications LSMS executes to compromise
    Oracle Communications LSMS. Successful attacks of this
    vulnerability can result in unauthorized access to
    critical data or complete access to all Oracle
    Communications LSMS accessible data. CVSS 3.1 Base Score
    5.5 (Confidentiality impacts). CVSS Vector:
    (CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N).
    (CVE-2018-3639)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.oracle.com/epmos/faces/DocumentDisplay?id=2492126.1"
  );
  # https://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/5228984.xml
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8d388438"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.oracle.com/security-alerts/cpujan2019.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Install the jan2019 CPU from the Oracle support website."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-3646");
  script_set_attribute(attribute: "cvss3_score_source", value: "manual");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/17");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");
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


fix_release = "11.4-11.4.3.0.1.5.0";

flag = 0;

if (solaris_check_release(release:"11.4-11.4.3.0.1.5.0", sru:"11.4.3.5.0") > 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:solaris_get_report2());
  else security_warning(0);
  exit(0);
}
audit(AUDIT_OS_RELEASE_NOT, "Solaris", fix_release, release);
