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
  script_id(178628);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/18");

  script_cve_id("CVE-2022-31783", "CVE-2022-37290", "CVE-2022-37434", "CVE-2022-43551", "CVE-2023-0215", "CVE-2023-1999", "CVE-2023-21911", "CVE-2023-21912", "CVE-2023-21919", "CVE-2023-21920", "CVE-2023-21929", "CVE-2023-21933", "CVE-2023-21935", "CVE-2023-21940", "CVE-2023-21945", "CVE-2023-21946", "CVE-2023-21947", "CVE-2023-21953", "CVE-2023-21955", "CVE-2023-21962", "CVE-2023-21966", "CVE-2023-21972", "CVE-2023-21976", "CVE-2023-21977", "CVE-2023-21980", "CVE-2023-21982", "CVE-2023-24539", "CVE-2023-24540", "CVE-2023-25652", "CVE-2023-25815", "CVE-2023-26767", "CVE-2023-26768", "CVE-2023-26769", "CVE-2023-2731", "CVE-2023-28484", "CVE-2023-28709", "CVE-2023-29007", "CVE-2023-29400", "CVE-2023-29469", "CVE-2023-30608", "CVE-2023-32324", "CVE-2023-34414", "CVE-2023-34416", "CVE-2023-34981", "CVE-2023-3575", "CVE-2023-41717");

  script_name(english:"Oracle Solaris Critical Patch Update : jul2023_SRU11_4_59_144_2");
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

  - Vulnerability in the MySQL Enterprise Monitor product of
    Oracle MySQL (component: Monitoring: General (Apache
    Tomcat)). Supported versions that are affected are
    8.0.34 and prior. Easily exploitable vulnerability
    allows unauthenticated attacker with network access via
    multiple protocols to compromise MySQL Enterprise
    Monitor. Successful attacks of this vulnerability can
    result in unauthorized ability to cause a hang or
    frequently repeatable crash (complete DOS) of MySQL
    Enterprise Monitor. CVSS 3.1 Base Score 7.5
    (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H).
    (CVE-2023-28709)

  - Vulnerability in the MySQL Server product of Oracle
    MySQL (component: Client programs). Supported versions
    that are affected are 5.7.41 and prior and 8.0.32 and
    prior. Difficult to exploit vulnerability allows low
    privileged attacker with network access via multiple
    protocols to compromise MySQL Server. Successful attacks
    require human interaction from a person other than the
    attacker. Successful attacks of this vulnerability can
    result in takeover of MySQL Server. CVSS 3.1 Base Score
    7.1 (Confidentiality, Integrity and Availability
    impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H).
    (CVE-2023-21980)

  - Vulnerability in the MySQL Server product of Oracle
    MySQL (component: Server: Optimizer). Supported versions
    that are affected are 8.0.32 and prior. Easily
    exploitable vulnerability allows low privileged attacker
    with network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability
    can result in unauthorized ability to cause a hang or
    frequently repeatable crash (complete DOS) of MySQL
    Server. CVSS 3.1 Base Score 6.5 (Availability impacts).
    CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H).
    (CVE-2023-21946)

  - Vulnerability in the MySQL Server product of Oracle
    MySQL (component: Server: DDL). Supported versions that
    are affected are 8.0.32 and prior. Easily exploitable
    vulnerability allows high privileged attacker with
    network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability
    can result in unauthorized ability to cause a hang or
    frequently repeatable crash (complete DOS) of MySQL
    Server as well as unauthorized update, insert or delete
    access to some of MySQL Server accessible data. CVSS 3.1
    Base Score 5.5 (Integrity and Availability impacts).
    CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:H).
    (CVE-2023-21929)

  - Vulnerability in the MySQL Server product of Oracle
    MySQL (component: InnoDB). Supported versions that are
    affected are 8.0.32 and prior. Easily exploitable
    vulnerability allows high privileged attacker with
    network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability
    can result in unauthorized ability to cause a hang or
    frequently repeatable crash (complete DOS) of MySQL
    Server. CVSS 3.1 Base Score 4.9 (Availability impacts).
    CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H).
    (CVE-2023-21911)

  - Vulnerability in the MySQL Server product of Oracle
    MySQL (component: Server: Components Services).
    Supported versions that are affected are 8.0.32 and
    prior. Easily exploitable vulnerability allows high
    privileged attacker with network access via multiple
    protocols to compromise MySQL Server. Successful attacks
    of this vulnerability can result in unauthorized ability
    to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. CVSS 3.1 Base Score 4.9
    (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H).
    (CVE-2023-21962)

  - Vulnerability in the MySQL Server product of Oracle
    MySQL (component: Server: DDL). Supported versions that
    are affected are 8.0.32 and prior. Easily exploitable
    vulnerability allows high privileged attacker with
    network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability
    can result in unauthorized ability to cause a hang or
    frequently repeatable crash (complete DOS) of MySQL
    Server. CVSS 3.1 Base Score 4.9 (Availability impacts).
    CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H).
    (CVE-2023-21919)

  - Vulnerability in the MySQL Server product of Oracle
    MySQL (component: Server: DDL). Supported versions that
    are affected are 8.0.32 and prior. Easily exploitable
    vulnerability allows high privileged attacker with
    network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability
    can result in unauthorized ability to cause a hang or
    frequently repeatable crash (complete DOS) of MySQL
    Server. CVSS 3.1 Base Score 4.9 (Availability impacts).
    CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H).
    (CVE-2023-21933)

  - Vulnerability in the MySQL Server product of Oracle
    MySQL (component: Server: DML). Supported versions that
    are affected are 8.0.32 and prior. Easily exploitable
    vulnerability allows high privileged attacker with
    network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability
    can result in unauthorized ability to cause a hang or
    frequently repeatable crash (complete DOS) of MySQL
    Server. CVSS 3.1 Base Score 4.9 (Availability impacts).
    CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H).
    (CVE-2023-21972)

  - Vulnerability in the MySQL Server product of Oracle
    MySQL (component: Server: JSON). Supported versions that
    are affected are 8.0.32 and prior. Easily exploitable
    vulnerability allows high privileged attacker with
    network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability
    can result in unauthorized ability to cause a hang or
    frequently repeatable crash (complete DOS) of MySQL
    Server. CVSS 3.1 Base Score 4.9 (Availability impacts).
    CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H).
    (CVE-2023-21966)

  - Vulnerability in the MySQL Server product of Oracle
    MySQL (component: Server: Optimizer). Supported versions
    that are affected are 8.0.32 and prior. Easily
    exploitable vulnerability allows high privileged
    attacker with network access via multiple protocols to
    compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to
    cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. CVSS 3.1 Base Score 4.9
    (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H).
    (CVE-2023-21920)

  - Vulnerability in the MySQL Server product of Oracle
    MySQL (component: Server: Optimizer). Supported versions
    that are affected are 8.0.32 and prior. Easily
    exploitable vulnerability allows high privileged
    attacker with network access via multiple protocols to
    compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to
    cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. CVSS 3.1 Base Score 4.9
    (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H).
    (CVE-2023-21935)

  - Vulnerability in the MySQL Server product of Oracle
    MySQL (component: Server: Optimizer). Supported versions
    that are affected are 8.0.32 and prior. Easily
    exploitable vulnerability allows high privileged
    attacker with network access via multiple protocols to
    compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to
    cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. CVSS 3.1 Base Score 4.9
    (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H).
    (CVE-2023-21945)

  - Vulnerability in the MySQL Server product of Oracle
    MySQL (component: Server: Optimizer). Supported versions
    that are affected are 8.0.32 and prior. Easily
    exploitable vulnerability allows high privileged
    attacker with network access via multiple protocols to
    compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to
    cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. CVSS 3.1 Base Score 4.9
    (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H).
    (CVE-2023-21976)

  - Vulnerability in the MySQL Server product of Oracle
    MySQL (component: Server: Optimizer). Supported versions
    that are affected are 8.0.32 and prior. Easily
    exploitable vulnerability allows high privileged
    attacker with network access via multiple protocols to
    compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to
    cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. CVSS 3.1 Base Score 4.9
    (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H).
    (CVE-2023-21977)

  - Vulnerability in the MySQL Server product of Oracle
    MySQL (component: Server: Optimizer). Supported versions
    that are affected are 8.0.32 and prior. Easily
    exploitable vulnerability allows high privileged
    attacker with network access via multiple protocols to
    compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to
    cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. CVSS 3.1 Base Score 4.9
    (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H).
    (CVE-2023-21982)

  - Vulnerability in the MySQL Server product of Oracle
    MySQL (component: Server: Partition). Supported versions
    that are affected are 8.0.32 and prior. Easily
    exploitable vulnerability allows high privileged
    attacker with network access via multiple protocols to
    compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to
    cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. CVSS 3.1 Base Score 4.9
    (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H).
    (CVE-2023-21953)

  - Vulnerability in the MySQL Server product of Oracle
    MySQL (component: Server: Partition). Supported versions
    that are affected are 8.0.32 and prior. Easily
    exploitable vulnerability allows high privileged
    attacker with network access via multiple protocols to
    compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to
    cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. CVSS 3.1 Base Score 4.9
    (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H).
    (CVE-2023-21955)

  - Vulnerability in the MySQL Server product of Oracle
    MySQL (component: Server: Components Services).
    Supported versions that are affected are 8.0.32 and
    prior. Difficult to exploit vulnerability allows high
    privileged attacker with network access via multiple
    protocols to compromise MySQL Server. Successful attacks
    of this vulnerability can result in unauthorized ability
    to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. CVSS 3.1 Base Score 4.4
    (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:H).
    (CVE-2023-21940)

  - Vulnerability in the MySQL Server product of Oracle
    MySQL (component: Server: Components Services).
    Supported versions that are affected are 8.0.32 and
    prior. Difficult to exploit vulnerability allows high
    privileged attacker with network access via multiple
    protocols to compromise MySQL Server. Successful attacks
    of this vulnerability can result in unauthorized ability
    to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. CVSS 3.1 Base Score 4.4
    (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:H).
    (CVE-2023-21947)

  - Vulnerability in the Oracle Communications Diameter
    Signaling Router product of Oracle Communications
    (component: Virtual Network Function Manager (git)). The
    supported version that is affected is 8.6.0.0. Easily
    exploitable vulnerability allows unauthenticated
    attacker with logon to the infrastructure where Oracle
    Communications Diameter Signaling Router executes to
    compromise Oracle Communications Diameter Signaling
    Router. Successful attacks require human interaction
    from a person other than the attacker. Successful
    attacks of this vulnerability can result in takeover of
    Oracle Communications Diameter Signaling Router. CVSS
    3.1 Base Score 7.8 (Confidentiality, Integrity and
    Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H).
    (CVE-2023-29007)

  - Vulnerability in the MySQL Workbench product of Oracle
    MySQL (component: Workbench (libxml2)). Supported
    versions that are affected are 8.0.33 and prior. Easily
    exploitable vulnerability allows unauthenticated
    attacker with network access via MySQL Workbench to
    compromise MySQL Workbench. Successful attacks require
    human interaction from a person other than the attacker.
    Successful attacks of this vulnerability can result in
    unauthorized ability to cause a hang or frequently
    repeatable crash (complete DOS) of MySQL Workbench. CVSS
    3.1 Base Score 6.5 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H).
    (CVE-2023-28484)

  - Vulnerability in the Oracle Retail Advanced Inventory
    Planning product of Oracle Retail Applications
    (component: Operations & Maintenance (zlib)). Supported
    versions that are affected are 15.0 and 16.0. Easily
    exploitable vulnerability allows unauthenticated
    attacker with network access via HTTP to compromise
    Oracle Retail Advanced Inventory Planning. Successful
    attacks of this vulnerability can result in takeover of
    Oracle Retail Advanced Inventory Planning. CVSS 3.1 Base
    Score 9.8 (Confidentiality, Integrity and Availability
    impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).
    (CVE-2022-37434)

  - Vulnerability in the Oracle Enterprise Operations
    Monitor product of Oracle Communications (component:
    Mediation Engine (OpenSSL)). Supported versions that are
    affected are 5.0 and 5.1. Easily exploitable
    vulnerability allows unauthenticated attacker with
    network access via TLS to compromise Oracle Enterprise
    Operations Monitor. Successful attacks of this
    vulnerability can result in unauthorized ability to
    cause a hang or frequently repeatable crash (complete
    DOS) of Oracle Enterprise Operations Monitor. CVSS 3.1
    Base Score 7.5 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H).
    (CVE-2023-0215)

  - Vulnerability in the MySQL Server product of Oracle
    MySQL (component: Server: Packaging (cURL)). Supported
    versions that are affected are 5.7.41 and prior and
    8.0.32 and prior. Easily exploitable vulnerability
    allows unauthenticated attacker with network access via
    multiple protocols to compromise MySQL Server.
    Successful attacks of this vulnerability can result in
    unauthorized access to critical data or complete access
    to all MySQL Server accessible data. CVSS 3.1 Base Score
    7.5 (Confidentiality impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N).
    (CVE-2022-43551)

  - Vulnerability in the MySQL Server product of Oracle
    MySQL (component: Server: Security: Privileges).
    Supported versions that are affected are 5.7.41 and
    prior and 8.0.30 and prior. Easily exploitable
    vulnerability allows unauthenticated attacker with
    network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability
    can result in unauthorized ability to cause a hang or
    frequently repeatable crash (complete DOS) of MySQL
    Server. CVSS 3.1 Base Score 7.5 (Availability impacts).
    CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H).
    (CVE-2023-21912)

  - Vulnerability in the MySQL Server product of Oracle
    MySQL (component: Client programs). Supported versions
    that are affected are 5.7.41 and prior and 8.0.32 and
    prior. Difficult to exploit vulnerability allows low
    privileged attacker with network access via multiple
    protocols to compromise MySQL Server. Successful attacks
    require human interaction from a person other than the
    attacker. Successful attacks of this vulnerability can
    result in takeover of MySQL Server. CVSS 3.1 Base Score
    7.1 (Confidentiality, Integrity and Availability
    impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H).
    (CVE-2023-21980)

  - Vulnerability in the Oracle Communications Diameter
    Signaling Router product of Oracle Communications
    (component: Virtual Network Function Manager (Libwebp)).
    The supported version that is affected is 8.6.0.0.
    Easily exploitable vulnerability allows unauthenticated
    attacker with network access via HTTP to compromise
    Oracle Communications Diameter Signaling Router.
    Successful attacks of this vulnerability can result in
    unauthorized ability to cause a hang or frequently
    repeatable crash (complete DOS) of Oracle Communications
    Diameter Signaling Router. CVSS 3.1 Base Score 7.5
    (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H).
    (CVE-2023-1999)"
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
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-31783");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Based on vendor documentation");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/02");
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


fix_release = "11.4-11.4.59.0.1.144.2";

flag = 0;

if (solaris_check_release(release:"11.4-11.4.59.0.1.144.2", sru:"11.4.59.144.2") > 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:solaris_get_report2());
  else security_warning(0);
  exit(0);
}
audit(AUDIT_OS_RELEASE_NOT, "Solaris", fix_release, release);
