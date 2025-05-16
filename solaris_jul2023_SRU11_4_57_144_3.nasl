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
  script_id(178627);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/16");

  script_cve_id("CVE-2021-43618", "CVE-2022-2097", "CVE-2022-21123", "CVE-2022-21125", "CVE-2022-21127", "CVE-2022-21166", "CVE-2022-21589", "CVE-2022-21592", "CVE-2022-21608", "CVE-2022-21617", "CVE-2022-28805", "CVE-2022-33099", "CVE-2022-39348", "CVE-2022-40897", "CVE-2022-42898", "CVE-2022-43551", "CVE-2022-43552", "CVE-2022-44617", "CVE-2022-44792", "CVE-2022-44793", "CVE-2022-46285", "CVE-2022-46663", "CVE-2022-46908", "CVE-2022-47016", "CVE-2022-48303", "CVE-2022-4883", "CVE-2023-0494", "CVE-2023-1161", "CVE-2023-22023", "CVE-2023-23931", "CVE-2023-27320", "CVE-2023-28486", "CVE-2023-28487", "CVE-2023-31284");
  script_xref(name:"IAVA", value:"2023-A-0370-S");

  script_name(english:"Oracle Solaris Critical Patch Update : jul2023_SRU11_4_57_144_3");
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
    (CVE-2023-22023)

  - Vulnerability in the PeopleSoft Enterprise PeopleTools
    product of Oracle PeopleSoft (component: Security
    (OpenSSL)). Supported versions that are affected are
    8.58, 8.59 and 8.60. Easily exploitable vulnerability
    allows unauthenticated attacker with network access via
    TLS to compromise PeopleSoft Enterprise PeopleTools.
    Successful attacks of this vulnerability can result in
    unauthorized read access to a subset of PeopleSoft
    Enterprise PeopleTools accessible data. CVSS 3.1 Base
    Score 5.3 (Confidentiality impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N).
    (CVE-2022-2097)

  - Vulnerability in the MySQL Server product of Oracle
    MySQL (component: Server: Connection Handling).
    Supported versions that are affected are 5.7.39 and
    prior and 8.0.30 and prior. Easily exploitable
    vulnerability allows high privileged attacker with
    network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability
    can result in unauthorized ability to cause a hang or
    frequently repeatable crash (complete DOS) of MySQL
    Server. CVSS 3.1 Base Score 4.9 (Availability impacts).
    CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H).
    (CVE-2022-21617)

  - Vulnerability in the MySQL Server product of Oracle
    MySQL (component: Server: Optimizer). Supported versions
    that are affected are 5.7.39 and prior and 8.0.30 and
    prior. Easily exploitable vulnerability allows high
    privileged attacker with network access via multiple
    protocols to compromise MySQL Server. Successful attacks
    of this vulnerability can result in unauthorized ability
    to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. CVSS 3.1 Base Score 4.9
    (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H).
    (CVE-2022-21608)

  - Vulnerability in the MySQL Server product of Oracle
    MySQL (component: Server: Security: Encryption).
    Supported versions that are affected are 5.7.39 and
    prior and 8.0.29 and prior. Easily exploitable
    vulnerability allows low privileged attacker with
    network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability
    can result in unauthorized read access to a subset of
    MySQL Server accessible data. CVSS 3.1 Base Score 4.3
    (Confidentiality impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N).
    (CVE-2022-21592)

  - Vulnerability in the MySQL Server product of Oracle
    MySQL (component: Server: Security: Privileges).
    Supported versions that are affected are 5.7.39 and
    prior and 8.0.16 and prior. Easily exploitable
    vulnerability allows low privileged attacker with
    network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability
    can result in unauthorized read access to a subset of
    MySQL Server accessible data. CVSS 3.1 Base Score 4.3
    (Confidentiality impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N).
    (CVE-2022-21589)

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

  - Vulnerability in the Oracle Communications Network
    Analytics Data Director product of Oracle Communications
    (component: Install/Upgrade (Kerberos)). The supported
    version that is affected is 23.1.0. Easily exploitable
    vulnerability allows low privileged attacker with
    network access via HTTP to compromise Oracle
    Communications Network Analytics Data Director.
    Successful attacks of this vulnerability can result in
    takeover of Oracle Communications Network Analytics Data
    Director. CVSS 3.1 Base Score 8.8 (Confidentiality,
    Integrity and Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H).
    (CVE-2022-42898)

  - Vulnerability in the Oracle Outside In Technology
    product of Oracle Fusion Middleware (component: Third
    Party (SQLite)). The supported version that is affected
    is 8.5.6. Easily exploitable vulnerability allows low
    privileged attacker with logon to the infrastructure
    where Oracle Outside In Technology executes to
    compromise Oracle Outside In Technology. Successful
    attacks of this vulnerability can result in unauthorized
    creation, deletion or modification access to critical
    data or all Oracle Outside In Technology accessible data
    as well as unauthorized access to critical data or
    complete access to all Oracle Outside In Technology
    accessible data and unauthorized ability to cause a
    partial denial of service (partial DOS) of Oracle
    Outside In Technology. CVSS 3.1 Base Score 7.3
    (Confidentiality, Integrity and Availability impacts).
    CVSS Vector:
    (CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L).
    (CVE-2022-46908)

  - Vulnerability in the Oracle Communications Diameter
    Signaling Router product of Oracle Communications
    (component: Platform (Microcode Controller)). The
    supported version that is affected is 8.6.0.0. Easily
    exploitable vulnerability allows low privileged attacker
    with logon to the infrastructure where Oracle
    Communications Diameter Signaling Router executes to
    compromise Oracle Communications Diameter Signaling
    Router. Successful attacks of this vulnerability can
    result in unauthorized access to critical data or
    complete access to all Oracle Communications Diameter
    Signaling Router accessible data. CVSS 3.1 Base Score
    5.5 (Confidentiality impacts). CVSS Vector:
    (CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N).
    (CVE-2022-21123)

  - Vulnerability in the PeopleSoft Enterprise PeopleTools
    product of Oracle PeopleSoft (component: Porting
    (Cryptography)). Supported versions that are affected
    are 8.59 and 8.60. Easily exploitable vulnerability
    allows unauthenticated attacker with network access via
    HTTPS to compromise PeopleSoft Enterprise PeopleTools.
    Successful attacks of this vulnerability can result in
    unauthorized update, insert or delete access to some of
    PeopleSoft Enterprise PeopleTools accessible data and
    unauthorized ability to cause a partial denial of
    service (partial DOS) of PeopleSoft Enterprise
    PeopleTools. CVSS 3.1 Base Score 6.5 (Integrity and
    Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L).
    (CVE-2023-23931)

  - Vulnerability in the PeopleSoft Enterprise PeopleTools
    product of Oracle PeopleSoft (component: Porting (Python
    setuptools)). Supported versions that are affected are
    8.59 and 8.60. Difficult to exploit vulnerability allows
    unauthenticated attacker with network access via HTTP to
    compromise PeopleSoft Enterprise PeopleTools. Successful
    attacks of this vulnerability can result in unauthorized
    ability to cause a hang or frequently repeatable crash
    (complete DOS) of PeopleSoft Enterprise PeopleTools.
    CVSS 3.1 Base Score 5.9 (Availability impacts). CVSS
    Vector: (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H).
    (CVE-2022-40897)"
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
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-28805");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/15");
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


fix_release = "11.4-11.4.57.0.1.144.3";

flag = 0;

if (solaris_check_release(release:"11.4-11.4.57.0.1.144.3", sru:"11.4.57.144.3") > 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:solaris_get_report2());
  else security_warning(0);
  exit(0);
}
audit(AUDIT_OS_RELEASE_NOT, "Solaris", fix_release, release);
