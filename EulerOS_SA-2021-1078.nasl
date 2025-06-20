#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(145111);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/29");

  script_cve_id(
    "CVE-2020-2754",
    "CVE-2020-2755",
    "CVE-2020-2756",
    "CVE-2020-2757",
    "CVE-2020-2773",
    "CVE-2020-2781",
    "CVE-2020-2800",
    "CVE-2020-2830",
    "CVE-2020-14581",
    "CVE-2020-14779",
    "CVE-2020-14781",
    "CVE-2020-14782",
    "CVE-2020-14792",
    "CVE-2020-14796",
    "CVE-2020-14797",
    "CVE-2020-14798",
    "CVE-2020-14803"
  );
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"EulerOS 2.0 SP3 : java-1.8.0-openjdk (EulerOS-SA-2021-1078)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the java-1.8.0-openjdk packages
installed, the EulerOS installation on the remote host is affected by
the following vulnerabilities :

  - Vulnerability in the Java SE, Java SE Embedded product
    of Oracle Java SE (component: Serialization). Supported
    versions that are affected are Java SE: 7u271, 8u261,
    11.0.8 and 15 Java SE Embedded: 8u261. Difficult to
    exploit vulnerability allows unauthenticated attacker
    with network access via multiple protocols to
    compromise Java SE, Java SE Embedded. Successful
    attacks of this vulnerability can result in
    unauthorized ability to cause a partial denial of
    service (partial DOS) of Java SE, Java SE Embedded.
    Note: Applies to client and server deployment of Java.
    This vulnerability can be exploited through sandboxed
    Java Web Start applications and sandboxed Java applets.
    It can also be exploited by supplying data to APIs in
    the specified Component without using sandboxed Java
    Web Start applications or sandboxed Java applets, such
    as through a web service.(CVE-2020-14779)

  - Vulnerability in the Java SE, Java SE Embedded product
    of Oracle Java SE (component: JNDI). Supported versions
    that are affected are Java SE: 7u271, 8u261, 11.0.8 and
    15 Java SE Embedded: 8u261. Difficult to exploit
    vulnerability allows unauthenticated attacker with
    network access via multiple protocols to compromise
    Java SE, Java SE Embedded. Successful attacks of this
    vulnerability can result in unauthorized read access to
    a subset of Java SE, Java SE Embedded accessible data.
    Note: Applies to client and server deployment of Java.
    This vulnerability can be exploited through sandboxed
    Java Web Start applications and sandboxed Java applets.
    It can also be exploited by supplying data to APIs in
    the specified Component without using sandboxed Java
    Web Start applications or sandboxed Java applets, such
    as through a web service.(CVE-2020-14781)

  - Vulnerability in the Java SE, Java SE Embedded product
    of Oracle Java SE (component: Hotspot). Supported
    versions that are affected are Java SE: 7u271, 8u261,
    11.0.8 and 15 Java SE Embedded: 8u261. Difficult to
    exploit vulnerability allows unauthenticated attacker
    with network access via multiple protocols to
    compromise Java SE, Java SE Embedded. Successful
    attacks require human interaction from a person other
    than the attacker. Successful attacks of this
    vulnerability can result in unauthorized update, insert
    or delete access to some of Java SE, Java SE Embedded
    accessible data as well as unauthorized read access to
    a subset of Java SE, Java SE Embedded accessible data.
    Note: Applies to client and server deployment of Java.
    This vulnerability can be exploited through sandboxed
    Java Web Start applications and sandboxed Java applets.
    It can also be exploited by supplying data to APIs in
    the specified Component without using sandboxed Java
    Web Start applications or sandboxed Java applets, such
    as through a web service.(CVE-2020-14792)

  - Vulnerability in the Java SE, Java SE Embedded product
    of Oracle Java SE (component: Libraries). Supported
    versions that are affected are Java SE: 7u271, 8u261,
    11.0.8 and 15 Java SE Embedded: 8u261. Difficult to
    exploit vulnerability allows unauthenticated attacker
    with network access via multiple protocols to
    compromise Java SE, Java SE Embedded. Successful
    attacks require human interaction from a person other
    than the attacker. Successful attacks of this
    vulnerability can result in unauthorized update, insert
    or delete access to some of Java SE, Java SE Embedded
    accessible data. Note: This vulnerability applies to
    Java deployments, typically in clients running
    sandboxed Java Web Start applications or sandboxed Java
    applets, that load and run untrusted code (e.g., code
    that comes from the internet) and rely on the Java
    sandbox for security. This vulnerability does not apply
    to Java deployments, typically in servers, that load
    and run only trusted code (e.g., code installed by an
    administrator).(CVE-2020-14798)

  - Vulnerability in the Java SE, Java SE Embedded product
    of Oracle Java SE (component: Libraries). Supported
    versions that are affected are Java SE: 7u271, 8u261,
    11.0.8 and 15 Java SE Embedded: 8u261. Difficult to
    exploit vulnerability allows unauthenticated attacker
    with network access via multiple protocols to
    compromise Java SE, Java SE Embedded. Successful
    attacks of this vulnerability can result in
    unauthorized update, insert or delete access to some of
    Java SE, Java SE Embedded accessible data. Note:
    Applies to client and server deployment of Java. This
    vulnerability can be exploited through sandboxed Java
    Web Start applications and sandboxed Java applets. It
    can also be exploited by supplying data to APIs in the
    specified Component without using sandboxed Java Web
    Start applications or sandboxed Java applets, such as
    through a web service.(CVE-2020-14782)

  - Vulnerability in the Java SE, Java SE Embedded product
    of Oracle Java SE (component: Libraries). Supported
    versions that are affected are Java SE: 7u271, 8u261,
    11.0.8 and 15 Java SE Embedded: 8u261. Difficult to
    exploit vulnerability allows unauthenticated attacker
    with network access via multiple protocols to
    compromise Java SE, Java SE Embedded. Successful
    attacks require human interaction from a person other
    than the attacker. Successful attacks of this
    vulnerability can result in unauthorized read access to
    a subset of Java SE, Java SE Embedded accessible data.
    Note: This vulnerability applies to Java deployments,
    typically in clients running sandboxed Java Web Start
    applications or sandboxed Java applets, that load and
    run untrusted code (e.g., code that comes from the
    internet) and rely on the Java sandbox for security.
    This vulnerability does not apply to Java deployments,
    typically in servers, that load and run only trusted
    code (e.g., code installed by an
    administrator).(CVE-2020-14796)

  - Vulnerability in the Java SE, Java SE Embedded product
    of Oracle Java SE (component: Libraries). Supported
    versions that are affected are Java SE: 7u271, 8u261,
    11.0.8 and 15 Java SE Embedded: 8u261. Difficult to
    exploit vulnerability allows unauthenticated attacker
    with network access via multiple protocols to
    compromise Java SE, Java SE Embedded. Successful
    attacks of this vulnerability can result in
    unauthorized update, insert or delete access to some of
    Java SE, Java SE Embedded accessible data. Note:
    Applies to client and server deployment of Java. This
    vulnerability can be exploited through sandboxed Java
    Web Start applications and sandboxed Java applets. It
    can also be exploited by supplying data to APIs in the
    specified Component without using sandboxed Java Web
    Start applications or sandboxed Java applets, such as
    through a web service.(CVE-2020-14797)

  - Vulnerability in the Java SE product of Oracle Java SE
    (component: Libraries). Supported versions that are
    affected are Java SE: 11.0.8 and 15. Easily exploitable
    vulnerability allows unauthenticated attacker with
    network access via multiple protocols to compromise
    Java SE. Successful attacks of this vulnerability can
    result in unauthorized read access to a subset of Java
    SE accessible data. Note: This vulnerability applies to
    Java deployments, typically in clients running
    sandboxed Java Web Start applications or sandboxed Java
    applets, that load and run untrusted code (e.g., code
    that comes from the internet) and rely on the Java
    sandbox for security. This vulnerability does not apply
    to Java deployments, typically in servers, that load
    and run only trusted code (e.g., code installed by an
    administrator).(CVE-2020-14803)

  - Vulnerability in the Java SE, Java SE Embedded product
    of Oracle Java SE (component: Scripting). Supported
    versions that are affected are Java SE: 8u241, 11.0.6
    and 14 Java SE Embedded: 8u241. Difficult to exploit
    vulnerability allows unauthenticated attacker with
    network access via multiple protocols to compromise
    Java SE, Java SE Embedded. Successful attacks of this
    vulnerability can result in unauthorized ability to
    cause a partial denial of service (partial DOS) of Java
    SE, Java SE Embedded.(CVE-2020-2754)

  - Vulnerability in the Java SE, Java SE Embedded product
    of Oracle Java SE (component: Scripting). Supported
    versions that are affected are Java SE: 8u241, 11.0.6
    and 14 Java SE Embedded: 8u241. Difficult to exploit
    vulnerability allows unauthenticated attacker with
    network access via multiple protocols to compromise
    Java SE, Java SE Embedded. Successful attacks of this
    vulnerability can result in unauthorized ability to
    cause a partial denial of service (partial DOS) of Java
    SE, Java SE Embedded.(CVE-2020-2755)

  - Vulnerability in the Java SE, Java SE Embedded product
    of Oracle Java SE (component: Serialization). Supported
    versions that are affected are Java SE: 7u251, 8u241,
    11.0.6 and 14 Java SE Embedded: 8u241. Difficult to
    exploit vulnerability allows unauthenticated attacker
    with network access via multiple protocols to
    compromise Java SE, Java SE Embedded. Successful
    attacks of this vulnerability can result in
    unauthorized ability to cause a partial denial of
    service (partial DOS) of Java SE, Java SE
    Embedded.(CVE-2020-2756)

  - Vulnerability in the Java SE, Java SE Embedded product
    of Oracle Java SE (component: Serialization). Supported
    versions that are affected are Java SE: 7u251, 8u241,
    11.0.6 and 14 Java SE Embedded: 8u241. Difficult to
    exploit vulnerability allows unauthenticated attacker
    with network access via multiple protocols to
    compromise Java SE, Java SE Embedded. Successful
    attacks of this vulnerability can result in
    unauthorized ability to cause a partial denial of
    service (partial DOS) of Java SE, Java SE
    Embedded.(CVE-2020-2757)

  - Vulnerability in the Java SE, Java SE Embedded product
    of Oracle Java SE (component: Security). Supported
    versions that are affected are Java SE: 7u251, 8u241,
    11.0.6 and 14 Java SE Embedded: 8u241. Difficult to
    exploit vulnerability allows unauthenticated attacker
    with network access via multiple protocols to
    compromise Java SE, Java SE Embedded. Successful
    attacks of this vulnerability can result in
    unauthorized ability to cause a partial denial of
    service (partial DOS) of Java SE, Java SE
    Embedded.(CVE-2020-2773)

  - Vulnerability in the Java SE, Java SE Embedded product
    of Oracle Java SE (component: JSSE). Supported versions
    that are affected are Java SE: 7u251, 8u241, 11.0.6 and
    14 Java SE Embedded: 8u241. Easily exploitable
    vulnerability allows unauthenticated attacker with
    network access via HTTPS to compromise Java SE, Java SE
    Embedded. Successful attacks of this vulnerability can
    result in unauthorized ability to cause a partial
    denial of service (partial DOS) of Java SE, Java SE
    Embedded.(CVE-2020-2781)

  - Vulnerability in the Java SE, Java SE Embedded product
    of Oracle Java SE (component: Lightweight HTTP Server).
    Supported versions that are affected are Java SE:
    7u251, 8u241, 11.0.6 and 14 Java SE Embedded: 8u241.
    Difficult to exploit vulnerability allows
    unauthenticated attacker with network access via
    multiple protocols to compromise Java SE, Java SE
    Embedded. Successful attacks of this vulnerability can
    result in unauthorized update, insert or delete access
    to some of Java SE, Java SE Embedded accessible data as
    well as unauthorized read access to a subset of Java
    SE, Java SE Embedded accessible data.(CVE-2020-2800)

  - Vulnerability in the Java SE, Java SE Embedded product
    of Oracle Java SE (component: Concurrency). Supported
    versions that are affected are Java SE: 7u251, 8u241,
    11.0.6 and 14 Java SE Embedded: 8u241. Easily
    exploitable vulnerability allows unauthenticated
    attacker with network access via multiple protocols to
    compromise Java SE, Java SE Embedded. Successful
    attacks of this vulnerability can result in
    unauthorized ability to cause a partial denial of
    service (partial DOS) of Java SE, Java SE
    Embedded.(CVE-2020-2830)

  - Vulnerability in the Java SE, Java SE Embedded product
    of Oracle Java SE (component: 2D). Supported versions
    that are affected are Java SE: 8u251, 11.0.7 and 14.0.1
    Java SE Embedded: 8u251. Difficult to exploit
    vulnerability allows unauthenticated attacker with
    network access via multiple protocols to compromise
    Java SE, Java SE Embedded. Successful attacks of this
    vulnerability can result in unauthorized read access to
    a subset of Java SE, Java SE Embedded accessible
    data.(CVE-2020-14581)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1078
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cc613330");
  script_set_attribute(attribute:"solution", value:
"Update the affected java-1.8.0-openjdk packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-2800");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:java-1.8.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:java-1.8.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:java-1.8.0-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0");

sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(3)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["java-1.8.0-openjdk-1.8.0.191.b12-0.h13",
        "java-1.8.0-openjdk-devel-1.8.0.191.b12-0.h13",
        "java-1.8.0-openjdk-headless-1.8.0.191.b12-0.h13"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"3", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.8.0-openjdk");
}
