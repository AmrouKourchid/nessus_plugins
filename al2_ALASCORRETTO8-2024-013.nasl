#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALASCORRETTO8-2024-013.
##

include('compat.inc');

if (description)
{
  script_id(202985);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/11");

  script_cve_id(
    "CVE-2024-21131",
    "CVE-2024-21138",
    "CVE-2024-21140",
    "CVE-2024-21144",
    "CVE-2024-21145",
    "CVE-2024-21147"
  );

  script_name(english:"Amazon Linux 2 : java-1.8.0-amazon-corretto (ALASCORRETTO8-2024-013)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of java-1.8.0-amazon-corretto installed on the remote host is prior to 1.8.0_422.b05-1. It is, therefore,
affected by multiple vulnerabilities as referenced in the ALAS2CORRETTO8-2024-013 advisory.

    Vulnerability in the Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition product of
    Oracle Java SE (component: Hotspot).  Supported versions that are affected are Oracle Java SE: 8u411,
    8u411-perf, 11.0.23, 17.0.11, 21.0.3, 22.0.1; Oracle GraalVM for JDK: 17.0.11, 21.0.3, 22.0.1; Oracle
    GraalVM Enterprise Edition: 20.3.14 and  21.3.10. Difficult to exploit vulnerability allows
    unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE, Oracle
    GraalVM for JDK, Oracle GraalVM Enterprise Edition.  Successful attacks of this vulnerability can result
    in  unauthorized update, insert or delete access to some of Oracle Java SE, Oracle GraalVM for JDK, Oracle
    GraalVM Enterprise Edition accessible data. Note: This vulnerability can be exploited by using APIs in the
    specified Component, e.g., through a web service which supplies data to the APIs. This vulnerability also
    applies to Java deployments, typically in clients running sandboxed Java Web Start applications or
    sandboxed Java applets, that load and run untrusted code (e.g., code that comes from the internet) and
    rely on the Java sandbox for security. CVSS 3.1 Base Score 3.7 (Integrity impacts).  CVSS Vector:
    (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N). (CVE-2024-21131)

    Vulnerability in the Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition product of
    Oracle Java SE (component: Hotspot).  Supported versions that are affected are Oracle Java SE: 8u411,
    8u411-perf, 11.0.23, 17.0.11, 21.0.3, 22.0.1; Oracle GraalVM for JDK: 17.0.11, 21.0.3, 22.0.1; Oracle
    GraalVM Enterprise Edition: 20.3.14 and  21.3.10. Difficult to exploit vulnerability allows
    unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE, Oracle
    GraalVM for JDK, Oracle GraalVM Enterprise Edition.  Successful attacks of this vulnerability can result
    in unauthorized ability to cause a partial denial of service (partial DOS) of Oracle Java SE, Oracle
    GraalVM for JDK, Oracle GraalVM Enterprise Edition. Note: This vulnerability can be exploited by using
    APIs in the specified Component, e.g., through a web service which supplies data to the APIs. This
    vulnerability also applies to Java deployments, typically in clients running sandboxed Java Web Start
    applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from the
    internet) and rely on the Java sandbox for security. CVSS 3.1 Base Score 3.7 (Availability impacts).  CVSS
    Vector: (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L). (CVE-2024-21138)

    Vulnerability in the Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition product of
    Oracle Java SE (component: Hotspot).  Supported versions that are affected are Oracle Java SE: 8u411,
    8u411-perf, 11.0.23, 17.0.11, 21.0.3, 22.0.1; Oracle GraalVM for JDK: 17.0.11, 21.0.3, 22.0.1; Oracle
    GraalVM Enterprise Edition: 20.3.14 and  21.3.10. Difficult to exploit vulnerability allows
    unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE, Oracle
    GraalVM for JDK, Oracle GraalVM Enterprise Edition.  Successful attacks of this vulnerability can result
    in  unauthorized update, insert or delete access to some of Oracle Java SE, Oracle GraalVM for JDK, Oracle
    GraalVM Enterprise Edition accessible data as well as  unauthorized read access to a subset of Oracle Java
    SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition accessible data. Note: This vulnerability
    can be exploited by using APIs in the specified Component, e.g., through a web service which supplies data
    to the APIs. This vulnerability also applies to Java deployments, typically in clients running sandboxed
    Java Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g., code that
    comes from the internet) and rely on the Java sandbox for security. CVSS 3.1 Base Score 4.8
    (Confidentiality and Integrity impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N).
    (CVE-2024-21140)

    Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE
    (component: Concurrency).  Supported versions that are affected are Oracle Java SE: 8u411, 8u411-perf,
    11.0.23; Oracle GraalVM Enterprise Edition: 20.3.14 and  21.3.10. Difficult to exploit vulnerability
    allows unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE,
    Oracle GraalVM Enterprise Edition.  Successful attacks of this vulnerability can result in unauthorized
    ability to cause a partial denial of service (partial DOS) of Oracle Java SE, Oracle GraalVM Enterprise
    Edition. Note: This vulnerability applies to Java deployments, typically in clients running sandboxed Java
    Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes
    from the internet) and rely on the Java sandbox for security. This vulnerability does not apply to Java
    deployments, typically in servers, that load and run only trusted code (e.g., code installed by an
    administrator). CVSS 3.1 Base Score 3.7 (Availability impacts).  CVSS Vector:
    (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L). (CVE-2024-21144)

    Vulnerability in the Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition product of
    Oracle Java SE (component: 2D).  Supported versions that are affected are Oracle Java SE: 8u411,
    8u411-perf, 11.0.23, 17.0.11, 21.0.3, 22.0.1; Oracle GraalVM for JDK: 17.0.11, 21.0.3, 22.0.1; Oracle
    GraalVM Enterprise Edition: 20.3.14 and  21.3.10. Difficult to exploit vulnerability allows
    unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE, Oracle
    GraalVM for JDK, Oracle GraalVM Enterprise Edition.  Successful attacks of this vulnerability can result
    in  unauthorized update, insert or delete access to some of Oracle Java SE, Oracle GraalVM for JDK, Oracle
    GraalVM Enterprise Edition accessible data as well as  unauthorized read access to a subset of Oracle Java
    SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition accessible data. Note: This vulnerability
    can be exploited by using APIs in the specified Component, e.g., through a web service which supplies data
    to the APIs. This vulnerability also applies to Java deployments, typically in clients running sandboxed
    Java Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g., code that
    comes from the internet) and rely on the Java sandbox for security. CVSS 3.1 Base Score 4.8
    (Confidentiality and Integrity impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N).
    (CVE-2024-21145)

    Vulnerability in the Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition product of
    Oracle Java SE (component: Hotspot).  Supported versions that are affected are Oracle Java SE: 8u411,
    8u411-perf, 11.0.23, 17.0.11, 21.0.3, 22.0.1; Oracle GraalVM for JDK: 17.0.11, 21.0.3, 22.0.1; Oracle
    GraalVM Enterprise Edition: 20.3.14 and  21.3.10. Difficult to exploit vulnerability allows
    unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE, Oracle
    GraalVM for JDK, Oracle GraalVM Enterprise Edition.  Successful attacks of this vulnerability can result
    in  unauthorized creation, deletion or modification access to critical data or all Oracle Java SE, Oracle
    GraalVM for JDK, Oracle GraalVM Enterprise Edition accessible data as well as  unauthorized access to
    critical data or complete access to all Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise
    Edition accessible data. Note: This vulnerability can be exploited by using APIs in the specified
    Component, e.g., through a web service which supplies data to the APIs. This vulnerability also applies to
    Java deployments, typically in clients running sandboxed Java Web Start applications or sandboxed Java
    applets, that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java
    sandbox for security. CVSS 3.1 Base Score 7.4 (Confidentiality and Integrity impacts).  CVSS Vector:
    (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N). (CVE-2024-21147)

Tenable has extracted the preceding description block directly from the tested product security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALASCORRETTO8-2024-013.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-21131.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-21138.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-21140.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-21144.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-21145.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-21147.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update java-1.8.0-amazon-corretto' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-21147");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.8.0-amazon-corretto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.8.0-amazon-corretto-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var alas_release = get_kb_item("Host/AmazonLinux/release");
if (isnull(alas_release) || !strlen(alas_release)) audit(AUDIT_OS_NOT, "Amazon Linux");
var os_ver = pregmatch(pattern: "^AL(A|\d+|-\d+)", string:alas_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var REPOS_FOUND = TRUE;
var extras_list = get_kb_item("Host/AmazonLinux/extras_label_list");
if (isnull(extras_list)) REPOS_FOUND = FALSE;
var repository = '"amzn2extra-corretto8"';
if (REPOS_FOUND && (repository >!< extras_list)) exit(0, AFFECTED_REPO_NOT_ENABLED);

var pkgs = [
    {'reference':'java-1.8.0-amazon-corretto-1.8.0_422.b05-1.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'corretto8'},
    {'reference':'java-1.8.0-amazon-corretto-1.8.0_422.b05-1.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'corretto8'},
    {'reference':'java-1.8.0-amazon-corretto-devel-1.8.0_422.b05-1.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'corretto8'},
    {'reference':'java-1.8.0-amazon-corretto-devel-1.8.0_422.b05-1.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'corretto8'}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  var cves = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['cves'])) cves = package_array['cves'];
  if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj, cves:cves)) flag++;
  }
}

if (flag)
{
  var extra = rpm_report_get();
  if (!REPOS_FOUND) extra = rpm_report_get() + report_repo_caveat();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.8.0-amazon-corretto / java-1.8.0-amazon-corretto-devel");
}
