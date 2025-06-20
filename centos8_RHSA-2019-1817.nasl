##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# Red Hat Security Advisory RHSA-2019:1817. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(145663);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/20");

  script_cve_id(
    "CVE-2019-2745",
    "CVE-2019-2762",
    "CVE-2019-2769",
    "CVE-2019-2786",
    "CVE-2019-2816",
    "CVE-2019-2818",
    "CVE-2019-2821"
  );
  script_bugtraq_id(
    109184,
    109185,
    109186,
    109187,
    109188,
    109201,
    109210
  );
  script_xref(name:"RHSA", value:"2019:1817");

  script_name(english:"CentOS 8 : java-11-openjdk (CESA-2019:1817)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
CESA-2019:1817 advisory.

  - OpenJDK: Side-channel attack risks in Elliptic Curve (EC) cryptography (Security, 8208698) (CVE-2019-2745)

  - OpenJDK: Insufficient checks of suppressed exceptions in deserialization (Utilities, 8212328)
    (CVE-2019-2762)

  - OpenJDK: Unbounded memory allocation during deserialization in Collections (Utilities, 8213432)
    (CVE-2019-2769)

  - OpenJDK: Insufficient restriction of privileges in AccessController (Security, 8216381) (CVE-2019-2786)

  - OpenJDK: Missing URL format validation (Networking, 8221518) (CVE-2019-2816)

  - OpenJDK: Non-constant time comparison in ChaCha20Cipher (Security, 8221344) (CVE-2019-2818)

  - OpenJDK: Incorrect handling of certificate status messages during TLS handshake (JSSE, 8222678)
    (CVE-2019-2821)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2019:1817");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-2816");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-2821");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-11-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-11-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-11-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-11-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-11-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-11-openjdk-javadoc-zip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-11-openjdk-jmods");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-11-openjdk-src");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list", "Host/cpu");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item('Host/CentOS/release');
if (isnull(release) || 'CentOS' >!< release) audit(AUDIT_OS_NOT, 'CentOS');
os_ver = pregmatch(pattern: "CentOS(?: Stream)?(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'CentOS');
os_ver = os_ver[1];
if ('CentOS Stream' >< release) audit(AUDIT_OS_NOT, 'CentOS 8.x', 'CentOS Stream ' + os_ver);
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '8')) audit(AUDIT_OS_NOT, 'CentOS 8.x', 'CentOS ' + os_ver);

if (!get_kb_item('Host/CentOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'CentOS', cpu);

pkgs = [
    {'reference':'java-11-openjdk-11.0.4.11-0.el8_0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-11-openjdk-11.0.4.11-0.el8_0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-11-openjdk-demo-11.0.4.11-0.el8_0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-11-openjdk-demo-11.0.4.11-0.el8_0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-11-openjdk-devel-11.0.4.11-0.el8_0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-11-openjdk-devel-11.0.4.11-0.el8_0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-11-openjdk-headless-11.0.4.11-0.el8_0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-11-openjdk-headless-11.0.4.11-0.el8_0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-11-openjdk-javadoc-11.0.4.11-0.el8_0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-11-openjdk-javadoc-11.0.4.11-0.el8_0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-11-openjdk-javadoc-zip-11.0.4.11-0.el8_0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-11-openjdk-javadoc-zip-11.0.4.11-0.el8_0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-11-openjdk-jmods-11.0.4.11-0.el8_0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-11-openjdk-jmods-11.0.4.11-0.el8_0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-11-openjdk-src-11.0.4.11-0.el8_0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-11-openjdk-src-11.0.4.11-0.el8_0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
];

flag = 0;
foreach package_array ( pkgs ) {
  reference = NULL;
  release = NULL;
  sp = NULL;
  cpu = NULL;
  el_string = NULL;
  rpm_spec_vers_cmp = NULL;
  epoch = NULL;
  allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = 'CentOS-' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && release) {
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'java-11-openjdk / java-11-openjdk-demo / java-11-openjdk-devel / etc');
}
