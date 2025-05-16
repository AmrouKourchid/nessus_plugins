#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2024-2264.
##

include('compat.inc');

if (description)
{
  script_id(195049);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/02");

  script_cve_id(
    "CVE-2022-36763",
    "CVE-2022-36764",
    "CVE-2023-3446",
    "CVE-2023-45229",
    "CVE-2023-45231",
    "CVE-2023-45232",
    "CVE-2023-45233",
    "CVE-2023-45235"
  );

  script_name(english:"Oracle Linux 9 : edk2 (ELSA-2024-2264)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2024-2264 advisory.

    - edk2-NetworkPkg-Dhcp6Dxe-SECURITY-PATCH-CVE-2023-45230-Pa.patch [RHEL-21841 RHEL-21843 RHEL-21845
    RHEL-21847 RHEL-21849 RHEL-21851 RHEL-21853]
    - edk2-NetworkPkg-Dhcp6Dxe-SECURITY-PATCH-CVE-2023-45230-Un.patch [RHEL-21841 RHEL-21843 RHEL-21845
    RHEL-21847 RHEL-21849 RHEL-21851 RHEL-21853]
    - edk2-NetworkPkg-Dhcp6Dxe-SECURITY-PATCH-CVE-2023-45229-Pa.patch [RHEL-21841 RHEL-21843 RHEL-21845
    RHEL-21847 RHEL-21849 RHEL-21851 RHEL-21853]
    - edk2-NetworkPkg-Dhcp6Dxe-SECURITY-PATCH-CVE-2023-45229-Un.patch [RHEL-21841 RHEL-21843 RHEL-21845
    RHEL-21847 RHEL-21849 RHEL-21851 RHEL-21853]
    - edk2-NetworkPkg-Ip6Dxe-SECURITY-PATCH-CVE-2023-45231-Patc.patch [RHEL-21841 RHEL-21843 RHEL-21845
    RHEL-21847 RHEL-21849 RHEL-21851 RHEL-21853]
    - edk2-NetworkPkg-Ip6Dxe-SECURITY-PATCH-CVE-2023-45231-Unit.patch [RHEL-21841 RHEL-21843 RHEL-21845
    RHEL-21847 RHEL-21849 RHEL-21851 RHEL-21853]
    - edk2-NetworkPkg-Ip6Dxe-SECURITY-PATCH-CVE-2023-45232-Patc.patch [RHEL-21841 RHEL-21843 RHEL-21845
    RHEL-21847 RHEL-21849 RHEL-21851 RHEL-21853]
    - edk2-NetworkPkg-Ip6Dxe-SECURITY-PATCH-CVE-2023-45232-Unit.patch [RHEL-21841 RHEL-21843 RHEL-21845
    RHEL-21847 RHEL-21849 RHEL-21851 RHEL-21853]
    - edk2-NetworkPkg-UefiPxeBcDxe-SECURITY-PATCH-CVE-2023-4523.patch [RHEL-21841 RHEL-21843 RHEL-21845
    RHEL-21847 RHEL-21849 RHEL-21851 RHEL-21853]
    - edk2-NetworkPkg-UefiPxeBcDxe-SECURITY-PATCH-CVE-2023-4523p2.patch [RHEL-21841 RHEL-21843 RHEL-21845
    RHEL-21847 RHEL-21849 RHEL-21851 RHEL-21853]
    - edk2-NetworkPkg-UefiPxeBcDxe-SECURITY-PATCH-CVE-2023-4523p3.patch [RHEL-21841 RHEL-21843 RHEL-21845
    RHEL-21847 RHEL-21849 RHEL-21851 RHEL-21853]
    - edk2-NetworkPkg-UefiPxeBcDxe-SECURITY-PATCH-CVE-2023-4523p4.patch [RHEL-21841 RHEL-21843 RHEL-21845
    RHEL-21847 RHEL-21849 RHEL-21851 RHEL-21853]
    - edk2-NetworkPkg-Dhcp6Dxe-SECURITY-PATCH-CVE-2023-45229-Re.patch [RHEL-21841 RHEL-21843 RHEL-21845
    RHEL-21847 RHEL-21849 RHEL-21851 RHEL-21853]
    - Resolves: RHEL-21841
      (CVE-2023-45229 edk2: Integer underflow when processing IA_NA/IA_TA options in a DHCPv6 Advertise
    message [rhel-9])
    - Resolves: RHEL-21843
      (CVE-2023-45230 edk2: Buffer overflow in the DHCPv6 client via a long Server ID option [rhel-9])
    - Resolves: RHEL-21845
      (CVE-2023-45231 edk2: Out of Bounds read when handling a ND Redirect message with truncated options
    [rhel-9])
    - Resolves: RHEL-21847
      (CVE-2023-45232 edk2: Infinite loop when parsing unknown options in the Destination Options header
    [rhel-9])
    - Resolves: RHEL-21849
      (TRIAGE CVE-2023-45233 edk2: Infinite loop when parsing a PadN option in the Destination Options header
    [rhel-9])
    - Resolves: RHEL-21851
      (CVE-2023-45234 edk2: Buffer overflow when processing DNS Servers option in a DHCPv6 Advertise message
    [rhel-9])
    - Resolves: RHEL-21853
      (TRIAGE CVE-2023-45235 edk2: Buffer overflow when handling Server ID option from a DHCPv6 proxy
    Advertise message [rhel-9])
    - Resolves: RHEL-21157
      (CVE-2022-36764 edk2: heap buffer overflow in Tcg2MeasurePeImage() [rhel-9])
    - edk2-SecurityPkg-Adding-CVE-2022-36763-to-SecurityFixes.y.patch [RHEL-21155]
    - Resolves: RHEL-21155
      (CVE-2022-36763 edk2: heap buffer overflow in Tcg2MeasureGptTable() [rhel-9])

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2024-2264.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:P");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-45235");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2023-3446");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/07/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:9:4:appstream_base");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:9::appstream");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:9::codeready_builder");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:edk2-aarch64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:edk2-ovmf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:edk2-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:edk2-tools-doc");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_release = get_kb_item("Host/RedHat/release");
if (isnull(os_release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:os_release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 9', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var pkgs = [
    {'reference':'edk2-aarch64-20231122-6.0.1.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'edk2-tools-20231122-6.0.1.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'edk2-tools-doc-20231122-6.0.1.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'edk2-ovmf-20231122-6.0.1.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'edk2-tools-20231122-6.0.1.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'edk2-tools-doc-20231122-6.0.1.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE}
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
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = 'EL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release) {
    if (exists_check) {
        if (rpm_exists(release:_release, rpm:exists_check) && rpm_check(release:_release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    } else {
        if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    }
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'edk2-aarch64 / edk2-ovmf / edk2-tools / etc');
}
