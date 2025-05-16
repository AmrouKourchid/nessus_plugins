#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2024-12407.
##

include('compat.inc');

if (description)
{
  script_id(200094);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/05");

  script_cve_id(
    "CVE-2021-3750",
    "CVE-2023-3019",
    "CVE-2023-5088",
    "CVE-2023-6683",
    "CVE-2023-6693",
    "CVE-2023-42467",
    "CVE-2024-24474"
  );
  script_xref(name:"IAVB", value:"2024-B-0070-S");

  script_name(english:"Oracle Linux 9 : qemu-kvm (ELSA-2024-12407)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2024-12407 advisory.

    - ui/clipboard: add asserts for update and request (Fiona Ebner) [Orabug: 36323175] {CVE-2023-6683}
    - ui/clipboard: mark type as not available when there is no data (Fiona Ebner) [Orabug: 36323175]
    {CVE-2023-6683}
    - virtio-net: correctly copy vnet header when flushing TX (Jason Wang) [Orabug: 36154459] {CVE-2023-6693}
    - esp: restrict non-DMA transfer length to that of available data (Mark Cave-Ayland) [Orabug: 36322141]
    {CVE-2024-24474}
    - net: Update MemReentrancyGuard for NIC (Akihiko Odaki) [Orabug: 35644197] {CVE-2023-3019}
    - net: Provide MemReentrancyGuard * to qemu_new_nic() (Akihiko Odaki) [Orabug: 35644197] {CVE-2023-3019}
    - lsi53c895a: disable reentrancy detection for MMIO region, too (Thomas Huth) [Orabug: 33774027]
    {CVE-2021-3750}
    - memory: stricter checks prior to unsetting engaged_in_io (Alexander Bulekov) [Orabug: 33774027]
    {CVE-2021-3750}
    - async: avoid use-after-free on re-entrancy guard (Alexander Bulekov) [Orabug: 33774027] {CVE-2021-3750}
    - apic: disable reentrancy detection for apic-msi (Alexander Bulekov) [Orabug: 33774027] {CVE-2021-3750}
    - raven: disable reentrancy detection for iomem (Alexander Bulekov) [Orabug: 33774027] {CVE-2021-3750}
    - bcm2835_property: disable reentrancy detection for iomem (Alexander Bulekov) [Orabug: 33774027]
    {CVE-2021-3750}
    - lsi53c895a: disable reentrancy detection for script RAM (Alexander Bulekov) [Orabug: 33774027]
    {CVE-2021-3750}
    - hw: replace most qemu_bh_new calls with qemu_bh_new_guarded (Alexander Bulekov) [Orabug: 33774027]
    {CVE-2021-3750}
    - checkpatch: add qemu_bh_new/aio_bh_new checks (Alexander Bulekov) [Orabug: 33774027] {CVE-2021-3750}
    - async: Add an optional reentrancy guard to the BH API (Alexander Bulekov) [Orabug: 33774027]
    {CVE-2021-3750}
    - memory: prevent dma-reentracy issues (Alexander Bulekov) [Orabug: 33774027] {CVE-2021-3750}
    - hw/scsi/scsi-disk: Disallow block sizes smaller than 512 [CVE-2023-42467] (Thomas Huth) [Orabug:
    35808564] {CVE-2023-42467}
    - tests/qtest: ahci-test: add test exposing reset issue with pending callback (Fiona Ebner) [Orabug:
    35977245] {CVE-2023-5088}
    - hw/ide: reset: cancel async DMA operation before resetting state (Fiona Ebner) [Orabug: 35977245]
    {CVE-2023-5088}

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2024-12407.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3750");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:9::kvm_utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-guest-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-img");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-kvm-block-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-kvm-block-iscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-kvm-block-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-kvm-block-ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-kvm-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-kvm-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-virtiofsd");
  script_set_attribute(attribute:"generated_plugin", value:"former");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
    {'reference':'qemu-guest-agent-7.2.0-11.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'30'},
    {'reference':'qemu-img-7.2.0-11.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'30'},
    {'reference':'qemu-kvm-7.2.0-11.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'30'},
    {'reference':'qemu-kvm-block-curl-7.2.0-11.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'30'},
    {'reference':'qemu-kvm-block-iscsi-7.2.0-11.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'30'},
    {'reference':'qemu-kvm-block-rbd-7.2.0-11.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'30'},
    {'reference':'qemu-kvm-block-ssh-7.2.0-11.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'30'},
    {'reference':'qemu-kvm-common-7.2.0-11.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'30'},
    {'reference':'qemu-kvm-core-7.2.0-11.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'30'},
    {'reference':'qemu-virtiofsd-7.2.0-11.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'30'},
    {'reference':'qemu-guest-agent-7.2.0-11.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'30'},
    {'reference':'qemu-img-7.2.0-11.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'30'},
    {'reference':'qemu-kvm-7.2.0-11.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'30'},
    {'reference':'qemu-kvm-block-curl-7.2.0-11.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'30'},
    {'reference':'qemu-kvm-block-iscsi-7.2.0-11.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'30'},
    {'reference':'qemu-kvm-block-rbd-7.2.0-11.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'30'},
    {'reference':'qemu-kvm-block-ssh-7.2.0-11.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'30'},
    {'reference':'qemu-kvm-common-7.2.0-11.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'30'},
    {'reference':'qemu-kvm-core-7.2.0-11.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'30'},
    {'reference':'qemu-virtiofsd-7.2.0-11.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'30'}
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
        if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, require_epoch_match:TRUE, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    }
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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'qemu-guest-agent / qemu-img / qemu-kvm / etc');
}
