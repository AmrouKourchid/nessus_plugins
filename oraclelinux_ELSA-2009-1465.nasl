#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2009:1465 and 
# Oracle Linux Security Advisory ELSA-2009-1465 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(67932);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/22");

  script_cve_id("CVE-2009-3290");
  script_bugtraq_id(36512);
  script_xref(name:"RHSA", value:"2009:1465");

  script_name(english:"Oracle Linux 5 : kvm (ELSA-2009-1465)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 5 host has packages installed that are affected by a vulnerability as referenced in the
ELSA-2009-1465 advisory.

    [83-105.0.1.el5_4.7]
    - Add kvm-add-oracle-workaround-for-libvirt-bug.patch

    [kvm-83-105.el5_4.7]
    - kvm-qemu-virtio-net-do-not-return-stack-pointer-from-fun.patch [bz#524557]
    - Resolves: bz#524557
      (QEMU crash (during virtio-net WHQL tests for Win2008 R2))

    [kvm-83-105.el5_4.6]
    - kvm-Revert-update_refcount-Write-complete-sectors.patch [bz#520693]
    - kvm-Revert-alloc_cluster_link_l2-Write-complete-sectors.patch [bz#520693]
    - kvm-Revert-Combined-patch-of-two-upstream-commits-the-se.patch [bz#520693]
    - kvm-Revert-qcow2-Update-multiple-refcounts-at-once.patch [bz#520693]
    - kvm-Revert-qcow2-Refactor-update_refcount.patch [bz#520693]
    - Related: bz#520693
      (Bad qcow2 performance with cache=off)

    [kvm-83-105.el5_4.5]
    - kvm-kernel-KVM-VMX-Optimize-vmx_get_cpl.patch [bz#524125 bz#524125]
    - kvm-kernel-KVM-x86-Disallow-hypercalls-for-guest-callers-in-rin.patch [bz#524125 bz#524125]
    - Resolves: bz#524125
      (kernel: KVM: x86: Disallow hypercalls for guest callers in rings > 0 [rhel-5.4.z])

    [83-105.el5_4.4]
    - kvm-kernel-reset-hflags-on-cpu-reset.patch [bz#520694]
    - Resolves: bz#520694
      (NMI filtering for AMD (Windows 2008 R2 KVM guest can not restart when set it as multiple cpus))

    [83-105.el5_4.3]
    - kvm-kernel-Fix-coalesced-interrupt-reporting-in-IOAPIC.patch [bz#521794]
    - kvm-kernel-VMX-Fix-cr8-exiting-control-clobbering-by-EPT.patch [bz#521793]
    - Resolves: bz#521793
      (windows 64 bit does vmexit on each cr8 access.)
    - Resolves: bz#521794
      (rtc-td-hack stopped working. Time drifts in windows)
    - kvm-qcow2-Refactor-update_refcount.patch [bz#520693]
    - kvm-qcow2-Update-multiple-refcounts-at-once.patch [bz#520693]
    - kvm-Combined-patch-of-two-upstream-commits-the-second-fi.patch [bz#520693]
    - kvm-alloc_cluster_link_l2-Write-complete-sectors.patch [bz#520693]
    - kvm-update_refcount-Write-complete-sectors.patch [bz#520693]
    - Resolves: bz#520693
      (Bad qcow2 performance with cache=off)

    [83-105.el5_4.2]
    - Update kversion to 2.6.18-164.el5 to match build root
    - kvm-kernel-add-nmi-support-to-svm.patch [bz#520694]
    - Resolves: bz#520694
      (NMI filtering for AMD (Windows 2008 R2 KVM guest can not restart when set it as multiple cpus))

    [83-105.el5_4.1]
    - Update kversion to 2.6.18-162.el5
    - kvm-Initialize-PS2-keyboard-mouse-state-on-reset.patch [bz#517855]
    - Resolves: bz#517855
      (guest not accepting keystrokes or mouse clicks after reboot)

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2009-1465.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2009-3290");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/09/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kmod-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kvm-qemu-img");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kvm-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

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
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 5', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);
if ('x86_64' >!< cpu) audit(AUDIT_ARCH_NOT, 'x86_64', cpu);

var pkgs = [
    {'reference':'kmod-kvm-83-105.0.1.el5_4.7', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kvm-83-105.0.1.el5_4.7', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kvm-qemu-img-83-105.0.1.el5_4.7', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kvm-tools-83-105.0.1.el5_4.7', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kmod-kvm / kvm / kvm-qemu-img / etc');
}
