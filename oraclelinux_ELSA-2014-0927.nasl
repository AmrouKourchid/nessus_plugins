#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2014:0927 and 
# Oracle Linux Security Advisory ELSA-2014-0927 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(76748);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/01");

  script_cve_id(
    "CVE-2013-4148",
    "CVE-2013-4149",
    "CVE-2013-4150",
    "CVE-2013-4151",
    "CVE-2013-4527",
    "CVE-2013-4529",
    "CVE-2013-4535",
    "CVE-2013-4536",
    "CVE-2013-4541",
    "CVE-2013-4542",
    "CVE-2013-6399",
    "CVE-2014-0182",
    "CVE-2014-0222",
    "CVE-2014-0223",
    "CVE-2014-3461"
  );
  script_bugtraq_id(
    66976,
    67357,
    67391,
    67392,
    67394,
    67483
  );
  script_xref(name:"RHSA", value:"2014:0927");

  script_name(english:"Oracle Linux 7 : qemu-kvm (ELSA-2014-0927)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2014-0927 advisory.

    - Resolves: bz#1095782
      (CVE-2014-0182 qemu-kvm: qemu: virtio: out-of-bounds buffer write on state load with invalid config_len
    [rhel-7.0.z])
    - kvm-qcow1-Validate-L2-table-size-CVE-2014-0222.patch [bz#1097229]
    - kvm-qcow1-Validate-image-size-CVE-2014-0223.patch [bz#1097236]
    - Resolves: bz#1095677
      (CVE-2013-4148 qemu-kvm: qemu: virtio-net: buffer overflow on invalid state load [rhel-7.0.z])
    - Resolves: bz#1095684
      (CVE-2013-4149 qemu-kvm: qemu: virtio-net: out-of-bounds buffer write on load [rhel-7.0.z])
    - Resolves: bz#1095689
      (CVE-2013-4150 qemu-kvm: qemu: virtio-net: out-of-bounds buffer write on invalid state load
    [rhel-7.0.z])
    - Resolves: bz#1095694
      (CVE-2013-4151 qemu-kvm: qemu: virtio: out-of-bounds buffer write on invalid state load [rhel-7.0.z])
    - Resolves: bz#1095706
      (CVE-2013-4527 qemu-kvm: qemu: hpet: buffer overrun on invalid state load [rhel-7.0.z])
    - Resolves: bz#1095714
      (CVE-2013-4529 qemu-kvm: qemu: hw/pci/pcie_aer.c: buffer overrun on invalid state load [rhel-7.0.z])
    - Resolves: bz#1095737
      (CVE-2013-6399 qemu-kvm: qemu: virtio: buffer overrun on incoming migration [rhel-7.0.z])
    - Resolves: bz#1095741
      (CVE-2013-4542 qemu-kvm: qemu: virtio-scsi: buffer overrun on invalid state load [rhel-7.0.z])
    - Resolves: bz#1095746
      (CVE-2013-4541 qemu-kvm: qemu: usb: insufficient sanity checking of setup_index+setup_len in post_load
    [rhel-7.0.z])
    - Resolves: bz#1095765
      (CVE-2013-4535 CVE-2013-4536 qemu-kvm: qemu: virtio: insufficient validation of num_sg when mapping
    [rhel-7.0.z])
    - Resolves: bz#1095782
      (CVE-2014-0182 qemu-kvm: qemu: virtio: out-of-bounds buffer write on state load with invalid config_len
    [rhel-7.0.z])
    - Resolves: bz#1096828
      (CVE-2014-3461 qemu-kvm: Qemu: usb: fix up post load checks [rhel-7.0.z])
    - Resolves: bz#1097229
      (CVE-2014-0222 qemu-kvm: Qemu: qcow1: validate L2 table size to avoid integer overflows [rhel-7.0.z])
    - Resolves: bz#1097236
      (CVE-2014-0223 qemu-kvm: Qemu: qcow1: validate image size to avoid out-of-bounds memory access
    [rhel-7.0.z])

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2014-0927.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-0222");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2013-4535");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libcacard");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libcacard-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libcacard-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-guest-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-img");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-kvm-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-kvm-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 7', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var pkgs = [
    {'reference':'libcacard-1.5.3-60.el7_0.5', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'10'},
    {'reference':'libcacard-devel-1.5.3-60.el7_0.5', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'10'},
    {'reference':'libcacard-tools-1.5.3-60.el7_0.5', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'10'},
    {'reference':'qemu-guest-agent-1.5.3-60.el7_0.5', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'10'},
    {'reference':'qemu-img-1.5.3-60.el7_0.5', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'10'},
    {'reference':'qemu-kvm-1.5.3-60.el7_0.5', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'10'},
    {'reference':'qemu-kvm-common-1.5.3-60.el7_0.5', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'10'},
    {'reference':'qemu-kvm-tools-1.5.3-60.el7_0.5', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'10'},
    {'reference':'libcacard-1.5.3-60.el7_0.5', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'10'},
    {'reference':'libcacard-devel-1.5.3-60.el7_0.5', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'10'},
    {'reference':'libcacard-tools-1.5.3-60.el7_0.5', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'10'},
    {'reference':'qemu-guest-agent-1.5.3-60.el7_0.5', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'10'},
    {'reference':'qemu-img-1.5.3-60.el7_0.5', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'10'},
    {'reference':'qemu-kvm-1.5.3-60.el7_0.5', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'10'},
    {'reference':'qemu-kvm-common-1.5.3-60.el7_0.5', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'10'},
    {'reference':'qemu-kvm-tools-1.5.3-60.el7_0.5', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'10'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libcacard / libcacard-devel / libcacard-tools / etc');
}
