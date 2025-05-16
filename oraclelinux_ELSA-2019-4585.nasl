#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2019-4585.
##

include('compat.inc');

if (description)
{
  script_id(180740);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/22");

  script_cve_id(
    "CVE-2017-2630",
    "CVE-2017-2633",
    "CVE-2017-5715",
    "CVE-2017-5753",
    "CVE-2017-5754",
    "CVE-2017-7471",
    "CVE-2017-7493",
    "CVE-2017-8112",
    "CVE-2017-8309",
    "CVE-2017-8379",
    "CVE-2017-8380",
    "CVE-2017-9503",
    "CVE-2017-10806",
    "CVE-2017-11334",
    "CVE-2017-12809",
    "CVE-2017-13672",
    "CVE-2017-13673",
    "CVE-2017-13711",
    "CVE-2017-14167",
    "CVE-2017-15038",
    "CVE-2017-15119",
    "CVE-2017-15124",
    "CVE-2017-15268",
    "CVE-2017-15289",
    "CVE-2017-16845",
    "CVE-2017-17381",
    "CVE-2017-18030",
    "CVE-2017-18043",
    "CVE-2018-3639",
    "CVE-2018-5683",
    "CVE-2018-7550",
    "CVE-2018-7858",
    "CVE-2018-10839",
    "CVE-2018-11806",
    "CVE-2018-12617",
    "CVE-2018-15746",
    "CVE-2018-16847",
    "CVE-2018-16867",
    "CVE-2018-16872",
    "CVE-2018-17958",
    "CVE-2018-17962",
    "CVE-2018-17963",
    "CVE-2018-18849",
    "CVE-2018-19364",
    "CVE-2018-19489",
    "CVE-2018-20124",
    "CVE-2018-20125",
    "CVE-2018-20126",
    "CVE-2018-20191",
    "CVE-2018-20216"
  );
  script_xref(name:"IAVA", value:"2018-A-0017-S");
  script_xref(name:"IAVA", value:"2018-A-0019");
  script_xref(name:"IAVA", value:"2018-A-0020");
  script_xref(name:"IAVA", value:"2018-A-0022-S");
  script_xref(name:"IAVA", value:"2018-A-0170");

  script_name(english:"Oracle Linux 7 : qemu (ELSA-2019-4585)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2019-4585 advisory.

    - usb-mtp: use O_NOFOLLOW and O_CLOEXEC. (Gerd Hoffmann)  [Orabug: 29216656]  {CVE-2018-16872}
    - pvrdma: add uar_read routine (Prasad J Pandit)  [Orabug: 29216658]  {CVE-2018-20191}
    - pvrdma: release ring object in case of an error (Prasad J Pandit)  [Orabug: 29216659]  {CVE-2018-20126}
    - pvrdma: check number of pages when creating rings (Prasad J Pandit)  [Orabug: 29216666]
    {CVE-2018-20125}
    - pvrdma: check return value from pvrdma_idx_ring_has_ routines (Prasad J Pandit)  [Orabug: 29216672]
    {CVE-2018-20216}
    - rdma: remove unused VENDOR_ERR_NO_SGE macro (Prasad J Pandit)  [Orabug: 29216678]  {CVE-2018-20124}
    - rdma: check num_sge does not exceed MAX_SGE (Prasad J Pandit)  [Orabug: 29216678]  {CVE-2018-20124}
    - Document various CVEs as fixed (Mark Kanda)  [Orabug: 29212424]  {CVE-2017-10806} {CVE-2017-11334}
    {CVE-2017-12809} {CVE-2017-13672} {CVE-2017-13673} {CVE-2017-13711} {CVE-2017-14167} {CVE-2017-15038}
    {CVE-2017-15119} {CVE-2017-15124} {CVE-2017-15268} {CVE-2017-15289} {CVE-2017-16845} {CVE-2017-17381}
    {CVE-2017-18030} {CVE-2017-18043} {CVE-2017-2630} {CVE-2017-2633} {CVE-2017-5715} {CVE-2017-5753}
    {CVE-2017-5754} {CVE-2017-7471} {CVE-2017-7493} {CVE-2017-8112} {CVE-2017-8309} {CVE-2017-8379}
    {CVE-2017-8380} {CVE-2017-9503} {CVE-2018-10839} {CVE-2018-11806} {CVE-2018-12617} {CVE-2018-15746}
    {CVE-2018-16847} {CVE-2018-16867} {CVE-2018-17958} {CVE-2018-17962} {CVE-2018-17963} {CVE-2018-18849}
    {CVE-2018-19364} {CVE-2018-19489} {CVE-2018-3639} {CVE-2018-5683} {CVE-2018-7550} {CVE-2018-7858}

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2019-4585.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-7471");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2017-16845");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/02/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ivshmem-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-block-gluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-block-iscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-block-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-img");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-kvm-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-system-aarch64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-system-aarch64-core");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 7', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);
if ('aarch64' >!< cpu) audit(AUDIT_ARCH_NOT, 'aarch64', cpu);

var pkgs = [
    {'reference':'ivshmem-tools-3.1.0-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-3.1.0-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-block-gluster-3.1.0-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-block-iscsi-3.1.0-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-block-rbd-3.1.0-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-common-3.1.0-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-img-3.1.0-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-3.1.0-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-core-3.1.0-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-system-aarch64-3.1.0-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-system-aarch64-core-3.1.0-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ivshmem-tools / qemu / qemu-block-gluster / etc');
}
