#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2014:0420 and 
# Oracle Linux Security Advisory ELSA-2014-0420 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(73662);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/22");

  script_cve_id(
    "CVE-2014-0142",
    "CVE-2014-0143",
    "CVE-2014-0144",
    "CVE-2014-0145",
    "CVE-2014-0146",
    "CVE-2014-0147",
    "CVE-2014-0148",
    "CVE-2014-0150"
  );
  script_bugtraq_id(
    66464,
    66472,
    66480,
    66481,
    66483,
    66484,
    66486,
    66821
  );
  script_xref(name:"RHSA", value:"2014:0420");

  script_name(english:"Oracle Linux 6 : qemu-kvm (ELSA-2014-0420)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 6 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2014-0420 advisory.

    - kvm-qcow2-Check-backing_file_offset-CVE-2014-0144.patch [bz#1079452 bz#1079453]
    - kvm-qcow2-Check-refcount-table-size-CVE-2014-0144.patch [bz#1079452 bz#1079453]
    - kvm-qcow2-Fix-new-L1-table-size-check-CVE-2014-0143.patch [bz#1079318 bz#1079319]
    - kvm-bochs-Check-catalog_size-header-field-CVE-2014-0143.patch [bz#1079318 bz#1079319]
    - kvm-bochs-Check-extent_size-header-field-CVE-2014-0142.patch [bz#1079313 bz#1079314]
    - kvm-vpc-Validate-block-size-CVE-2014-0142.patch [bz#1079313 bz#1079314]
    - kvm-dmg-prevent-chunk-buffer-overflow-CVE-2014-0145.patch [bz#1079323 bz#1079324]
    - kvm-block-Limit-request-size-CVE-2014-0143.patch [bz#1079318 bz#1079319]
    - kvm-parallels-Sanity-check-for-s-tracks-CVE-2014-0142.patch [bz#1079313 bz#1079314]
    - Resolves: bz#1078849
      (EMBARGOED CVE-2014-0150 qemu-kvm: qemu: virtio-net: buffer overflow in virtio_net_handle_mac() function
    [rhel-6.5.z])
    - Resolves: bz#1079313
      (CVE-2014-0142 qemu-kvm: qemu: crash by possible division by zero [rhel-6.5.z])
    - Resolves: bz#1079318
      (CVE-2014-0143 qemu-kvm: Qemu: block: multiple integer overflow flaws [rhel-6.5.z])
    - Resolves: bz#1079323
      (CVE-2014-0145 qemu-kvm: Qemu: prevent possible buffer overflows [rhel-6.5.z])
    - Resolves: bz#1079330
      (CVE-2014-0146 qemu-kvm: Qemu: qcow2: NULL dereference in qcow2_open() error path [rhel-6.5.z])
    - Resolves: bz#1079337
      (CVE-2014-0147 qemu-kvm: Qemu: block: possible crash due signed types or logic error [rhel-6.5.z])
    - Resolves: bz#1079343
      (CVE-2014-0148 qemu-kvm: Qemu: vhdx: bounds checking for block_size and logical_sector_size
    [rhel-6.5.z])
    - Resolves: bz#1079452
      (CVE-2014-0144 qemu-kvm: Qemu: block: missing input validation [rhel-6.5.z])

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2014-0420.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-0150");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2014-0144");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-guest-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-img");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-kvm-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 6', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var pkgs = [
    {'reference':'qemu-guest-agent-0.12.1.2-2.415.el6_5.8', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'qemu-img-0.12.1.2-2.415.el6_5.8', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'qemu-kvm-0.12.1.2-2.415.el6_5.8', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'qemu-kvm-tools-0.12.1.2-2.415.el6_5.8', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'qemu-guest-agent-0.12.1.2-2.415.el6_5.8', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'qemu-img-0.12.1.2-2.415.el6_5.8', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'qemu-kvm-0.12.1.2-2.415.el6_5.8', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'qemu-kvm-tools-0.12.1.2-2.415.el6_5.8', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'}
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
