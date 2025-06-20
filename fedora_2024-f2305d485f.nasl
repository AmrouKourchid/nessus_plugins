#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2024-f2305d485f
#

include('compat.inc');

if (description)
{
  script_id(190506);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/14");

  script_cve_id("CVE-2023-50711");
  script_xref(name:"FEDORA", value:"2024-f2305d485f");

  script_name(english:"Fedora 38 : firecracker / libkrun / rust-event-manager / rust-kvm-bindings / etc (2024-f2305d485f)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 38 host has packages installed that are affected by a vulnerability as referenced in the
FEDORA-2024-f2305d485f advisory.

    Update rust-vmm components and their consumers to address CVE-2023-50711

Tenable has extracted the preceding description block directly from the Fedora security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-f2305d485f");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-50711");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:38");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:firecracker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libkrun");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-event-manager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-kvm-bindings");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-kvm-ioctls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-linux-loader");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-userfaultfd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-versionize");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-vhost");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-vhost-user-backend");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-virtio-queue");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-vm-memory");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-vm-superio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-vmm-sys-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:virtiofsd");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Fedora' >!< os_release) audit(AUDIT_OS_NOT, 'Fedora');
var os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Fedora');
os_ver = os_ver[1];
if (! preg(pattern:"^38([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 38', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

var pkgs = [
    {'reference':'firecracker-1.6.0-6.fc38', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libkrun-1.7.2-4.fc38', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-event-manager-0.4.0-2.fc38', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-kvm-bindings-0.7.0-1.fc38', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-kvm-ioctls-0.16.0-3.fc38', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-linux-loader-0.11.0-1.fc38', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-userfaultfd-0.8.1-2.fc38', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-versionize-0.2.0-2.fc38', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-vhost-0.10.0-2.fc38', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-vhost-user-backend-0.13.1-2.fc38', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-virtio-queue-0.11.0-1.fc38', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-vm-memory-0.14.0-1.fc38', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-vm-superio-0.7.0-4.fc38', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-vmm-sys-util-0.12.1-2.fc38', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'virtiofsd-1.10.1-1.fc38', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && _release) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'firecracker / libkrun / rust-event-manager / rust-kvm-bindings / etc');
}
