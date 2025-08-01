#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2018:2284 and 
# Oracle Linux Security Advisory ELSA-2018-2284 respectively.
#

include('compat.inc');

if (description)
{
  script_id(111482);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/01");

  script_cve_id("CVE-2018-10897");
  script_xref(name:"RHSA", value:"2018:2284");

  script_name(english:"Oracle Linux 6 : yum-utils (ELSA-2018-2284)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 6 host has packages installed that are affected by a vulnerability as referenced in the
ELSA-2018-2284 advisory.

    [1.1.30-42.0.1]
    - add dependency btrfs-progs for yum-plugin-fs-snapshot (guangyu.sun@oracle.com) [bug 16285176]
    - use unified btrfs binary instead of btrfsctl (guangyu.sun@oracle.com) [bug 16285176]

    [-1.1.30-42]
    - reposync: prevent path traversal.
    - Resolves: bug#1600619

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2018-2284.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-10897");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:yum-NetworkManager-dispatcher");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:yum-plugin-aliases");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:yum-plugin-auto-update-debug-info");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:yum-plugin-changelog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:yum-plugin-fastestmirror");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:yum-plugin-filter-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:yum-plugin-fs-snapshot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:yum-plugin-keys");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:yum-plugin-list-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:yum-plugin-local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:yum-plugin-merge-conf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:yum-plugin-ovl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:yum-plugin-post-transaction-actions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:yum-plugin-priorities");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:yum-plugin-protectbase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:yum-plugin-ps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:yum-plugin-remove-with-leaves");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:yum-plugin-rpm-warm-cache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:yum-plugin-security");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:yum-plugin-show-leaves");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:yum-plugin-tmprepo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:yum-plugin-tsflags");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:yum-plugin-upgrade-helper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:yum-plugin-verify");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:yum-plugin-versionlock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:yum-updateonboot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:yum-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if ('x86_64' >!< cpu) audit(AUDIT_ARCH_NOT, 'x86_64', cpu);

var pkgs = [
    {'reference':'yum-NetworkManager-dispatcher-1.1.30-42.0.1.el6_10', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'yum-plugin-aliases-1.1.30-42.0.1.el6_10', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'yum-plugin-auto-update-debug-info-1.1.30-42.0.1.el6_10', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'yum-plugin-changelog-1.1.30-42.0.1.el6_10', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'yum-plugin-fastestmirror-1.1.30-42.0.1.el6_10', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'yum-plugin-filter-data-1.1.30-42.0.1.el6_10', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'yum-plugin-fs-snapshot-1.1.30-42.0.1.el6_10', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'yum-plugin-keys-1.1.30-42.0.1.el6_10', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'yum-plugin-list-data-1.1.30-42.0.1.el6_10', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'yum-plugin-local-1.1.30-42.0.1.el6_10', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'yum-plugin-merge-conf-1.1.30-42.0.1.el6_10', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'yum-plugin-ovl-1.1.30-42.0.1.el6_10', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'yum-plugin-post-transaction-actions-1.1.30-42.0.1.el6_10', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'yum-plugin-priorities-1.1.30-42.0.1.el6_10', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'yum-plugin-protectbase-1.1.30-42.0.1.el6_10', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'yum-plugin-ps-1.1.30-42.0.1.el6_10', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'yum-plugin-remove-with-leaves-1.1.30-42.0.1.el6_10', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'yum-plugin-rpm-warm-cache-1.1.30-42.0.1.el6_10', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'yum-plugin-security-1.1.30-42.0.1.el6_10', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'yum-plugin-show-leaves-1.1.30-42.0.1.el6_10', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'yum-plugin-tmprepo-1.1.30-42.0.1.el6_10', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'yum-plugin-tsflags-1.1.30-42.0.1.el6_10', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'yum-plugin-upgrade-helper-1.1.30-42.0.1.el6_10', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'yum-plugin-verify-1.1.30-42.0.1.el6_10', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'yum-plugin-versionlock-1.1.30-42.0.1.el6_10', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'yum-updateonboot-1.1.30-42.0.1.el6_10', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'yum-utils-1.1.30-42.0.1.el6_10', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'yum-NetworkManager-dispatcher / yum-plugin-aliases / yum-plugin-auto-update-debug-info / etc');
}
