#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2012:0774 and 
# Oracle Linux Security Advisory ELSA-2012-0774 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(68548);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/22");

  script_cve_id("CVE-2012-2690");
  script_bugtraq_id(53932);
  script_xref(name:"RHSA", value:"2012:0774");

  script_name(english:"Oracle Linux 6 : libguestfs (ELSA-2012-0774)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 6 host has packages installed that are affected by a vulnerability as referenced in the
ELSA-2012-0774 advisory.

    [1:1.16.19-1]
    - Rebase to libguestfs 1.16.19
      resolves: rhbz#719879
    - Rebuild against augeas 0.9.0-3.el6
      related: rhbz#808662
    - Fix: Don't abort inspection if mdadm.conf ARRAY doesn't have a uuid.
    - Switch back to git for patch management.

    [1:1.16.18-2]
    - Rebase to libguestfs 1.16.18
      resolves: rhbz#719879
    - Fix: guestfs_last_error not set when qemu fails early during launch
      resolves: rhbz#811673
    - Fix: RFE: virt-sysprep: hostname can not be changed on rhel system
      (RHBZ#811112)
    - Fix: RFE: virt-sysprep: net-hwaddr not removed from ifcfg-* files on
      rhel (RHBZ#811117)
    - Fix: inspection fails on ubuntu 10.04 guest with encrypted swap (RHBZ#811872)
    - Fix: cannot open disk images which are symlinks to files that
      contain ':' (colon) character (RHBZ#812092)
    - BR gettext-devel so we can rerun autoconf.

    [1:1.16.15-1]
    - Rebase to libguestfs 1.16.15
      resolves: rhbz#719879
    - Fix: inspection doesn't recognize Fedora 17+ (RHBZ#809401)

    [1:1.16.14-1]
    - Rebase to libguestfs 1.16.14
      resolves: rhbz#719879
    - virt-sysprep should use virt-inspector2
      resolves: rhbz#807557
    - Fix: mkfs blocksize option breaks when creating btrfs
      resolves: rhbz#807905

    [1:1.16.12-1]
    - Rebase to libguestfs 1.16.12
      resolves: rhbz#719879
    - Fix: could not locate HKLM\SYSTEM\MountedDevices
      resolves: rhbz#803699

    [1:1.16.10-1]
    - Rebase to libguestfs 1.16.10
      resolves: rhbz#719879
    - Fix: libguestfs holds open file descriptors when handle is launched
      resolves: rhbz#801788
    - Fix: Document for set-pgroup need to be updated
      resolves: rhbz#801273
    - Fix: Possible null dereference and resource leaks
      resolves: rhbz#801298

    [1:1.16.8-1]
    - Rebase to libguestfs 1.16.8
      resolves: rhbz#719879
    - Fix set_autosync function so it is not 'ConfigOnly'
      resolves: rhbz#796520
    - Fix header compilation for C++
      resolves: rhbz#799695

    [1:1.16.6-1]
    - Rebase to libguesfs 1.16.6
      resolves: rhbz#798197, rhbz#797760,rhbz#790958,rhbz#798980,rhbz#795322,rhbz#796520
    - Fix virt-inspector2 man page.

    [1:1.16.5-1]
    - Rebase to libguestfs 1.16.5
      resolves: rhbz#679737, rhbz#789960

    [1:1.16.4-1]
    - Rebase to libguestfs 1.16.4
      resolves: rhbz#788642

    [1:1.16.3-1]
    - Rebase to libguestfs 1.16.3
      resolves: rhbz#679737, rhbz#769359, rhbz#785305

    [1:1.16.2-1]
    - Rebase to libguestfs 1.16.2
      resolves: rhbz#719879

    [1:1.16.1-1]
    - Rebase to libguestfs 1.16.1
    - Disable tests (probably because we are hitting
      https://lists.gnu.org/archive/html/qemu-devel/2010-02/threads.html#00823 )
      resolves: rhbz#719879

    [1:1.14.7-4]
    - Continue with rebase to libguestfs 1.14.7
      resolves: rhbz#719879

    [1:1.14.7-1]
    - Rebase to libguestfs 1.14.7
      resolves: rhbz#719879

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2012-0774.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-2690");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs-java-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs-tools-c");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ocaml-libguestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ocaml-libguestfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Sys-Guestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-libguestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ruby-libguestfs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 6', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);
if ('x86_64' >!< cpu) audit(AUDIT_ARCH_NOT, 'x86_64', cpu);

var pkgs = [
    {'reference':'libguestfs-1.16.19-1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-devel-1.16.19-1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-java-1.16.19-1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-java-devel-1.16.19-1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-javadoc-1.16.19-1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-tools-1.16.19-1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-tools-c-1.16.19-1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'ocaml-libguestfs-1.16.19-1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'ocaml-libguestfs-devel-1.16.19-1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'perl-Sys-Guestfs-1.16.19-1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'python-libguestfs-1.16.19-1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'ruby-libguestfs-1.16.19-1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
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
      severity   : SECURITY_NOTE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libguestfs / libguestfs-devel / libguestfs-java / etc');
}
