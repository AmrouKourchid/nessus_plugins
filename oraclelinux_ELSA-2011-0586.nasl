#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2011-0586.
##

include('compat.inc');

if (description)
{
  script_id(181101);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/22");

  script_cve_id("CVE-2010-3851");

  script_name(english:"Oracle Linux 6 : libguestfs (ELSA-2011-0586)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 6 host has packages installed that are affected by a vulnerability as referenced in the
ELSA-2011-0586 advisory.

    [1.7.17-17]
    - Remove dependency on gfs2-utils.
      resolves: rhbz#695138

    [1.7.17-16]
    - Canonicalize /dev/vd* paths in virt-inspector code.
      resolves: rhbz#691724

    [1.7.17-15]
    - Fix trace segfault for non-daemon functions.
      resolves: rhbz#676788

    [1.7.17-14]
    - Add explicit BuildRequires for latest augeas. (RHBZ#677616)

    [1.7.17-13]
    - Rebuild to pick up new augeas lens (RHBZ#677616)

    [1.7.17-12]
    - Fix typo in virt-make-fs manual page.
      resolves: rhbz#673721
    - Add a grep-friendly string to LIBGUESTFS_TRACE output.
      resolves: rhbz#673477

    [1.7.17-11]
    - Only runtime require febootstrap-supermin-helper (not whole of
      febootstrap) (RHBZ#669840).

    [1.7.17-10]
    - Remove external hexedit script and make guestfish users set .
      This is because requiring emacs pulls in all of X (RHBZ#641494).

    [1.7.17-9]
    - Fix: guestfish fails when guest fstab entry does not exist (RHBZ#668611).

    [1.7.17-8]
    - Backport patches up to upstream 1.8.1. (RHBZ#613593)
    - Fixes:
       * guestfish: fails to tilde expand '~' when /home/ksharma unset (RHBZ#617440)
       * libguestfs: unknown filesystem /dev/fd0 (RHBZ#666577)
       * libguestfs: unknown filesystem label SWAP-sda2 (RHBZ#666578)
       * libguestfs: unknown filesystem /dev/hd{x} (cdrom) (RHBZ#666579)
       * virt-filesystems fails on guest with corrupt filesystem label (RHBZ#668115)
       * emphasize 'libguestfs-winsupport' in error output (RHBZ#627468)

    [1.7.17-4]
    - Backport patches up to upstream 1.8.0 _except_ for:
       * changes which require febootstrap 3.x
       * changes which were only relevant for other distros

    [1.7.17-3]
    - New upstream version 1.7.17, rebase for RHEL 6.1 (RHBZ#613593).
    - Require febootstrap >= 2.11.
    - Split out new libguestfs-tools-c package from libguestfs-tools.
      . This is so that the -tools-c package can be pulled in by people
        wanting to avoid a dependency on Perl, while -tools pulls in everything
        as before.
      . The C tools currently are: cat, df, filesystems, fish, inspector, ls,
        mount, rescue.
      . libguestfs-tools no longer pulls in guestfish.
    - guestfish no longer requires pod2text, hence no longer requires perl.
    - guestfish also depends on: less, man, vi, emacs.
    - Add BR db4-utils (although since RPM needs it, it not really necessary).
    - Runtime requires on db4-utils should be on core lib, not tools package.
    - Change all 'Requires: perl-Foo' to 'Requires: perl(Foo)'.
    - New manual pages containing example code.
    - Ship examples for C, OCaml, Ruby, Python.
    - Don't ship HTML versions of man pages.
    - Rebase no-fuse-test patch to latest version.
    - New tool: virt-filesystems.
    - Rename perl-libguestfs as perl-Sys-Guestfs (RHBZ#652587).
    - Remove guestfs-actions.h and guestfs-structs.h.  Libguestfs now
    [header file.]
    - Add AUTHORS file from tarball.

    [1.6.2-4]
    - New upstream stable version 1.6.2, rebase for RHEL 6.1 (RHBZ#613593).
    - Remove previous patches which are now all upstream and in this new version.
    - BR febootstrap 2.10 (RHBZ#628849).
    - BR cryptsetup-luks for new LUKS encryption support.
    - ocaml-xml-light{,-devel} is no longer required to build.
    - guestfish is no longer dependent on virt-inspector.
    - Require the ruby package.
    - Disable PHP and Haskell bindings in configure (they wouldn't build anyway,
      but this will help people building from source).
    - Set sysconfdir in configure.
    - --enable-debug-command is no longer required by configure script.
    - New command 'virt-make-fs'.
    - Include virt-inspector2, upstream replacement for virt-inspector.
    - Provide hexedit replacement script for guestfish.
    - BR autotools, and rerun after applying patches.

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2011-0586.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2010-3851");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/10/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:guestfish");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs-java-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs-mount");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs-tools-c");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ocaml-libguestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ocaml-libguestfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Sys-Guestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-libguestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ruby-libguestfs");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 6', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);
if ('x86_64' >!< cpu) audit(AUDIT_ARCH_NOT, 'x86_64', cpu);

var pkgs = [
    {'reference':'guestfish-1.7.17-17.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-1.7.17-17.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-devel-1.7.17-17.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-java-1.7.17-17.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-java-devel-1.7.17-17.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-javadoc-1.7.17-17.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-mount-1.7.17-17.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-tools-1.7.17-17.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-tools-c-1.7.17-17.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'ocaml-libguestfs-1.7.17-17.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'ocaml-libguestfs-devel-1.7.17-17.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'perl-Sys-Guestfs-1.7.17-17.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'python-libguestfs-1.7.17-17.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'ruby-libguestfs-1.7.17-17.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'guestfish / libguestfs / libguestfs-devel / etc');
}
