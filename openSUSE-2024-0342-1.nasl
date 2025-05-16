#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2024:0342-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(209977);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/31");

  script_cve_id("CVE-2022-47952");

  script_name(english:"openSUSE 15 Security Update : lxc (openSUSE-SU-2024:0342-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote openSUSE 15 host has packages installed that are affected by a vulnerability as referenced in the openSUSE-
SU-2024:0342-1 advisory.

    lxc was updated to 6.0.2:

      The LXC team is pleased to announce the release of LXC 6.0.2!
      This is the second bugfix release for LXC 6.0 which is supported
      until June 2029.

      As usual this bugfix releases focus on stability and hardening.

      * Some of the highlights for this release are:

        - Reduced log level on some common messages
        - Fix compilation error on aarch64

      * Detailed changelog

        - Remove unused function
        - idmap: Lower logging level of newXidmap tools to INFO
        - Exit 0 when there's no error
        - doc: Fix definitions of get_config_path and set_config_path
        - README: Update security contact
        - fix possible clang compile error in AARCH

    Update to 6.0.1:

      The LXC team is pleased to announce the release of LXC 6.0.1!
      This is the first bugfix release for LXC 6.0 which is supported
      until June 2029.

      As usual this bugfix releases focus on stability and hardening.

      * Highlights

        - Fixed some build tooling issues
        - Fixed startup failures on system without IPv6 support
        - Updated AppArmor rules to avoid potential warnings

    Update to 6.0.0:

      The LXC team is pleased to announce the release of LXC 6.0 LTS!
      This is the result of two years of work since the LXC 5.0 release
      and is the sixth LTS release for the LXC project. This release
      will be supported until June 2029.

      * New multi-call binary?

        A new tools-multicall=true configuration option can be used to
        produce a single lxc binary which can then have all other
        lxc-XYZ commands be symlinked to.
        This allows for a massive disk space reduction, particularly
        useful for embedded platforms.

      * Add a set_timeout function to the library

        A new set_timeout function is available on the main
        lxc_container struct and allow for setting a global timeout for
        interactions with the LXC monitor.
        Prior to this, there was no timeout, leading to potential
        deadlocks as there's also no way to cancel an monitor request.
        As a result of adding this new symbol to the library, we have
        bumped the liblxc symbol version to 1.8.0.

      * LXC bridge now has IPV6 enabled

        The default lxcbr0 bridge now comes with IPv6 enabled by
        default, using an IPv6 ULA subnet.
        Support for uid/gid selection in lxc-usernsexec
        The lxc-usernsexec tool now has both -u and -g options to
        control what resulting UID and GID (respectively) the user
        wishes to use (defaulting to 0/0).

      * Improvements to lxc-checkconfig

        lxc-checkconfig now only shows the version if lxc-start is
        present (rather than failing).
        Additionally, it's seen a number of other cosmetic improvements
        as well as now listing the maximum number of allowed namespaces
        for every namespace type.

      * Support for squashfs OCI images

        The built-in oci container template can now handle squashfs
        compressed OCI images through the use of atomfs.

      * Switched from systemd's dbus to dbus-1

        LXC now uses libdbus-1 for DBus interactions with systemd
        rather than using libsystemd.
        The reason for this change is that libdbus-1 is readily
        available for static builds.

      * Removed Upstart support

        Support for the Upstart init system has finally been removed
        from LXC.
        This shouldn't really affect anyone at this stage and allowed
        for cleaning up some logic and config files from our
        repository.

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204842");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206779");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/OOSMXYJMF3W5N7MDXO2O3PADSGDX4HXP/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cada3a15");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-47952");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-47952");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liblxc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liblxc1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lxc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lxc-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pam_cgfs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/SuSE/release');
if (isnull(os_release) || os_release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, 'openSUSE');
var _os_ver = pregmatch(pattern: "^SUSE([\d.]+)", string:os_release);
if (isnull(_os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
_os_ver = _os_ver[1];
if (os_release !~ "^(SUSE15\.5|SUSE15\.6)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.5 / 15.6', os_release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + _os_ver, cpu);

var pkgs = [
    {'reference':'liblxc-devel-6.0.2-bp156.2.3.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'liblxc-devel-6.0.2-bp156.2.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'liblxc1-6.0.2-bp156.2.3.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'liblxc1-6.0.2-bp156.2.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'lxc-6.0.2-bp156.2.3.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'lxc-6.0.2-bp156.2.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'lxc-bash-completion-6.0.2-bp156.2.3.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'lxc-bash-completion-6.0.2-bp156.2.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pam_cgfs-6.0.2-bp156.2.3.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pam_cgfs-6.0.2-bp156.2.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var _cpu = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (rpm_check(release:_release, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'liblxc-devel / liblxc1 / lxc / lxc-bash-completion / pam_cgfs');
}
