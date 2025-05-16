##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2020-4553.
##

include('compat.inc');

if (description)
{
  script_id(142800);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/01");

  script_cve_id("CVE-2019-20386");

  script_name(english:"Oracle Linux 8 : systemd (ELSA-2020-4553)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has packages installed that are affected by a vulnerability as referenced in the
ELSA-2020-4553 advisory.

    [239-40.0.1]
    - backport upstream pstore tmpfiles patch [Orabug: 31420486]
    - udev rules: fix memory hot add and remove [Orabug: 31310273]
    - fix to enable systemd-pstore.service [Orabug: 30951066]
    - journal: change support URL shown in the catalog entries [Orabug: 30853009]
    - fix to generate systemd-pstore.service file [Orabug: 30230056]
    - fix _netdev is missing for iscsi entry in /etc/fstab (tony.l.lam@oracle.com) [Orabug: 25897792]
    - set 'RemoveIPC=no' in logind.conf as default for OL7.2 [Orabug: 22224874]
    - allow dm remove ioctl to co-operate with UEK3 (Vaughan Cao) [Orabug: 18467469]
    - add hv dynamic memory support (Jerry Snitselaar) [Orabug: 18621475]
    - Backport upstream patches for the new systemd-pstore tool (Eric DeVolder) [OraBug: 30230056]

    [239-40]
    - units: add generic boot-complete.target (#1872243)
    - man: document new 'boot-complete.target' unit (#1872243)
    - core: make sure to restore the control command id, too (#1829867)

    [239-39]
    - device: make sure we emit PropertiesChanged signal once we set sysfs (#1793533)
    - device: dont emit PropetiesChanged needlessly (#1793533)

    [239-38]
    - spec: fix rpm verification (#1702300)

    [239-37]
    - spec: dont package /etc/systemd/system/dbus-org.freedesktop.resolve1.service (#1844465)

    [239-36]
    - core: dont consider SERVICE_SKIP_CONDITION for abnormal or failure restarts (#1737283)
    - selinux: do preprocessor check only in selinux-access.c (#1830861)
    - basic/cgroup-util: introduce cg_get_keyed_attribute_full() (#1830861)
    - shared: add generic logic for waiting for a unit to enter some state (#1830861)
    - shared: fix assert call (#1830861)
    - shared: Dont try calling NULL callback in bus_wait_for_units_clear (#1830861)
    - shared: add NULL callback check in one more place (#1830861)
    - core: introduce support for cgroup freezer (#1830861)
    - core/cgroup: fix return value of unit_cgorup_freezer_action() (#1830861)
    - core: fix the return value in order to make sure we dont dipatch method return too early (#1830861)
    - test: add test for cgroup v2 freezer support (#1830861)
    - fix mis-merge (#1848421)
    - tests: sleep a bit and give kernel time to perform the action after manual freeze/thaw (#1848421)

    [239-35]
    - spec: fix rpm verification (#1702300)

    [239-34]
    - spec: fix rpm verification (#1702300)

    [239-33]
    - tmpfiles: fix crash with NULL in arg_root and other fixes and tests (#1836024)
    - sulogin-shell: Use force if SYSTEMD_SULOGIN_FORCE set (#1625929)
    - resolvconf: fixes for the compatibility interface (#1835594)
    - mount: dont add Requires for tmp.mount (#1748840)
    - core: coldplug possible nop_job (#1829798)
    - core: add IODeviceLatencyTargetSec (#1831519)
    - time-util: Introduce parse_sec_def_infinity (#1770379)
    - cgroup: use structured initialization (#1770379)
    - core: add CPUQuotaPeriodSec= (#1770379)
    - core: downgrade CPUQuotaPeriodSec= clamping logs to debug (#1770379)
    - sd-bus: avoid magic number in SASL length calculation (#1838081)
    - sd-bus: fix SASL reply to empty AUTH (#1838081)
    - sd-bus: skip sending formatted UIDs via SASL (#1838081)
    - core: add MemoryMin (#1763435)
    - core: introduce cgroup_add_device_allow() (#1763435)
    - test: remove support for suffix in get_testdata_dir() (#1763435)
    - cgroup: Implement default propagation of MemoryLow with DefaultMemoryLow (#1763435)
    - cgroup: Create UNIT_DEFINE_ANCESTOR_MEMORY_LOOKUP (#1763435)
    - unit: Add DefaultMemoryMin (#1763435)
    - cgroup: Polish hierarchically aware protection docs a bit (#1763435)
    - cgroup: Readd some plumbing for DefaultMemoryMin (#1763435)
    - cgroup: Support 0-value for memory protection directives (#1763435)
    - cgroup: Test that its possible to set memory protection to 0 again (#1763435)
    - cgroup: Check ancestor memory min for unified memory config (#1763435)
    - cgroup: Respect DefaultMemoryMin when setting memory.min (#1763435)
    - cgroup: Mark memory protections as explicitly set in transient units (#1763435)
    - meson: allow setting the version string during configuration (#1804252)

    [239-32]
    - pid1: fix DefaultTasksMax initialization (#1809037)
    - cgroup: make sure that cpuset is supported on cgroup v2 and disabled with v1 (#1808940)
    - test: introduce TEST-36-NUMAPOLICY (#1808940)
    - test: replace 'tail -f' with journal cursor which should be... (#1808940)
    - test: support MPOL_LOCAL matching in unpatched strace versions (#1808940)
    - test: make sure the strace process is indeed dead (#1808940)
    - test: skip the test on systems without NUMA support (#1808940)
    - test: give strace some time to initialize (#1808940)
    - test: add a simple sanity check for systems without NUMA support (#1808940)
    - test: drop the missed || exit 1 expression (#1808940)
    - test: replace cursor file with a plain cursor (#1808940)
    - cryptsetup: Treat key file errors as a failed password attempt (#1763155)
    - swap: finish the secondary swap units jobs if deactivation of the primary swap unit fails (#1749622)
    - resolved: Recover missing PrivateTmp=yes and ProtectSystem=strict (#1810869)
    - bus_open leak sd_event_source when udevadm trigger (#1798504)
    - core: rework StopWhenUnneeded= logic (#1798046)
    - pid1: fix the names of AllowedCPUs= and AllowedMemoryNodes= (#1818054)
    - core: fix re-realization of cgroup siblings (#1818054)
    - basic: use comma as separator in cpuset cgroup cpu ranges (#1818054)
    - core: transition to FINAL_SIGTERM state after ExecStopPost= (#1766479)
    - sd-journal: close journal files that were deleted by journald before weve setup inotify watch (#1796128)
    - sd-journal: remove the dead code and actually fix #14695 (#1796128)
    - udev: downgrade message when we fail to set inotify watch up (#1808051)
    - logind: check PolicyKit before allowing VT switch (#1797679)
    - test: do not use global variable to pass error (#1823767)
    - test: install libraries required by tests (#1823767)
    - test: introduce install_zoneinfo() (#1823767)
    - test: replace duplicated Makefile by symbolic link (#1823767)
    - test: add paths of keymaps in install_keymaps() (#1823767)
    - test: make install_keymaps() optionally install more keymaps (#1823767)
    - test-fs-util: skip some tests when running in unprivileged container (#1823767)
    - test-process-util: skip several verifications when running in unprivileged container (#1823767)
    - test-execute: also check python3 is installed or not (#1823767)
    - test-execute: skip several tests when running in container (#1823767)
    - test: introduce test_is_running_from_builddir() (#1823767)
    - test: make test-catalog relocatable (#1823767)
    - test: parallelize tasks in TEST-24-UNIT-TESTS (#1823767)
    - test: try to determine QEMU_SMP dynamically (#1823767)
    - test: store coredumps in journal (#1823767)
    - pid1: add new kernel cmdline arg systemd.cpu_affinity= (#1812894)
    - udev-rules: make tape-changers also apprear in /dev/tape/by-path/ (#1820112)
    - man: be clearer that .timer time expressions need to be reset to override them (#1816908)
    - Add support for opening files for appending (#1809175)
    - nspawn: move payload to sub-cgroup first, then sync cgroup trees (#1837094)
    - core: move unit_status_emit_starting_stopping_reloading() and related calls to job.c (#1737283)
    - job: when a job was skipped due to a failed condition, log about it (#1737283)
    - core: split out all logic that updates a Job on a units unit_notify() invocation (#1737283)
    - core: make log messages about units entering a 'failed' state recognizable (#1737283)
    - core: log a recognizable message when a unit succeeds, too (#1737283)
    - tests: always use the right vtable wrapper calls (#1737283)
    - test-execute: allow filtering test cases by pattern (#1737283)
    - test-execute: provide custom failure message (#1737283)
    - core: ExecCondition= for services (#1737283)
    - Drop support for lz4 < 1.3.0 (#1843871)
    - test-compress: add test for short decompress_startswith calls (#1843871)
    - journal: adapt for new improved LZ4_decompress_safe_partial() (#1843871)
    - fuzz-compress: add fuzzer for compression and decompression (#1843871)
    - seccomp: fix __NR__sysctl usage (#1843871)

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2020-4553.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-20386");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:systemd-container");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:systemd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:systemd-journal-remote");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:systemd-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:systemd-pam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:systemd-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:systemd-udev");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 8', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var pkgs = [
    {'reference':'systemd-239-40.0.1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-container-239-40.0.1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-devel-239-40.0.1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-journal-remote-239-40.0.1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-libs-239-40.0.1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-pam-239-40.0.1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-tests-239-40.0.1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-udev-239-40.0.1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-239-40.0.1.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-container-239-40.0.1.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-devel-239-40.0.1.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-journal-remote-239-40.0.1.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-libs-239-40.0.1.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-pam-239-40.0.1.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-tests-239-40.0.1.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-udev-239-40.0.1.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-239-40.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-container-239-40.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-devel-239-40.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-journal-remote-239-40.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-libs-239-40.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-pam-239-40.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-tests-239-40.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-udev-239-40.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'systemd / systemd-container / systemd-devel / etc');
}
