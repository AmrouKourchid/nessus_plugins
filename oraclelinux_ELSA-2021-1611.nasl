#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2021-1611.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149954);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/01");

  script_cve_id("CVE-2019-3842", "CVE-2020-13776");

  script_name(english:"Oracle Linux 8 : systemd (ELSA-2021-1611)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2021-1611 advisory.

    [239-45.0.1]
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

    [239-45]
    - Revert 'test: add test cases for empty string match' and 'test: add test case for multi matches when use
    ||' (#1931947)
    - test/sys-script.py: add missing DEVNAME entries to uevents (#1931947)
    - sd-event: split out helper functions for reshuffling prioqs (#1819868)
    - sd-event: split out enable and disable codepaths from sd_event_source_set_enabled() (#1819868)
    - sd-event: mention that two debug logged events are ignored (#1819868)
    - sd-event: split clock data allocation out of sd_event_add_time() (#1819868)
    - sd-event: split out code to add/remove timer event sources to earliest/latest prioq (#1819868)
    - sd-event: fix delays assert brain-o (#17790) (#1819868)
    - sd-event: lets suffix last_run/last_log with '_usec' (#1819868)
    - sd-event: refuse running default event loops in any other thread than the one they are default for
    (#1819868)
    - sd-event: ref event loop while in sd_event_prepare() ot sd_event_run() (#1819868)
    - sd-event: follow coding style with naming return parameter (#1819868)
    - sd-event: remove earliest_index/latest_index into common part of event source objects (#1819868)
    - sd-event: update state at the end in event_source_enable (#1819868)
    - sd-event: increase n_enabled_child_sources just once (#1819868)
    - sd-event: add ability to ratelimit event sources (#1819868)
    - test: add ratelimiting test (#1819868)
    - core: prevent excessive /proc/self/mountinfo parsing (#1819868)
    - udev: run link_update() with increased retry count in second invocation (#1931947)
    - pam-systemd: use secure_getenv() rather than getenv() (#1687514)

    [239-44]
    - ci: PowerTools repo was renamed to powertools in RHEL 8.3 (#1871827)
    - ci: use quay.io instead of Docker Hub to avoid rate limits (#1871827)
    - ci: move jobs from Travis CI to GH Actions (#1871827)
    - unit: make UNIT() cast function deal with NULL pointers (#1871827)
    - use link to RHEL-8 docs (#1623116)
    - cgroup: Also set blkio.bfq.weight (#1657810)
    - units: make sure initrd-cleanup.service terminates before switching to rootfs (#1657810)
    - core: reload SELinux label cache on daemon-reload (#1888912)
    - selinux: introduce mac_selinux_create_file_prepare_at() (#1888912)
    - selinux: add trigger for policy reload to refresh internal selabel cache (#1888912)
    - udev/net_id: give RHEL-8.4 naming scheme a name (#1827462)
    - basic/stat-util: make mtime check stricter and use entire timestamp (#1642728)
    - udev: make algorithm that selects highest priority devlink less susceptible to race conditions
    (#1642728)
    - test: create /dev/null in test-udev.pl (#1642728)
    - test: missing 'die' (#1642728)
    - udev-test: remove a check for whether the test is run in a container (#1642728)
    - udev-test: skip the test only if it cant setup its environment (#1642728)
    - udev-test: fix test skip condition (#1642728)
    - udev-test: fix missing directory test/run (#1642728)
    - udev-test: check if permitted to create block device nodes (#1642728)
    - test-udev: add a testcase of too long line (#1642728)
    - test-udev: use proper semantics for too long line with continuation (#1642728)
    - test-udev: add more tests for line continuations and comments (#1642728)
    - test-udev: add more tests for line continuation (#1642728)
    - test-udev: fix alignment and drop unnecessary white spaces (#1642728)
    - test/udev-test.pl: cleanup if skipping test (#1642728)
    - test: add test cases for empty string match (#1642728)
    - test: add test case for multi matches when use '||' (#1642728)
    - udev-test: do not rely on 'mail' group being defined (#1642728)
    - test/udev-test.pl: allow multiple devices per test (#1642728)
    - test/udev-test.pl: create rules only once (#1642728)
    - test/udev-test.pl: allow concurrent additions and removals (#1642728)
    - test/udev-test.pl: use computed devnode name (#1642728)
    - test/udev-test.pl: test correctness of symlink targets (#1642728)
    - test/udev-test.pl: allow checking multiple symlinks (#1642728)
    - test/udev-test.pl: fix wrong test descriptions (#1642728)
    - test/udev-test.pl: last_rule is unsupported (#1642728)
    - test/udev-test.pl: Make some tests a little harder (#1642728)
    - test/udev-test.pl: remove bogus rules from magic subsys test (#1642728)
    - test/udev-test.pl: merge 'space and var with space' tests (#1642728)
    - test/udev-test.pl: merge import parent tests into one (#1642728)
    - test/udev-test.pl: count 'good' results (#1642728)
    - tests/udev-test.pl: add multiple device test (#1642728)
    - test/udev-test.pl: add repeat count (#1642728)
    - test/udev-test.pl: generator for large list of block devices (#1642728)
    - test/udev-test.pl: suppress umount error message at startup (#1642728)
    - test/udev_test.pl: add 'expected good' count (#1642728)
    - test/udev-test: gracefully exit when imports fail (#1642728)

    [239-43]
    - man: mention System Administrators Guide in systemctl manpage (#1623116)
    - udev: introduce udev net_id 'naming schemes' (#1827462)
    - meson: make net.naming-scheme= default configurable (#1827462)
    - man: describe naming schemes in a new man page (#1827462)
    - udev/net_id: parse _SUN ACPI index as a signed integer (#1827462)
    - udev/net_id: dont generate slot based names if multiple devices might claim the same slot (#1827462)
    - fix typo in ProtectSystem= option (#1871139)
    - remove references of non-existent man pages (#1876807)
    - log: Prefer logging to CLI unless JOURNAL_STREAM is set (#1865840)
    - locale-util: add new helper locale_is_installed() (#1755287)
    - test: add test case for locale_is_installed() (#1755287)
    - tree-wide: port various bits over to locale_is_installed() (#1755287)
    - install: allow instantiated units to be enabled via presets (#1812972)
    - install: small refactor to combine two function calls into one function (#1812972)
    - test: fix a memleak (#1812972)
    - docs: Add syntax for templated units to systemd.preset man page (#1812972)
    - shared/install: fix preset operations for non-service instantiated units (#1812972)
    - introduce setsockopt_int() helper (#1887181)
    - socket-util: add generic socket_pass_pktinfo() helper (#1887181)
    - core: add new PassPacketInfo= socket unit property (#1887181)
    - resolved: tweak cmsg calculation (#1887181)

    [239-42]
    - logind: dont print warning when user@.service template is masked (#1880270)
    - build: use simple project version in pkgconfig files (#1862714)
    - basic/virt: try the /proc/1/sched hack also for PID1 (#1868877)
    - seccomp: rework how the S[UG]ID filter is installed (#1860374)
    - vconsole-setup: downgrade log message when setting font fails on dummy console (#1889996)
    - units: fix systemd.special man page reference in system-update-cleanup.service (#1871827)
    - units: drop reference to sushell man page (#1871827)
    - sd-bus: break the loop in bus_ensure_running() if the bus is not connecting (#1885553)
    - core: add new API for enqueing a job with returning the transaction data (#846319)
    - systemctl: replace switch statement by table of structures (#846319)
    - systemctl: reindent table (#846319)
    - systemctl: Only wait when theres something to wait for. (#846319)
    - systemctl: clean up start_unit_one() error handling (#846319)
    - systemctl: split out extra args generation into helper function of its own (#846319)
    - systemctl: add new --show-transaction switch (#846319)
    - test: add some basic testing that 'systemctl start -T' does something (#846319)
    - man: document the new systemctl --show-transaction option (#846319)
    - socket: New option 'FlushPending' (boolean) to flush socket before entering listening state (#1870638)
    - core: remove support for API bus 'started outside our own logic' (#1764282)
    - mount-setup: fix segfault in mount_cgroup_controllers when using gcc9 compiler (#1868877)
    - dbus-execute: make transfer of CPUAffinity endian safe (#12711) (#1740657)
    - core: add support for setting CPUAffinity= to special 'numa' value (#1740657)
    - basic/user-util: always use base 10 for user/group numbers (#1848373)
    - parse-util: sometimes it is useful to check if a string is a valid integer, but not actually parse it
    (#1848373)
    - basic/parse-util: add safe_atoux64() (#1848373)
    - parse-util: allow tweaking how to parse integers (#1848373)
    - parse-util: allow '-0' as alternative to '0' and '+0' (#1848373)
    - parse-util: make return parameter optional in safe_atou16_full() (#1848373)
    - parse-util: rewrite parse_mode() on top of safe_atou_full() (#1848373)
    - user-util: be stricter in parse_uid() (#1848373)
    - strv: add new macro STARTSWITH_SET() (#1848373)
    - parse-util: also parse integers prefixed with 0b and 0o (#1848373)
    - tests: beef up integer parsing tests (#1848373)
    - shared/user-util: add compat forms of user name checking functions (#1848373)
    - shared/user-util: emit a warning on names with dots (#1848373)
    - user-util: Allow names starting with a digit (#1848373)
    - shared/user-util: allow usernames with dots in specific fields (#1848373)
    - user-util: switch order of checks in valid_user_group_name_or_id_full() (#1848373)
    - user-util: rework how we validate user names (#1848373)

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2021-1611.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-13776");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-3842");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/26");

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

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'systemd-239-45.0.1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-container-239-45.0.1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-devel-239-45.0.1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-journal-remote-239-45.0.1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-libs-239-45.0.1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-pam-239-45.0.1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-tests-239-45.0.1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-udev-239-45.0.1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-239-45.0.1.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-container-239-45.0.1.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-devel-239-45.0.1.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-journal-remote-239-45.0.1.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-libs-239-45.0.1.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-pam-239-45.0.1.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-tests-239-45.0.1.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-udev-239-45.0.1.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-239-45.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-container-239-45.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-devel-239-45.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-journal-remote-239-45.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-libs-239-45.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-pam-239-45.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-tests-239-45.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-udev-239-45.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'systemd / systemd-container / systemd-devel / etc');
}
