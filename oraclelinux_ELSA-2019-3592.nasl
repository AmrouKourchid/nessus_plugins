#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2019-3592.
##

include('compat.inc');

if (description)
{
  script_id(180650);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/01");

  script_cve_id("CVE-2019-15718");

  script_name(english:"Oracle Linux 8 : systemd (ELSA-2019-3592)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has packages installed that are affected by a vulnerability as referenced in the
ELSA-2019-3592 advisory.

    [239-18.0.1]
    - fix _netdev is missing for iscsi entry in /etc/fstab (tony.l.lam@oracle.com) [Orabug: 25897792]
    - set 'RemoveIPC=no' in logind.conf as default for OL7.2 [Orabug: 22224874]
    - allow dm remove ioctl to co-operate with UEK3 (Vaughan Cao) [Orabug: 18467469]
    - add hv dynamic memory support (Jerry Snitselaar) [Orabug: 18621475]
    - Backport upstream patches for the new systemd-pstore tool (Eric DeVolder) [OraBug: 30230056]

    [239-18]
    - shared/but-util: drop trusted annotation from bus_open_system_watch_bind_with_description() (#1746857)
    - sd-bus: adjust indentation of comments (#1746857)
    - resolved: do not run loop twice (#1746857)
    - resolved: allow access to Set*Link and Revert methods through polkit (#1746857)
    - resolved: query polkit only after parsing the data (#1746857)

    [239-17]
    - mount: simplify /proc/self/mountinfo handler (#1696178)
    - mount: rescan /proc/self/mountinfo before processing waitid() results (#1696178)
    - swap: scan /proc/swaps before processing waitid() results (#1696178)
    - analyze-security: fix potential division by zero (#1734400)

    [239-16]
    - sd-bus: deal with cookie overruns (#1694999)
    - journal-remote: do not request Content-Length if Transfer-Encoding is chunked (#1708849)
    - journal: do not remove multiple spaces after identifier in syslog message (#1691817)
    - cryptsetup: Do not fallback to PLAIN mapping if LUKS data device set fails. (#1719153)
    - cryptsetup: call crypt_load() for LUKS only once (#1719153)
    - cryptsetup: Add LUKS2 token support. (#1719153)
    - udev/scsi_id: fix incorrect page length when get device identification VPD page (#1713227)
    - Change job mode of manager triggered restarts to JOB_REPLACE (#11456
    - bash-completion: analyze: support 'security' (#1733395)
    - man: note that journal does not validate syslog fields (#1707175)
    - rules: skip memory hotplug on ppc64 (#1713159)

    [239-15]
    - tree-wide: shorten error logging a bit (#1697893)
    - nspawn: simplify machine terminate bus call (#1697893)
    - nspawn: merge two variable declaration lines (#1697893)
    - nspawn: rework how we allocate/kill scopes (#1697893)
    - unit: enqueue cgroup empty check event if the last ref on a unit is dropped (#1697893)
    - Revert 'journal: remove journal audit socket' (#1699287)
    - journal: dont enable systemd-journald-audit.socket by default (#1699287)
    - logs-show: use grey color for de-emphasizing journal log output (#1695601)
    - units: add [Install] section to tmp.mount (#1667065)
    - nss: do not modify errno when NSS_STATUS_NOTFOUND or NSS_STATUS_SUCCESS (#1691691)
    - util.h: add new UNPROTECT_ERRNO macro (#1691691)
    - nss: unportect errno before writing to NSS *errnop (#1691691)
    - seccomp: reduce logging about failure to add syscall to seccomp (#1658691)
    - format-table: when duplicating a cell, also copy the color (#1689832)
    - format-table: optionally make specific cells clickable links (#1689832)
    - format-table: before outputting a color, check if colors are available (#1689832)
    - format-table: add option to store/format percent and uint64_t values in cells (#1689832)
    - format-table: optionally allow reversing the sort order for a column (#1689832)
    - format-table: add table_update() to update existing entries (#1689832)
    - format-table: add an API for getting the cell at a specific row/column (#1689832)
    - format-table: always underline header line (#1689832)
    - format-table: add calls to query the data in a specific cell (#1689832)
    - format-table: make sure we never call memcmp() with NULL parameters (#1689832)
    - format-table: use right field for display (#1689832)
    - format-table: add option to uppercase cells on display (#1689832)
    - format-table: never try to reuse cells that have color/url/uppercase set (#1689832)
    - locale-util: add logic to output smiley emojis at various happiness levels (#1689832)
    - analyze: add new security verb (#1689832)
    - tests: add a rudimentary fuzzer for server_process_syslog_message (#9979) (#1696224)
    - journald: make it clear that dev_kmsg_record modifies the string passed to it (#1696224)
    - journald: free the allocated memory before returning from dev_kmsg_record (#1696224)
    - tests: rework the code fuzzing journald (#1696224)
    - journald: make server_process_native_message compatible with fuzz_journald_processing_function
    (#1696224)
    - tests: add a fuzzer for server_process_native_message (#1696224)
    - tests: add a fuzzer for sd-ndisc (#1696224)
    - ndisc: fix two infinite loops (#1696224)
    - tests: add reproducers for several issues uncovered with fuzz-journald-syslog (#1696224)
    - tests: add a reproducer for an infinite loop in ndisc_handle_datagram (#1696224)
    - tests: add a reproducer for another infinite loop in ndisc_handle_datagram (#1696224)
    - fuzz: rename 'fuzz-corpus' directory to just 'fuzz' (#1696224)
    - test: add testcase for issue 10007 by oss-fuzz (#1696224)
    - fuzz: unify the 'fuzz-regressions' directory with the main corpus (#1696224)
    - test-bus-marshal: use cescaping instead of hexmem (#1696224)
    - meson: add -Dlog-trace to set LOG_TRACE (#1696224)
    - meson: allow building resolved and machined without nss modules (#1696224)
    - meson: drop duplicated condition (#1696224)
    - meson: use .source_root() in more places (#1696224)
    - meson: treat all fuzz cases as unit tests (#1696224)
    - fuzz-bus-message: add fuzzer for message parsing (#1696224)
    - bus-message: use structured initialization to avoid use of unitialized memory (#1696224)
    - bus-message: avoid an infinite loop on empty structures (#1696224)
    - bus-message: lets always use -EBADMSG when the message is bad (#1696224)
    - bus-message: rename function for clarity (#1696224)
    - bus-message: use define (#1696224)
    - bus: do not print (null) if the message has unknown type (#1696224)
    - bus-message: fix calculation of offsets table (#1696224)
    - bus-message: remove duplicate assignment (#1696224)
    - bus-message: fix calculation of offsets table for arrays (#1696224)
    - bus-message: drop asserts in functions which are wrappers for varargs version (#1696224)
    - bus-message: output debug information about offset troubles (#1696224)
    - bus-message: fix skipping of array fields in !gvariant messages (#1696224)
    - bus-message: also properly copy struct signature when skipping (#1696224)
    - fuzz-bus-message: add two test cases that pass now (#1696224)
    - bus-message: return -EBADMSG not -EINVAL on invalid !gvariant messages (#1696224)
    - bus-message: avoid wrap-around when using length read from message (#1696224)
    - util: do not use stack frame for parsing arbitrary inputs (#1696224)
    - travis: enable ASan and UBSan on RHEL8 (#1683319)
    - tests: keep SYS_PTRACE when running under ASan (#1683319)
    - tree-wide: various ubsan zero size memory fixes (#1683319)
    - util: introduce memcmp_safe() (#1683319)
    - test-socket-util: avoid 'memleak' reported by valgrind (#1683319)
    - sd-journal: escape binary data in match_make_string() (#1683319)
    - capability: introduce CAP_TO_MASK_CORRECTED() macro replacing CAP_TO_MASK() (#1683319)
    - sd-bus: use size_t when dealing with memory offsets (#1683319)
    - sd-bus: call cap_last_cap() only once in has_cap() (#1683319)
    - mount-point: honour AT_SYMLINK_FOLLOW correctly (#1683319)
    - travis: switch from trusty to xenial (#1683319)
    - test-socket-util: Add tests for receive_fd_iov() and friends. (#1683319)
    - socket-util: Introduce send_one_fd_iov() and receive_one_fd_iov() (#1683319)
    - core: swap order of 'n_storage_fds' and 'n_socket_fds' parameters (#1683334)
    - execute: use our usual syntax for defining bit masks (#1683334)
    - core: introduce new Type=exec service type (#1683334)
    - man: document the new Type=exec type (#1683334)
    - sd-bus: allow connecting to the pseudo-container '.host' (#1683334)
    - sd-login: lets also make sd-login understand '.host' (#1683334)
    - test: add test for Type=exec (#1683334)
    - journal-gateway: explicitly declare local variables (#1705971)
    - tools: drop unused variable (#1705971)
    - journal-gateway: use localStorage['cursor'] only when it has valid value (#1705971)

    [239-14]
    - rules: implement new memory hotplug policy (#1670728)
    - rules: add the rule that adds elevator= kernel command line parameter (#1670126)
    - bus-socket: Fix line_begins() to accept word matching full string (#1692991)
    - Refuse dbus message paths longer than BUS_PATH_SIZE_MAX limit. (#1678641)
    - Allocate temporary strings to hold dbus paths on the heap (#1678641)
    - sd-bus: if we receive an invalid dbus message, ignore and proceeed (#1678641)
    - Revert 'core: one step back again, for nspawn we actually can't wait for cgroups running empty since
    systemd will get exactly zero notifications about it (#1703485)

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2019-3592.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-15718");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/07");

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
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 8', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var pkgs = [
    {'reference':'systemd-239-18.0.1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-container-239-18.0.1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-devel-239-18.0.1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-journal-remote-239-18.0.1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-libs-239-18.0.1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-pam-239-18.0.1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-tests-239-18.0.1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-udev-239-18.0.1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-239-18.0.1.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-container-239-18.0.1.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-devel-239-18.0.1.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-journal-remote-239-18.0.1.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-libs-239-18.0.1.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-pam-239-18.0.1.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-tests-239-18.0.1.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-udev-239-18.0.1.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-239-18.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-container-239-18.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-devel-239-18.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-journal-remote-239-18.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-libs-239-18.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-pam-239-18.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-tests-239-18.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-udev-239-18.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
