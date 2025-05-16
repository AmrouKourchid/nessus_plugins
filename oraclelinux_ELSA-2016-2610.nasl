#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2016:2610 and 
# Oracle Linux Security Advisory ELSA-2016-2610 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(94726);
  script_version("2.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/01");

  script_cve_id("CVE-2016-7795");
  script_xref(name:"RHSA", value:"2016:2610");

  script_name(english:"Oracle Linux 7 : systemd (ELSA-2016-2610)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 host has packages installed that are affected by a vulnerability as referenced in the
ELSA-2016-2610 advisory.

    [219-30.0.1.3]
    - set 'RemoveIPC=no' in logind.conf as default for OL7.2 [22224874]
    - allow dm remove ioctl to co-operate with UEK3 (Vaughan Cao) [Orabug: 18467469]
    - add hv dynamic memory support (Jerry Snitselaar) [Orabug: 18621475]
    - rules: load sg module (#1223340)
    - run: drop mistakenly committed test code (#1220272)
    - cgroup: downgrade log messages when we cannot write to cgroup trees that are mounted read-only
    (#1220298)
    - Revert 'conditionalize hardening away on s390(x)'
    - Revert 'units: fix BindsTo= logic when applied relative to services with Type=oneshot' (#1203803)
    - shared/install: avoid prematurely rejecting 'missing' units (#1199981)
    - core: fix enabling units via their absolute paths (#1199981)

    [219-30.3]
    - mtd_probe: add include for stdint (#1381573)

    [219-30.2]
    - manager: 219 needs u->id in log_unit_debug (#1381573)

    [219-30.1]
    - If the notification message length is 0, ignore the message (#4237) (#1381573)
    - systemctl: suppress errors with 'show' for nonexistent units and properties (#1380686)
    - 40-redhat.rules: disable auto-online of hot-plugged memory on IBM z Systems (#1381123)
    - pid1: don't return any error in manager_dispatch_notify_fd() (#4240) (#1381573)
    - pid1: process zero-length notification messages again (#1381573)
    - pid1: more informative error message for ignored notifications (#1381573)

    [219-30]
    - systemctl,pid1: do not warn about missing install info with 'preset' (#1373950)
    - systemctl/core: ignore masked units in preset-all (#1375097)
    - shared/install: handle dangling aliases as an explicit case, report nicely (#1375097)
    - shared/install: ignore unit symlinks when doing preset-all (#1375097)
    - 40-redhat.rules: don't hoplug memory on s390x (#1370161)

    [219-29]
    - fix gcc warnings about uninitialized variables (#1318994)
    - journalctl: rework code that checks whether we have access to /var/log/journal (#1318994)
    - journalctl: Improve boot ID lookup (#1318994)
    - journalctl: only have a single exit path from main() (#1318994)
    - journalctl: free all command line argument objects (#1318994)
    - journalctl: rename boot_id_t to BootId (#1318994)
    - util: introduce CMSG_FOREACH() macro and make use of it everywhere (#1318994)
    - journald: don't employ inner loop for reading from incoming sockets (#1318994)
    - journald: fix count of object meta fields (#1318994)
    - journal-cat: return a correct error, not -1 (#1318994)
    - journalctl: introduce short options for --since and --until (#1318994)
    - journal: s/Envalid/Invalid/ (#1318994)
    - journald: dispatch SIGTERM/SIGINT with a low priority (#1318994)
    - lz4: fix size check which had no chance of working on big-endian (#1318994)
    - journal: normalize priority of logging sources (#1318994)
    - Fix miscalculated buffer size and uses of size-unlimited sprintf() function. (#1318994)
    - journal: Drop monotonicity check when appending to journal file (#1318994)
    - journalctl: unify how we free boot id lists a bit (#1318994)
    - journalctl: don't trust the per-field entry tables when looking for boot IDs (#1318994)
    - units: remove udev control socket when systemd stops the socket unit (#49) (#1370133)
    - logind: don't assert if the slice is missing (#1371437)
    - core: enable transient unit support for slice units (#1370299)
    - sd-bus: bump message queue size (#1371205)
    - install: fix disable when /etc/systemd/system is a symlink (#1285996)
    - rules: add NVMe rules (#3136) (#1274651)
    - rules: introduce disk/by-id (model_serial) symlinks for NVMe drives (#3974) (#1274651)
    - rules: fix for possible whitespace in the 'model' attribute (#1274651)

    [219-27]
    - tmpfiles: enforce ordering when executing lines (#1365870)
    - Introduce bus_unit_check_load_state() helper (#1256858)
    - core: use bus_unit_check_load_state() in transaction_add_job_and_dependencies() (#1256858)
    - udev/path_id: correct segmentation fault due to missing NULL check (#1365556)
    - rules: load sg driver also when scsi_target appears (#45) (#1322773)

    [219-26]
    - install: do not crash when processing empty (masked) unit file (#1159308)
    - Revert 'install: fix disable via unit file path' (#1348208)
    - systemctl: allow disable on the unit file path, but warn about it (#3806) (#1348208)

    [219-25]
    - units: increase watchdog timeout to 3min for all our services (#1267707)
    - core: bump net.unix.max_dgram_qlen really early during boot (#1267707)
    - core: fix priority ordering in notify-handling (#1267707)
    - tests: fix personality tests on ppc64 and aarch64 (#1361049)
    - systemctl: consider service running only when it is in active or reloading state (#3874) (#1362461)

    [219-24]
    - manager: don't skip sigchld handler for main and control pid for services (#3738) (#1342173)

    [219-23]
    - udevadm: explicitly relabel /etc/udev/hwdb.bin after rename (#1350756)
    - systemctl: return diffrent error code if service exist or not (#3385) (#1047466)
    - systemctl: Replace init script error codes with enum (#3400) (#1047466)
    - systemctl: rework 'systemctl status' a bit (#1047466)
    - journal-verify: don't hit SIGFPE when determining progress (#1350232)
    - journal: avoid mapping empty data and field hash tables (#1350232)
    - journal: when verifying journal files, handle empty ones nicely (#1350232)
    - journal: explain the error when we find a non-DATA object that is compressed (#1350232)
    - journalctl: properly detect empty journal files (#1350232)
    - journal: uppercase first character in verify error messages (#1350232)
    - journalctl: make sure 'journalctl -f -t unmatched' blocks (#1350232)
    - journalctl: don't print -- No entries -- in quiet mode (#1350232)
    - sd-event: expose the event loop iteration counter via sd_event_get_iteration() (#1342173)
    - manager: Only invoke a single sigchld per unit within a cleanup cycle (#1342173)
    - manager: Fixing a debug printf formatting mistake (#1342173)
    - core: support IEC suffixes for RLIMIT stuff (#1351415)
    - core: accept time units for time-based resource limits (#1351415)
    - time-util: add parse_time(), which is like parse_sec() but allows specification of default time unit if
    none is specified (#1351415)
    - core: support <soft:hard> ranges for RLIMIT options (#1351415)
    - core: fix rlimit parsing (#1351415)
    - core: dump rlim_cur too (#1351415)
    - install: fix disable via unit file path (#1348208)

    [219-22]
    - nspawn: when connected to pipes for stdin/stdout, pass them as-is to PID 1 (#1307080)
    - mount: remove obsolete -n (#1339721)
    - core: don't log job status message in case job was effectively NOP (#3199) (#1280014)
    - core: use an AF_UNIX/SOCK_DGRAM socket for cgroup agent notification (#1305608)
    - logind: process session/inhibitor fds at higher priority (#1305608)
    - Teach bus_append_unit_property_assignment() about 'Delegate' property (#1337922)
    - sd-netlink: fix deep recursion in message destruction (#1330593)
    - add REMOTE_ADDR and REMOTE_PORT for Accept=yes (#1341154)
    - core: don't dispatch load queue when setting Slice= for transient units (#1343904)
    - run: make --slice= work in conjunction with --scope (#1343904)
    - myhostname: fix timeout if ipv6 is disabled (#1330973)
    - readahead: do not increase nr_requests for root fs block device (#1314559)
    - manager: reduce complexity of unit_gc_sweep (#3507) (#1344556)
    - hwdb: selinuxify a bit (#3460) (#1343648)

    [219-21]
    - path_id: reintroduce by-path links for virtio block devices (#952567)
    - journal: fix error handling when compressing journal objects (#1292447)
    - journal: irrelevant coding style fixes (#1292447)
    - install: follow unit file symlinks in /usr, but not /etc when looking for [Install] data (#1159308)
    - core: look for instance when processing template name (#1159308)
    - core: improve error message when starting template without instance (#1142369)
    - man/tmpfiles.d: add note about permissions and ownership of symlinks (#1296288)
    - tmpfiles: don't follow symlinks when adjusting ACLs, fille attributes, access modes or ownership
    (#1296288)
    - udev: filter out non-sensically high onboard indexes reported by the kernel (#1230210)
    - test-execute: add tests for RuntimeDirectory (#1324826)
    - core: fix group ownership when Group is set (#1324826)
    - fstab-generator: cescape device name in root-fsck service (#1306126)
    - core: add new RandomSec= setting for time units (#1305279)
    - core: rename Random* to RandomizedDelay* (#1305279)
    - journal-remote: change owner of /var/log/journal/remote and create /var/lib/systemd/journal-upload
    (#1327303)
    - Add Seal option in the configuration file for journald-remote (#1329233)
    - tests: fix make check failure (#1159308)
    - device: make sure to not ignore re-plugged device (#1332606)
    - device: Ensure we have sysfs path before comparing. (#1332606)
    - core: fix memory leak on set-default, enable, disable etc (#1331667)
    - nspawn: fix minor memory leak (#1331667)
    - basic: fix error/memleak in socket-util (#1331667)
    - core: fix memory leak in manager_run_generators() (#1331667)
    - modules-load: fix memory leak (#1331667)
    - core: fix memory leak on failed preset-all (#1331667)
    - sd-bus: fix memory leak in test-bus-chat (#1331667)
    - core: fix memory leak in transient units (#1331667)
    - bus: fix leak in error path (#1331667)
    - shared/logs-show: fix memleak in add_matches_for_unit (#1331667)
    - logind: introduce LockedHint and SetLockedHint (#3238) (#1335499)
    - import: use the old curl api (#1284974)
    - importd: drop dkr support (#1284974)
    - import: add support for gpg2 for verifying imported images (#1284974)

    [219-20]
    - run: synchronously wait until the scope unit we create is started (#1272368)
    - device: rework how we enter tentative state (#1283579)
    - core: Do not bind a mount unit to a device, if it was from mountinfo (#1283579)
    - logind: set RemoveIPC=no by default (#1284588)
    - sysv-generator: follow symlinks in /etc/rc.d/init.d (#1285492)
    - sysv-generator test: always log to console (#1279034)
    - man: RemoveIPC is set to no on rhel (#1284588)
    - Avoid /tmp being mounted as tmpfs without the user's will (#1298109)
    - test sysv-generator: Check for network-online.target. (#1279034)
    - arm/aarch64: detect-virt: check dmi (#1278165)
    - detect-virt: dmi: look for KVM (#1278165)
    - Revert 'journald: turn ForwardToSyslog= off by default' (#1285642)
    - terminal-util: when resetting terminals, don't wait for carrier (#1266745)
    - basic/terminal-util: introduce SYSTEMD_COLORS environment variable (#1247963)
    - ask-password: don't abort when message is missing (#1261136)
    - sysv-generator: do not join dependencies on one line, split them (#1288600)
    - udev: fibre channel: fix NPIV support (#1266934)
    - ata_id: unreverse WWN identifier (#1273306)
    - Fixup WWN bytes for big-endian systems (#1273306)
    - sd-journal: introduce has_runtime_files and has_persistent_files (#1082179)
    - journalctl: improve error messages when the specified boot is not found (#1082179)
    - journalctl: show friendly info when using -b on runtime journal only (#1082179)
    - journalctl: make 'journalctl /dev/sda' work (#947636)
    - journalctl: add match for the current boot when called with devpath (#947636)
    - man: clarify what happens when journalctl is called with devpath (#947636)
    - core: downgrade warning about duplicate device names (#1296249)
    - udev: downgrade a few warnings to debug messages (#1289461)
    - man: LEVEL in systemd-analyze set-log level is not optional (#1268336)
    - Revert 'udev: fibre channel: fix NPIV support' (#1266934)
    - udev: path-id: fibre channel NPIV - use fc_vport's port_name (#1266934)
    - systemctl: is-active/failed should return 0 if at least one unit is in given state (#1254650)
    - rules: set SYSTEMD_READY=0 on DM_UDEV_DISABLE_OTHER_RULES_FLAG=1 only with ADD event (#1312011)
    - s390: add personality support (#1300344)
    - socket_address_listen - do not rely on errno (#1316452)

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2016-2610.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-7795");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libgudev1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libgudev1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:systemd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:systemd-journal-gateway");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:systemd-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:systemd-networkd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:systemd-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:systemd-resolved");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:systemd-sysv");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 7', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var pkgs = [
    {'reference':'libgudev1-219-30.0.1.el7_3.3', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgudev1-devel-219-30.0.1.el7_3.3', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-219-30.0.1.el7_3.3', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-devel-219-30.0.1.el7_3.3', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-journal-gateway-219-30.0.1.el7_3.3', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-libs-219-30.0.1.el7_3.3', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-networkd-219-30.0.1.el7_3.3', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-python-219-30.0.1.el7_3.3', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-resolved-219-30.0.1.el7_3.3', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-sysv-219-30.0.1.el7_3.3', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgudev1-219-30.0.1.el7_3.3', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgudev1-devel-219-30.0.1.el7_3.3', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-219-30.0.1.el7_3.3', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-devel-219-30.0.1.el7_3.3', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-journal-gateway-219-30.0.1.el7_3.3', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-libs-219-30.0.1.el7_3.3', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-networkd-219-30.0.1.el7_3.3', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-python-219-30.0.1.el7_3.3', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-resolved-219-30.0.1.el7_3.3', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-sysv-219-30.0.1.el7_3.3', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libgudev1 / libgudev1-devel / systemd / etc');
}
