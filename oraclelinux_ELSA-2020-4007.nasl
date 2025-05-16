##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2020-4007.
##

include('compat.inc');

if (description)
{
  script_id(141225);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/01");

  script_cve_id("CVE-2019-20386");

  script_name(english:"Oracle Linux 7 : systemd (ELSA-2020-4007)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 host has packages installed that are affected by a vulnerability as referenced in the
ELSA-2020-4007 advisory.

    [219-78.0.1]
    - Backport upstream patches related to private-tmp (Sushmita Bhattacharya) [Orabug: 31561883]
    - backport upstream pstore tmpfiles patch (Eric DeVolder) [Orabug: 31414539]
    - udev rules: fix memory hot add and remove [Orabug: 31309730]
    - enable and start the pstore service [Orabug: 30950903]
    - fix to generate the systemd-pstore.service file [Orabug: 30235241]
    - Backport upstream patches for the new systemd-pstore tool [Orabug: 30235241]
    - do not create utmp update symlinks for reboot and poweroff [Orabug: 27854896]
    - OL7 udev rule for virtio net standby interface [Orabug: 28826743]
    - fix _netdev is missing for iscsi entry in /etc/fstab [Orabug: 25897792] (tony.l.lam@oracle.com)
    - set 'RemoveIPC=no' in logind.conf as default for OL7.2 [22224874]
    - allow dm remove ioctl to co-operate with UEK3 (Vaughan Cao) [Orabug: 18467469]
    - add hv dynamic memory support (Jerry Snitselaar) [Orabug: 18621475]

    [219-78]
    - avoid double free (#1832816)

    [219-77]
    - core: coldplug possible nop_job (#1829754)
    - core: make sure to restore the control command id, too (#1828953)

    [219-76]
    - core: enforce a ratelimiter when stopping units due to StopWhenUnneeded=1 (#1775291)
    - core: rework StopWhenUnneeded= logic (#1775291)

    [219-75]
    - journal: break recursion (#1778744)

    [219-74]
    - sd-bus: bump message queue size again (#1770158)
    - unit: fix potential use of cgroup_path after free() when freeing unit (#1760149)
    - add test for ExecStopPost (#1733998)
    - core: when restarting services, dont close fds (#1757704)
    - unit: rework a bit how we keep the service fdstore from being destroyed during service restart
    (#1757704)
    - tests: add basic journal test (#1757704)
    - tests: add regression test for 'systemctl restart systemd-journald' (#1757704)
    - tests: add test that journald keeps fds over termination by signal (#1757704)
    - nss-util: silence warning about deprecated RES_USE_INET6 (#1799002)
    - journal: do not trigger assertion when journal_file_close() get NULL (#1786046)
    - mount: dont propagate errors from mount_setup_unit() further up (#1804757)
    - mount: when allocating a Mount object based on /proc/self/mountinfo mark it so (#1804757)
    - fix the fix for #1691511 (#1804757)
    - v3: Properly parsing SCSI Hyperv devices (#8509) (#1809053)
    - Consider smb3 as remote filesystem (#1811700)
    - mount: dont add Requires for tmp.mount (#1813270)
    - sd-bus: when attached to an sd-event loop, disconnect on processing errors (#1769928)
    - sd-journal: close journal files that were deleted by journald before weve setup inotify watch (#1812889)
    - sd-journal: remove the dead code and actually fix #14695 (#1812889)
    - swap: adjust swap.c in a similar way to what we just did to mount.c (#1749621)
    - swap: finish the secondary swap units jobs if deactivation of the primary swap unit fails (#1749621)
    - core: add a new unit file setting CollectMode= for tweaking the GC logic (#1817576)
    - run: add '-G' as shortcut for '--property=CollectMode=inactive-or-failed' (#1817576)
    - core: clarify that the CollectMode bus property is constant (#1817576)
    - udev-rules: make tape-changers also apprear in /dev/tape/by-path/ (#1814028)
    - logind: check PolicyKit before allowing VT switch (#1797672)
    - timer: dont use persietent file timestamps from the future (#6823) (#1769923)
    - core: transition to FINAL_SIGTERM state after ExecStopPost= (#1766477)
    - bus_open leak sd_event_source when udevadm trigger (#1798503)
    - journal-remote: split-mode=host, remove port from journal filename (#1244691)
    - core: downgrade log message about inability to propagate cgroup release message (#1679934)
    - units: move Before deps for quota services to remote-fs.target (#5627) (#1693374)
    - set kptr_restrict=1 (#1689344)

    [219-73.3]
    - journal: do not trigger assertion when journal_file_close() get NULL (#1807798)

    [219-73.2]
    - core: when restarting services, dont close fds (#1803802)
    - unit: rework a bit how we keep the service fdstore from being destroyed during service restart
    (#1803802)
    - tests: add basic journal test (#1803802)
    - tests: add regression test for 'systemctl restart systemd-journald' (#1803802)
    - tests: add test that journald keeps fds over termination by signal (#1803802)

    [219-73.1]
    - unit: fix potential use of cgroup_path after free() when freeing unit (#1760149)

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2020-4007.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-20386");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 7', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var pkgs = [
    {'reference':'libgudev1-219-78.0.1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgudev1-devel-219-78.0.1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-219-78.0.1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-devel-219-78.0.1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-journal-gateway-219-78.0.1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-libs-219-78.0.1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-networkd-219-78.0.1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-python-219-78.0.1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-resolved-219-78.0.1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-sysv-219-78.0.1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgudev1-219-78.0.1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgudev1-devel-219-78.0.1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-219-78.0.1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-devel-219-78.0.1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-journal-gateway-219-78.0.1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-libs-219-78.0.1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-networkd-219-78.0.1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-python-219-78.0.1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-resolved-219-78.0.1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-sysv-219-78.0.1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgudev1-219-78.0.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgudev1-devel-219-78.0.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-219-78.0.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-devel-219-78.0.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-journal-gateway-219-78.0.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-libs-219-78.0.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-networkd-219-78.0.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-python-219-78.0.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-resolved-219-78.0.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-sysv-219-78.0.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libgudev1 / libgudev1-devel / systemd / etc');
}
