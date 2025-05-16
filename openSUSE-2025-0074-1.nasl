#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2025:0074-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(216855);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/26");

  script_cve_id("CVE-2024-21626", "CVE-2025-24965");

  script_name(english:"openSUSE 15 Security Update : crun (openSUSE-SU-2025:0074-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote openSUSE 15 host has a package installed that is affected by multiple vulnerabilities as referenced in the
openSUSE-SU-2025:0074-1 advisory.

    Update to 1.20:

      * krun: fix CVE-2025-24965. The .krun_config.json file could be created outside of the container rootfs.
    (bsc#1237421)
      * cgroup: reverted the removal of tun/tap from the default allow list, this was done in crun-1.5. The
    tun/tap device is now added by default again.
      * CRIU: do not set network_lock unless explicitly specified.
      * status: disallow container names containing slashes in their name.
      * linux: Improved error message when failing to set the net.ipv4.ping_group_range sysctl.
      * scheduler: Ignore ENOSYS errors when resetting the CPU affinity mask.
      * linux: return a better error message when pidfd_open fails with EINVAL.
      * cgroup: display the absolute path to cgroup.controllers when a controller is unavailable.
      * exec: always call setsid. Now processes created through exec get the correct process group id.

    Update to 1.19.1:

      * linux: fix a hang if there are no reads from the tty. Use non blocking
        sockets to read and write from the tty so that the 'crun exec' process
        doesn't hang when the terminal is not consuming any data.
      * linux: remove the workaround needed to mount a cgroup on top of
        another cgroup mount. The workaround had the disadvantage to temporarily
        leak a mount on the host. The alternative that is currently used is
        to mount a temporary tmpfs between the twoo cgroup mounts.

    Update to 1.19:
      * wasm: add new handler wamr.
      * criu: allow passing network lock method to libcriu.
      * linux: honor exec cpu affinity mask.
      * build: fix build with musl libc.
      * crun: use mount API to self-clone.
      * cgroup, systemd: do not override devices on update. If the 'update' request has no device block
    configured, do not reset the previously configuration.
      * cgroup: handle case where cgroup v1 freezer is disabled. On systems without the freezer controller,
    containers were mistakenly reported as paused.
      * cgroup: do not stop process on exec. The cpu mask is configured on the systemd scope, the previous
    workaround to stop the container until the cgroup is fully configured is no longer needed.

    - Update to crun v1.18.2 Upstream changelog is available from
      <https://github.com/containers/crun/releases/tag/1.18.2>

    - Update to crun v1.18. Upstream changelog is available from
      <https://github.com/containers/crun/releases/tag/1.18>

    Update to 1.17:

      * Add --log-level option. It accepts error, warning and error.
      * Add debug logs for container creation.
      * Fix double-free in crun exec code that could lead to a crash.
      * Allow passing an ID to the journald log driver.
      * Report 'executable not found' errors after tty has been setup.
      * Do not treat EPIPE from hooks as an error.
      * Make sure DefaultDependencies is correctly set in the systemd scope.
      * Improve the error message when the container process is not found.
      * Improve error handling for the mnt namespace restoration.
      * Fix error handling for getpwuid_r, recvfrom and libcrun_kill_linux.
      * Fix handling of device paths with trailing slashes.
    - add url for keyring
    - enable leap by disabling wasmedge (not packaged for leap)

    Upstream release 1.16.1:

    - fix a regression introduced by 1.16 where using 'rshared' rootfs mount propagation and the rootfs itself
    is a mountpoint.
    - inherit user from original process on exec, if not overridden.

    Update to 1.16:

    - build: fix build for s390x.
    - linux: fix mount of special files with rro.  Open the mount target with O_PATH to prevent open(2)
    failures with special files like FIFOs or UNIX sockets.
    - Fix sd-bus error handling for cpu quota and period props update.
    - container: use relative path for rootfs if possible.  If the rootfs cannot be resolved and it is below
    the current working directory, only use its relative path.
    - wasmedge: access container environment variables for the WasmEdge configuration.
    - cgroup, systemd: use MemoryMax instead of MemoryLimit.  Fixes a warning for using an old configuration
    name.
    - cgroup, systemd: improve checks for sd_bus_message_append errors

    New upstream release 1.15:

      * fix a mount point leak under /run/crun, add a retry mechanism to unmount the directory if the removal
    failed with EBUSY.
      * linux: cgroups: fix potential mount leak when /sys/fs/cgroup is already mounted, causing the posthooks
    to not run.
      * release: build s390x binaries using musl libc.
      * features: add support for potentiallyUnsafeConfigAnnotations.
      * handlers: add option to load wasi-nn plugin for wasmedge.
      * linux: fix 'harden chdir()' security measure. The previous check was not correct.
      * crun: add option --keep to the run command. When specified the container is not automatically deleted
    when it exits.

    New upstream release 1.14.4:

    - linux: fix mount of file with recursive flags.  Do not assume it is
      a directory, but check the source type.

    - follow up for 1.14.2.  Drop the version check for each command.

    - crun: drop check for OCI version.  A recent bump in the OCI runtime
      specs caused crun to fail with every config file.  Just drop the
      check since it doesn't add any value.

    - there was recently a security vulnerability (CVE-2024-21626) in runc
      that allowed a malicious user to chdir(2) to a /proc/*/fd entry that is
      outside the container rootfs.  While crun is not affected directly,
      harden chdir by validating that we are still inside the container
      rootfs.
    - container: attempt to close all the files before execv(2).
      if we leak any fd, it prevents execv to gain access to files outside
      the container rootfs through /proc/self/fd/$fd.
    - fix a regression caused by 1.14 when installing the ebpf filter on a
      kernel older than 5.11.
    - cgroup, systemd: fix segfault if the resources block is not specified.

    Update to 1.14:

      * build: drop dependency on libgcrypt. Use blake3 to compute the cache key.
      * cpuset: don't clobber parent cgroup value when writing the cpuset value.
      * linux: force umask(0). It ensures that the mknodat syscall is not affected by the umask of the calling
    process,
        allowing file permissions to be set as specified in the OCI configuration.
      * ebpf: do not require MEMLOCK for eBPF programs. This requirement was relaxed in Linux 5.11.
    - update to 1.13:
      * src: use O_CLOEXEC for all open/openat calls
      * cgroup v1: use 'max' when pids limit < 0.
      * improve error message when idmap mount fails because the underlying file system has no support for it.
      * libcrun: fix compilation when building without libseccomp and libcap.
      * fix relative idmapped mount when using the custom annotation.

    - New upstream release 1.12:
      * add new WebAssembly handler: spin.
      * systemd: fallback to system bus if session bus is not available.
      * configure the cpu rt and cpuset controllers before joining them to
        avoid running temporarily the workload on the wrong cpus.
      * preconfigure the cpuset with required resources instead of using the
        parent's set.  This prevents needless churn in the kernel as it
        tracks which CPUs have load balancing disabled.
      * try attr/<lsm>/* before the attr/* files.  Writes to the attr/*
        files may fail if apparmor is not the first 'major' LSM in the list
        of loaded LSMs (e.g. lsm=apparmor,bpf vs lsm=bpf,apparmor).
    - New upstream release 1.11.2:
      * fix a regression caused by 1.11.1 where the process crashes if there
        are no CPU limits configured on cgroup v1. (boo#1217590)
      * fix error code check for the ptsname_r function.

    - update to 1.11.1:
      * force a remount operation with bind mounts from the host to
        correctly set all the mount flags.
      * cgroup: honor cpu burst.
      * systemd: set CPUQuota and CPUPeriod on the scope cgroup.
      * linux: append tmpfs mode if missing for mounts.  This is the
        same behavior of runc.
      * cgroup: always use the user session for rootless.
      * support for Intel Resource Director Technology (RDT).
      * new mount option 'copy-symlink'.  When provided for a mount,
        if the source is a symlink, then it is copied in the container
        instead of attempting a mount.
      * linux: open mounts before setgroups if in a userns.  This
        solves a problem where a directory that was previously
        accessible to the user, become inaccessible after setgroups
        causing the bind mount to fail.

    - New upstream release 1.9.2:
      * cgroup: reset the inherited cpu affinity after moving to cgroup. Old kernels
        do that automatically, but new kernels remember the affinity that was set
        before the cgroup move, so we need to reset it in order to honor the cpuset
        configuration.
    - New upstream release 1.9.1:
      * utils: ignore ENOTSUP when chmod a symlink. It fixes a problem on Linux 6.6
        that always refuses chmod on a symlink.
      * build: fix build on CentOS 7
      * linux: add new fallback when mount fails with EBUSY, so that there is not an
        additional tmpfs mount if not needed.
      * utils: improve error message when a directory cannot be created as a
        component of the path is already existing as a non directory.
    - Only build with wasmedge on x86_64 & aarch64

    - Add crun-wasm symlink for platform 'wasi/wasm'

    - Update to 1.9:
      * linux: support arbitrary idmapped mounts.
      * linux: add support for 'ridmap' mount option to support recursive
        idmapped mounts.
      * crun delete: call systemd's reset-failed.
      * linux: fix check for oom_score_adj.
      * features: Support mountExtensions.
      * linux: correctly handle unknown signal string when it doesn't start with
        a digit.
      * linux: do not attempt to join again already joined namespace.
      * wasmer: use latest wasix API.

    - Enable WasmEdge support to run Wasm compat containers.

      * linux: idmapped mounts expect the same configuration as
        mapping. It is a breaking change, but the behavior was aligned
      * cgroup: always delete the cgroup on errors.
      ? exec: fix double free when using --apparmor and

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217590");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218894");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237421");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/MFFSKUX256PEK52RLQGT33MIN3ZQO27D/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1cf9d252");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-21626");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-24965");
  script_set_attribute(attribute:"solution", value:
"Update the affected crun package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:P");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-21626");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2025-24965");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crun");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (os_release !~ "^(SUSE15\.6)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.6', os_release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + _os_ver, cpu);

var pkgs = [
    {'reference':'crun-1.20-bp156.2.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'crun');
}
