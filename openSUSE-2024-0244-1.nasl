#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2024:0244-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(205746);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/17");

  script_cve_id("CVE-2023-30549", "CVE-2023-38496", "CVE-2024-3727");

  script_name(english:"openSUSE 15 Security Update : apptainer (openSUSE-SU-2024:0244-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote openSUSE 15 host has packages installed that are affected by multiple vulnerabilities as referenced in the
openSUSE-SU-2024:0244-1 advisory.

    - Make sure, digest values handled by the Go library
      github.com/opencontainers/go-digest and used throughout the
      Go-implemented containers ecosystem are always validated. This
      prevents attackers from triggering unexpected authenticated
      registry accesses. (CVE-2024-3727, boo#1224114).


    - Updated apptainer to version 1.3.0
      * FUSE mounts are now supported in setuid mode, enabling full
        functionality even when kernel filesystem mounts are insecure due to
        unprivileged users having write access to raw filesystems in
        containers. When allow `setuid-mount extfs = no` (the default) in
        apptainer.conf, then the fuse2fs image driver will be used to mount
        ext3 images in setuid mode instead of the kernel driver (ext3 images
        are primarily used for the `--overlay` feature), restoring
        functionality that was removed by default in Apptainer 1.1.8 because
        of the security risk.
        The allow `setuid-mount squashfs` configuration option in
        `apptainer.conf` now has a new default called `iflimited` which allows
        kernel squashfs mounts only if there is at least one `limit container`
        option set or if Execution Control Lists are activated in ecl.toml.
        If kernel squashfs mounts are are not allowed, then the squashfuse
        image driver will be used instead.
        `iflimited` is the default because if one of those limits are used
        the system administrator ensures that unprivileged users do not have
        write access to the containers, but on the other hand using FUSE
        would enable a user to theoretically bypass the limits via `ptrace()`
        because the FUSE process runs as that user.
        The `fuse-overlayfs` image driver will also now be tried in setuid
        mode if the kernel overlayfs driver does not work (for example if
        one of the layers is a FUSE filesystem).  In addition, if `allow
        setuid-mount encrypted = no` then the unprivileged gocryptfs format
        will be used for encrypting SIF files instead of the kernel
        device-mapper. If a SIF file was encrypted using the gocryptfs
        format, it can now be mounted in setuid mode in addition to
        non-setuid mode.
      * Change the default in user namespace mode to use either kernel
        overlayfs or fuse-overlayfs instead of the underlay feature for the
        purpose of adding bind mount points. That was already the default in
        setuid mode; this change makes it consistent. The underlay feature
        can still be used with the `--underlay` option, but it is deprecated
        because the implementation is complicated and measurements have
        shown that the performance of underlay is similar to overlayfs and
        fuse-overlayfs.
        For now the underlay feature can be made the default again with a
        new `preferred` value on the `enable underlay` configuration option.
        Also the `--underlay` option can be used in setuid mode or as the
        root user, although it was ignored previously.
      * Prefer again to use kernel overlayfs over fuse-overlayfs when a
        lower layer is FUSE and there's no writable upper layer, undoing the
        change from 1.2.0. Another workaround was found for the problem that
        change addressed. This applies in both setuid mode and in user
        namespace mode.
      * `--cwd` is now the preferred form of the flag for setting the
        container's working directory, though `--pwd` is still supported for
        compatibility.
      * The way `--home` is handled when running as root (e.g. sudo apptainer)
        or with `--fakeroot` has changed. Previously, we were only modifying
        the `HOME` environment variable in these cases, while leaving the
        container's `/etc/passwd` file unchanged (with its homedir field
        pointing to `/root`, regardless of the value passed to `--home`). With
        this change, both value of HOME and the contents of `/etc/passwd` in
        the container will reflect the value passed to `--home` if the
        container is readonly. If the container is writable, the
        `/etc/passwd` file is left alone because it can interfere with
        commands that want to modify it.
      * The `--vm` and related flags to start apptainer inside a VM have been
        removed. This functionality was related to the retired Singularity Desktop
        / SyOS projects.
      * The keyserver-related commands that were under `remote` have been moved to
        their own, dedicated `keyserver` command. Run `apptainer help keyserver`
        for more information.
      * The commands related to OCI/Docker registries that were under `remote` have
        been moved to their own, dedicated `registry` command. Run
        `apptainer help registry` for more information.
      * The the `remote list` subcommand now outputs only remote endpoints (with
        keyservers and OCI/Docker registries having been moved to separate
        commands), and the output has been streamlined.
      * Adding a new remote endpoint using the `apptainer remote add` command will
        now set the new endpoint as default. This behavior can be suppressed by
        supplying the `--no-default` (or `-n`) flag to `remote add`.
      * Skip parsing build definition file template variables after comments
        beginning with a hash symbol.
      * The global `/tmp` directory is no longer used for gocryptfs mountpoints.
    - New Features & Functionality
      * The `remote status` command will now print the username, realname, and
        email of the logged-in user, if available.
      * Add monitoring feature support, which requires the usage of an
        additional tool named `apptheus`, this tool will put apptainer starter
        into a newly created cgroup and collect system metrics.
      * A new `--no-pid` flag for `apptainer run/shell/exec` disables the PID
        namespace inferred by `--containall` and `--compat`.
      * Added `--config` option to `keyserver` commands.
      * Honor an optional remoteName argument to the `keyserver list` command.
      * Added the `APPTAINER_ENCRYPTION_PEM_DATA` env var to allow for
        encrypting and running encrypted containers without a PEM file.
      * Adding `--sharens` mode for `apptainer exec/run/shell`, which enables to
        run multiple apptainer instances created by the same parent using
        the same image in the same user namespace.
    - Make 'gocryptfs' an optional dependency.
    - Make apptainer definition templates version dependent.

    - Fix 'apptainer build' using signed packages from the SUSE
      Registry (boo#1221364).

    - Updated apptainer to version 1.2.5
      * Added `libnvidia-nvvm` to `nvliblist.conf`. Newer NVIDIA
        Drivers (known with >= 525.85.05) require this lib to compile
        OpenCL programs against NVIDIA GPUs, i.e. `libnvidia-opencl`
        depends on `libnvidia-nvvm`.
      * Disable the usage of cgroup in instance creation when
        `--fakeroot` is passed.
      * Disable the usage of cgroup in instance creation when `hidepid`
        mount option on `/proc` is set.
      * Fixed a regression introduced in 1.2.0 where the user's
        password file information was not copied in to the container
        when there was a parent root-mapped user namespace (as is the
        case for example in `cvmfsexec`).
      * Added the upcoming NVIDIA driver library `libnvidia-gpucomp.so`
        to the list of libraries to add to NVIDIA GPU-enabled
        containers. Fixed missing error handling during the creation
        of an encrypted image that lead to the generation of corrupted
        images.
      * Use `APPTAINER_TMPDIR` for temporary files during privileged
        image encryption.
      * If rootless unified cgroups v2 is available when starting an
        image but `XDG_RUNTIME_DIR` or `DBUS_SESSION_BUS_ADDRESS` is
        not set, print an info message that stats will not be available
        instead of exiting with a fatal error.
      * Allow templated build arguments to definition files to have
        empty values.
    - Package .def templates separately for different SPs.

    - Do not build squashfuse, require it as a dependency.
    - Replace awkward 'Obsoletes: singularity-*' as well as the
      'Provides: Singularity' by 'Conflicts:' and drop the provides -
      the versioning scheme does not match and we do not automatically
      migrate from one to the other.
    - Exclude platforms which do not provide all build dependencies.

    - updated to 1.2.3 with following changes:
      * The apptainer push/pull commands now show a progress bar for the oras
        protocol like there was for docker and library protocols.
      * The --nv and --rocm flags can now be used simultaneously.
      * Fix the use of APPTAINER_CONFIGDIR with apptainer instance start and action
        commands that refer to instance://.
      * Fix the issue that apptainer would not read credentials from the Docker
        fallback path ~/.docker/config.json if missing in the apptainer
        credentials.

    - updated to 1.2.2 with following changes:
      * Fix $APPTAINER_MESSAGELEVEL to correctly set the logging level.
      * Fix build failures when in setuid mode and unprivileged user namespaces are
        unavailable and the --fakeroot option is not selected.

    - updated to 1.2.1 to fix CVE-2023-38496 although not relevant as package is
      compiled with setuid

    - update to 1.2.0 with following changes:
      * binary is built reproducible which disables plugins
      * Create the current working directory in a container when it doesn't exist.
        This restores behavior as it was before singularity 3.6.0. As a result,
        using --no-mount home won't have any effect when running apptainer from a
        home directory and will require --no-mount home,cwd to avoid mounting that
        directory.
      * Handle current working directory paths containing symlinks both on the host
        and in a container but pointing to different destinations. If detected, the
        current working directory is not mounted when the destination directory in
        the container exists.
      * Destination mount points are now sorted by shortest path first to ensure
        that a user bind doesn't override a previous bind path when set in
        arbitrary order on the CLI. This is also applied to image binds.
      * When the kernel supports unprivileged overlay mounts in a user namespace,
        the container will be constructed by default using an overlay instead of an
        underlay layout for bind mounts. A new --underlay action option can be used
        to prefer underlay instead of overlay.
      * sessiondir maxsize in apptainer.conf now defaults to 64 MiB for new
        installations. This is an increase from 16 MiB in prior versions.
      * The apptainer cache is now architecture aware, so the same home directory
        cache can be shared by machines with different architectures.
      * Overlay is blocked on the panfs filesystem, allowing sandbox directories to
        be run from panfs without error.
      * Lookup and store user/group information in stage one prior to entering any
        namespaces, to fix an issue with winbind not correctly looking up
        user/group information when using user namespaces.
    - New features / functionalities
      * Support for unprivileged encryption of SIF files using gocryptfs.  This is
        not compatible with privileged encryption, so containers encrypted by root
        need to be rebuilt by an unprivileged user.
      * Templating support for definition files. Users can now define variables in
        definition files via a matching pair of double curly brackets. Variables of
        the form {{ variable }} will be replaced by a value defined either by a
        variable=value entry in the %arguments section of the definition file or
        through new build options --build-arg or --build-arg-file.
      * Add a new instance run command that will execute the runscript when an
        instance is initiated instead of executing the startscript.
      * The sign and verify commands now support signing and verification with
        non-PGP key material by specifying the path to a private key via the --key
        flag.
      * The verify command now supports verification with X.509 certificates by
        specifying the path to a certificate via the --certificate flag. By
        default, the system root certificate pool is used as trust anchors unless
        overridden via the --certificate-roots flag. A pool of intermediate
        certificates that are not trust anchors, but can be used to form a
        certificate chain, can also be specified via the
        --certificate-intermediates flag.
      * Support for online verification checks of X.509 certificates using OCSP
        protocol via the new verify --ocsp-verify option.
      * The instance stats command displays the resource usage every second. The
        --no-stream option disables this interactive mode and shows the
        point-in-time usage.
      * Instances are now started in a cgroup by default, when run as root or when
        unified cgroups v2 with systemd as manager is configured. This allows
        apptainer instance stats to be supported by default when possible.
      * The instance start command now accepts an optional --app <name> argument
        which invokes a start script within the %appstart <name> section in the
        definition file. The instance stop command still only requires the instance
        name.
      * The instance name is now available inside an instance via the new
        APPTAINER_INSTANCE environment variable.
      * The --no-mount flag now accepts the value bind-paths to disable mounting of
        all bind path entries in apptainer.conf.
        Support for DOCKER_HOST parsing when using docker-daemon://
        DOCKER_USERNAME and DOCKER_PASSWORD supported without APPTAINER_ prefix.
        Add new Linux capabilities CAP_PERFMON, CAP_BPF, and CAP_CHECKPOINT_RESTORE.
      * The remote get-login-password command allows users to retrieve a remote's
        token. This enables piping the secret directly into docker login while
        preventing it from showing up in a shell's history.
      * Define EUID in %environment alongside UID.
      * In --rocm mode, the whole of /dev/dri is now bound into the container when
        --contain is in use. This makes /dev/dri/render devices available, required
        for later ROCm versions.

    - update to 1.1.9 with following changes:
      * Remove warning about unknown xino=on option from fuse-overlayfs, introduced
        in 1.1.8.
      * Ignore extraneous warning from fuse-overlayfs about a readonly /proc.
      * Fix dropped 'n' characters on some platforms in definition file stored as
        part of SIF metadata.
      * Remove duplicated group ids.
      * Fix not being able to handle multiple entries in LD_PRELOAD when binding
        fakeroot into container during apptainer startup for --fakeroot with
        fakeroot command.

    - Included a fix for CVE-2023-30549 which is a vulnerability in setuid-root
      installations of Apptainer iwhich was not active in the recent openSUSE
      packages. Still this is included for completenss. The fix adds allow
      setuid-mount configuration options encrypted, squashfs, and extfs, and makes
      the default for extfs be 'no'. That disables the use of extfs mounts
      including for overlays or binds while in the setuid-root mode, while leaving
      it enabled for unprivileged user namespace mode. The default for encrypted
      and squashfs is 'yes'.
    - Other bug fixes:
      * Fix loop device 'no such device or address' spurious errors when using shared
        loop devices.
      * Add xino=on mount option for writable kernel overlay mount points to fix
        inode numbers consistency after kernel cache flush (not applicable to
        fuse-overlayfs).


    - updated to 1.1.7 with following changes:
      * Allow gpu options such as --nv to be nested by always inheriting all
        libraries bound in to a parent container's /.singularity.d/libs.
      * Map the user's home directory to the root home directory by default in the
        non-subuid fakeroot mode like it was in the subuid fakeroot mode, for both
        action commands and building containers from definition files.
      * Make the error message more helpful in another place where a remote is
        found to have no library client.
      * Avoid incorrect error when requesting fakeroot network.
      * Pass computed LD_LIBRARY_PATH to wrapped unsquashfs. Fixes issues where
        unsquashfs on host uses libraries in non-default paths.

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221364");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224114");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/3BEJQC6TDQZLJ4YE746IHLCFJFUQ2JKQ/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?61dcc3e1");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-30549");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-38496");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-3727");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-30549");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apptainer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apptainer-leap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apptainer-sle15_5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apptainer-sle15_6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsquashfuse0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:squashfuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:squashfuse-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:squashfuse-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.5");
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
if (os_release !~ "^(SUSE15\.5)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.5', os_release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + _os_ver, cpu);

var pkgs = [
    {'reference':'apptainer-1.3.0-bp155.3.3.2', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'apptainer-1.3.0-bp155.3.3.2', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'apptainer-leap-1.3.0-bp155.3.3.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'apptainer-sle15_5-1.3.0-bp155.3.3.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'apptainer-sle15_6-1.3.0-bp155.3.3.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsquashfuse0-0.5.0-bp155.2.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'squashfuse-0.5.0-bp155.2.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'squashfuse-devel-0.5.0-bp155.2.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'squashfuse-tools-0.5.0-bp155.2.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'apptainer / apptainer-leap / apptainer-sle15_5 / apptainer-sle15_6 / etc');
}
