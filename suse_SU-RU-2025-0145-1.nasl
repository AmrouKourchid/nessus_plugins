#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-SUSE-RU-2025:0145-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(214292);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/17");

  script_cve_id("CVE-2024-32462", "CVE-2024-42472");
  script_xref(name:"SuSE", value:"SUSE-RU-2025:0145-1");

  script_name(english:"SUSE SLED15 / SLES15 / openSUSE 15 : Recommended update for bubblewrap, flatpak, wayland-protocols (SUSE-SU-SUSE-RU-2025:0145-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED15 / SLED_SAP15 / SLES15 / SLES_SAP15 / openSUSE 15 host has packages installed that are
affected by multiple vulnerabilities as referenced in the SUSE-SU-SUSE-RU-2025:0145-1 advisory.

    This update for bubblewrap, flatpak updates flatpak to 1.16.0.

    flatpak changes:

    - Update to version 1.16.0:

      - Bug fixes:

        - Update libglnx to 2024-12-06:

          . Fix an assertion failure if creating a parent directory
            encounters a dangling symlink.
          . Fix a Meson warning.
          . Don't emit terminal progress indicator escape sequences by
            default. They are interpreted as notifications by some
            terminal emulators.
        - Fix introspection annotations in libflatpak.

      - Enhancements:

        - Add the FLATPAK_TTY_PROGRESS environment variable, which
          re-enables the terminal progress indicator escape sequences
          added in 1.15.91.
        - Document the FLATPAK_FANCY_OUTPUT environment variable, which
          allows disabling the fancy formatting when outputting to a
          terminal.

    Update to version 1.15.91 (unstable):

      - Enhancements:

        - Add the FLATPAK_DATA_DIR environment variable, which allows
          overriding at runtime the data directory location that
          Flatpak uses to search for configuration files such as
          remotes. This is useful for running tests, and for when
          installing using Flatpak in a chroot.
        - Add a FLATPAK_DOWNLOAD_TMPDIR variable. This allows using
          download directories other than /var/tmp.
        - Emit progress escape sequence. This can be used by terminal
          emulators to detect and display progress of Flatpak
          operations on their graphical user interfaces.

      - Bug fixes:

        - Install missing test data. This should fix 'as-installed'
          tests via ginsttest-runner, used for example in Debian's
          autopkgtest framework.
        - Unify and improve how the Wayland socket is passed to the
          sandboxed app. This should fix a regression that is triggered
          by compositors that both implement the security-context-v1
          protocol, and sets the WAYLAND_DISPLAY environment variable
          when launching Flatpak apps.
        - Fix the plural form of a translatable string.

    Update to version 1.15.12:

      - Return to using the process ID of the Flatpak app in the cgroup
        name. Using the instance ID in 1.15.11 caused crashes when
        installing apps, extensions or runtimes that use the 'extra
        data' mechanism, which does not set up an instance ID.

    Changes from version 1.15.11:

      - Dependencies:

        - In distributions that compile Flatpak to use a separate
          xdg-dbus-proxy executable, version 0.1.6 is recommended (but
          not required).
        - The minimum xdg-dbus-proxy continues to be 0.1.0.

      - Enhancements:

        - Allow applications like WebKit to connect the AT-SPI
          accessibility tree of processes in a sub-sandbox with the
          tree in the main process.
          . New sandboxing parameter flatpak run --a11y-own-name, which
            is like --own-name but for the accessibility bus.
          . flatpak-portal API v7: add new sandbox-a11y-own-names
            option, which accepts names matching ${FLATPAK_ID}.*
          . Apps may call the org.a11y.atspi.Socket.Embedded method on
            names matching ${FLATPAK_ID}.Sandboxed.* by default
          . flatpak run -vv $app_id shows all applicable sandboxing
            parameters and their source, including overrides, as debug
            messages
        - Introduce USB device listing
          . Apps can list which USB devices they want to access ahead
            of time by using the --usb parameter. Check the manpages
            for the more information about the accepted syntax.
          . Denying access to USB devices is also possible with the
            --no-usb parameter. The syntax is equal to --usb.
          . Both options merely store metadata, and aren't used by
            Flatpak itself. This metadata is intended to be used by the
            (as of now, still in progress) USB portal to decide which
            devices the app can enumerate and request access.
        - Add support for KDE search completion
        - Use the instance id of the Flatpak app as part of the cgroup
          name. This better matches the naming conventions for cgroup.

      - Bug fixes:

        - Update libglnx to 2024-08-23
        - fix build in environments that use -Werror=return-type, such
          as openSUSE Tumbleweed
        - add a fallback definition for G_PID_FORMAT with older GLib
        - avoid warnings for g_steal_fd() with newer GLib
        - improve compatibility of g_closefrom() backport with newer
          GLib
        - Update meson wrap file for xdg-dbus-proxy to version 0.1.6:
        - compatibility with D-Bus implementations that pipeline the
          authentication handshake, such as sd-bus and zbus
        - compatibility with D-Bus implementations that use
          non-consecutive serial numbers, such as godbus and zbus
        - broadcast signals can be allowed without having to add TALK
          permission
        - fix memory leaks

      - Internal changes:

        - Better const-correctness
        - Fix a shellcheck warning in the tests

    - add weak dep on p11-kit-server for certificate transfer (boo#1188902)
    - disable parental controls for now by using '-Dmalcontent=disabled', to work around
      issues with xdg-desktop-portal

    Update to version 1.14.10:

      - Dependencies: In distributions that compile Flatpak to use a
        separate bubblewrap (bwrap) executable, either version 0.10.0,
        version 0.6.x  0.6.3, or a version with a backport of the
        --bind-fd option is required. These versions add a new feature
        which is required by the security fix in this release.
      - Security fixes: Don't follow symbolic links when mounting
        persistent directories (--persist option). This prevents a
        sandbox escape where a malicious or compromised app could edit
        the symlink to point to a directory that the app should not have
        been allowed to read or write. (bsc#1229157, CVE-2024-42472,
        GHSA-7hgv-f2j8-xw87)
      - Documentation: Mark the 1.12.x and 1.10.x branches as
        end-of-life (#5352)
      - Version 1.14.9 was not released due to an incompatibility with
        older versions of GLib. Version 1.14.10 replaces it.

    Update to version 1.14.8:

      - No changes. This release is rolling out to correct mismatching
        submodule versions in the release tarball.

    Update to version 1.14.7:

      - New features: Automatically reload D-Bus session bus
        configuration after installing or upgrading apps, to pick up
        any exported D-Bus services (#3342)
      - Bug fixes:
        - Expand the list of environment variables that Flatpak apps do
          not inherit from the host system (#5765, #5785)
        - Don't refuse to start apps when there is no D-Bus system bus
          available (#5076)
        - Don't try to repeat migration of apps whose data was migrated
          to a new name and then deleted (#5668)
        - Fix warnings from newer GLib versions (#5660)
        - Always set the container environment variable (#5610)
        - In flatpak ps, add xdg-desktop-portal-gnome to the list of
          backends we'll use to learn which apps are running in the
          background (#5729)
        - Avoid leaking a temporary variable from
          /etc/profile.d/flatpak.sh into the shell environment (#5574)
        - Avoid undefined behaviour of signed left-shift when storing
          object IDs in a hash table (#5738)
        - Fix Docbook validity in documentation (#5719)
        - Skip more tests when FUSE isn't available (#5611)
        - Fix a misleading comment in the test for CVE-2024-32462
          (#5779)
      - Internal changes:
        - Fix Github Workflows recipes

    Update to version 1.14.6:

      - Security fixes:
        - Don't allow an executable name to be misinterpreted as a
          command-line option for bwrap(1). This prevents a sandbox
          escape where a malicious or compromised app could ask
          xdg-desktop-portal to generate a .desktop file with access
          to files outside the sandbox. (CVE-2024-32462, bsc#1223110)
      - Other bug fixes:
        - Don't parse <developer><name/></developer> as the application
          name (#5700)

    bubblewrap changes:

    Update to 0.11.0:

     * New --overlay, --tmp-overlay, --ro-overlay and --overlay-src
       options allow creation of overlay mounts. This feature is not
       available when bubblewrap is installed setuid.
     * New --level-prefix option produces output that can be parsed
       by tools like logger --prio-prefix and
       systemd-cat --level-prefix=1
     * bug fixes and developer visible changes

    Update to version v0.10.0:

     * New features: Add the --[ro-]bind-fd option, which can be used
       to mount a filesystem represented by a file descriptor without
       time-of-check/time-of-use attacks. This is needed when
       resolving security issue in Flatpak.
       (CVE-2024-42472, bsc#1229157)

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188902");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212476");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1216320");
  script_set_attribute(attribute:"see_also", value:"https://lists.suse.com/pipermail/sle-updates/2025-January/038111.html");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-32462");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42472");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-32462");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-42472");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:bubblewrap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:bubblewrap-zsh-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:flatpak");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:flatpak-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:flatpak-remote-flathub");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:flatpak-zsh-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libflatpak0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:system-user-flatpak");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:typelib-1_0-Flatpak-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:wayland-protocols-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
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
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES|SUSE)") audit(AUDIT_OS_NOT, "SUSE / openSUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)(?:_SAP)?\d+|SUSE([\d.]+))", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE / openSUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED15|SLED_SAP15|SLES15|SLES_SAP15|SUSE15\.6)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED15 / SLED_SAP15 / SLES15 / SLES_SAP15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLED15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED15 SP6", os_ver + " SP" + service_pack);
if (os_ver == "SLED_SAP15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED_SAP15 SP6", os_ver + " SP" + service_pack);
if (os_ver == "SLES15" && (! preg(pattern:"^(5|6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP5/6", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(5|6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP5/6", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'bubblewrap-0.11.0-150500.3.9.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'bubblewrap-zsh-completion-0.11.0-150500.3.9.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'flatpak-1.16.0-150500.3.15.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'flatpak-devel-1.16.0-150500.3.15.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'flatpak-remote-flathub-1.16.0-150500.3.15.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'flatpak-zsh-completion-1.16.0-150500.3.15.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'libflatpak0-1.16.0-150500.3.15.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'system-user-flatpak-1.16.0-150500.3.15.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'typelib-1_0-Flatpak-1_0-1.16.0-150500.3.15.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'wayland-protocols-devel-1.36-150500.3.3.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'bubblewrap-0.11.0-150500.3.9.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'bubblewrap-0.11.0-150500.3.9.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'bubblewrap-zsh-completion-0.11.0-150500.3.9.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'bubblewrap-zsh-completion-0.11.0-150500.3.9.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'flatpak-1.16.0-150600.3.6.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'flatpak-1.16.0-150600.3.6.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'flatpak-devel-1.16.0-150600.3.6.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'flatpak-devel-1.16.0-150600.3.6.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'flatpak-remote-flathub-1.16.0-150600.3.6.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'flatpak-remote-flathub-1.16.0-150600.3.6.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'flatpak-zsh-completion-1.16.0-150600.3.6.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'flatpak-zsh-completion-1.16.0-150600.3.6.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libflatpak0-1.16.0-150600.3.6.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libflatpak0-1.16.0-150600.3.6.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'system-user-flatpak-1.16.0-150600.3.6.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'system-user-flatpak-1.16.0-150600.3.6.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'typelib-1_0-Flatpak-1_0-1.16.0-150600.3.6.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'typelib-1_0-Flatpak-1_0-1.16.0-150600.3.6.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'bubblewrap-0.11.0-150500.3.9.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'bubblewrap-0.11.0-150500.3.9.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'bubblewrap-zsh-completion-0.11.0-150500.3.9.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'bubblewrap-zsh-completion-0.11.0-150500.3.9.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'flatpak-1.16.0-150500.3.15.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'flatpak-1.16.0-150500.3.15.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'flatpak-devel-1.16.0-150500.3.15.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'flatpak-devel-1.16.0-150500.3.15.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'flatpak-remote-flathub-1.16.0-150500.3.15.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'flatpak-zsh-completion-1.16.0-150500.3.15.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'libflatpak0-1.16.0-150500.3.15.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'libflatpak0-1.16.0-150500.3.15.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'system-user-flatpak-1.16.0-150500.3.15.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'typelib-1_0-Flatpak-1_0-1.16.0-150500.3.15.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'typelib-1_0-Flatpak-1_0-1.16.0-150500.3.15.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'wayland-protocols-devel-1.36-150500.3.3.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'bubblewrap-0.11.0-150500.3.9.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5']},
    {'reference':'bubblewrap-0.11.0-150500.3.9.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5']},
    {'reference':'bubblewrap-zsh-completion-0.11.0-150500.3.9.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5']},
    {'reference':'bubblewrap-zsh-completion-0.11.0-150500.3.9.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5']},
    {'reference':'flatpak-1.16.0-150500.3.15.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5']},
    {'reference':'flatpak-1.16.0-150500.3.15.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5']},
    {'reference':'flatpak-devel-1.16.0-150500.3.15.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5']},
    {'reference':'flatpak-devel-1.16.0-150500.3.15.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5']},
    {'reference':'flatpak-remote-flathub-1.16.0-150500.3.15.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5', 'sles-ltss-release-15.5']},
    {'reference':'flatpak-zsh-completion-1.16.0-150500.3.15.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5', 'sles-ltss-release-15.5']},
    {'reference':'libflatpak0-1.16.0-150500.3.15.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5']},
    {'reference':'libflatpak0-1.16.0-150500.3.15.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5']},
    {'reference':'system-user-flatpak-1.16.0-150500.3.15.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5', 'sles-ltss-release-15.5']},
    {'reference':'typelib-1_0-Flatpak-1_0-1.16.0-150500.3.15.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5']},
    {'reference':'typelib-1_0-Flatpak-1_0-1.16.0-150500.3.15.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5']},
    {'reference':'wayland-protocols-devel-1.36-150500.3.3.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5', 'sles-ltss-release-15.5']},
    {'reference':'bubblewrap-0.11.0-150500.3.9.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'bubblewrap-0.11.0-150500.3.9.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'bubblewrap-zsh-completion-0.11.0-150500.3.9.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'bubblewrap-zsh-completion-0.11.0-150500.3.9.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'flatpak-1.16.0-150600.3.6.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-desktop-applications-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'flatpak-1.16.0-150600.3.6.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-desktop-applications-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'flatpak-devel-1.16.0-150600.3.6.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-desktop-applications-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'flatpak-devel-1.16.0-150600.3.6.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-desktop-applications-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'flatpak-remote-flathub-1.16.0-150600.3.6.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-desktop-applications-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'flatpak-remote-flathub-1.16.0-150600.3.6.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-desktop-applications-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'flatpak-zsh-completion-1.16.0-150600.3.6.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-desktop-applications-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'flatpak-zsh-completion-1.16.0-150600.3.6.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-desktop-applications-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libflatpak0-1.16.0-150600.3.6.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-desktop-applications-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libflatpak0-1.16.0-150600.3.6.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-desktop-applications-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'system-user-flatpak-1.16.0-150600.3.6.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-desktop-applications-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'system-user-flatpak-1.16.0-150600.3.6.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-desktop-applications-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'typelib-1_0-Flatpak-1_0-1.16.0-150600.3.6.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-desktop-applications-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'typelib-1_0-Flatpak-1_0-1.16.0-150600.3.6.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-desktop-applications-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'bubblewrap-0.11.0-150500.3.9.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'bubblewrap-zsh-completion-0.11.0-150500.3.9.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'flatpak-1.16.0-150600.3.6.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'flatpak-devel-1.16.0-150600.3.6.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'flatpak-remote-flathub-1.16.0-150600.3.6.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'flatpak-zsh-completion-1.16.0-150600.3.6.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'libflatpak0-1.16.0-150600.3.6.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'system-user-flatpak-1.16.0-150600.3.6.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'typelib-1_0-Flatpak-1_0-1.16.0-150600.3.6.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'bubblewrap-0.11.0-150500.3.9.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.5']},
    {'reference':'bubblewrap-zsh-completion-0.11.0-150500.3.9.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.5']},
    {'reference':'flatpak-1.16.0-150500.3.15.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.5']},
    {'reference':'flatpak-devel-1.16.0-150500.3.15.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.5']},
    {'reference':'libflatpak0-1.16.0-150500.3.15.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.5']},
    {'reference':'typelib-1_0-Flatpak-1_0-1.16.0-150500.3.15.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.5']}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (exists_check) {
      var check_flag = 0;
      foreach var check (exists_check) {
        if (!rpm_exists(release:_release, rpm:check)) continue;
        if ('ltss' >< tolower(check)) ltss_caveat_required = TRUE;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  var ltss_plugin_caveat = NULL;
  if(ltss_caveat_required) ltss_plugin_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in SUSE Enterprise Linux Server LTSS\n' +
    'repositories. Access to these package security updates require\n' +
    'a paid SUSE LTSS subscription.\n';
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + ltss_plugin_caveat
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bubblewrap / bubblewrap-zsh-completion / flatpak / flatpak-devel / etc');
}
