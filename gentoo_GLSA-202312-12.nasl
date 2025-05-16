#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202312-12.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(187282);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/23");

  script_cve_id(
    "CVE-2021-21381",
    "CVE-2021-41133",
    "CVE-2021-43860",
    "CVE-2022-21682",
    "CVE-2023-28100",
    "CVE-2023-28101"
  );

  script_name(english:"GLSA-202312-12 : Flatpak: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202312-12 (Flatpak: Multiple Vulnerabilities)

  - Flatpak is a system for building, distributing, and running sandboxed desktop applications on Linux. In
    Flatpack since version 0.9.4 and before version 1.10.2 has a vulnerability in the file forwarding
    feature which can be used by an attacker to gain access to files that would not ordinarily be allowed by
    the app's permissions. By putting the special tokens `@@` and/or `@@u` in the Exec field of a Flatpak
    app's .desktop file, a malicious app publisher can trick flatpak into behaving as though the user had
    chosen to open a target file with their Flatpak app, which automatically makes that file available to the
    Flatpak app. This is fixed in version 1.10.2. A minimal solution is the first commit `Disallow @@ and @@U
    usage in desktop files`. The follow-up commits `dir: Reserve the whole @@ prefix` and `dir: Refuse to
    export .desktop files with suspicious uses of @@ tokens` are recommended, but not strictly required. As a
    workaround, avoid installing Flatpak apps from untrusted sources, or check the contents of the exported
    `.desktop` files in `exports/share/applications/*.desktop` (typically
    `~/.local/share/flatpak/exports/share/applications/*.desktop` and
    `/var/lib/flatpak/exports/share/applications/*.desktop`) to make sure that literal filenames do not follow
    `@@` or `@@u`. (CVE-2021-21381)

  - Flatpak is a system for building, distributing, and running sandboxed desktop applications on Linux. In
    versions prior to 1.10.4 and 1.12.0, Flatpak apps with direct access to AF_UNIX sockets such as those used
    by Wayland, Pipewire or pipewire-pulse can trick portals and other host-OS services into treating the
    Flatpak app as though it was an ordinary, non-sandboxed host-OS process. They can do this by manipulating
    the VFS using recent mount-related syscalls that are not blocked by Flatpak's denylist seccomp filter, in
    order to substitute a crafted `/.flatpak-info` or make that file disappear entirely. Flatpak apps that act
    as clients for AF_UNIX sockets such as those used by Wayland, Pipewire or pipewire-pulse can escalate the
    privileges that the corresponding services will believe the Flatpak app has. Note that protocols that
    operate entirely over the D-Bus session bus (user bus), system bus or accessibility bus are not affected
    by this. This is due to the use of a proxy process `xdg-dbus-proxy`, whose VFS cannot be manipulated by
    the Flatpak app, when interacting with these buses. Patches exist for versions 1.10.4 and 1.12.0, and as
    of time of publication, a patch for version 1.8.2 is being planned. There are no workarounds aside from
    upgrading to a patched version. (CVE-2021-41133)

  - Flatpak is a Linux application sandboxing and distribution framework. Prior to versions 1.12.3 and 1.10.6,
    Flatpak doesn't properly validate that the permissions displayed to the user for an app at install time
    match the actual permissions granted to the app at runtime, in the case that there's a null byte in the
    metadata file of an app. Therefore apps can grant themselves permissions without the consent of the user.
    Flatpak shows permissions to the user during install by reading them from the xa.metadata key in the
    commit metadata. This cannot contain a null terminator, because it is an untrusted GVariant. Flatpak
    compares these permissions to the *actual* metadata, from the metadata file to ensure it wasn't lied to.
    However, the actual metadata contents are loaded in several places where they are read as simple C-style
    strings. That means that, if the metadata file includes a null terminator, only the content of the file
    from *before* the terminator gets compared to xa.metadata. Thus, any permissions that appear in the
    metadata file after a null terminator are applied at runtime but not shown to the user. So maliciously
    crafted apps can give themselves hidden permissions. Users who have Flatpaks installed from untrusted
    sources are at risk in case the Flatpak has a maliciously crafted metadata file, either initially or in an
    update. This issue is patched in versions 1.12.3 and 1.10.6. As a workaround, users can manually check the
    permissions of installed apps by checking the metadata file or the xa.metadata key on the commit metadata.
    (CVE-2021-43860)

  - Flatpak is a Linux application sandboxing and distribution framework. A path traversal vulnerability
    affects versions of Flatpak prior to 1.12.3 and 1.10.6. flatpak-builder applies `finish-args` last in the
    build. At this point the build directory will have the full access that is specified in the manifest, so
    running `flatpak build` against it will gain those permissions. Normally this will not be done, so this is
    not problem. However, if `--mirror-screenshots-url` is specified, then flatpak-builder will launch
    `flatpak build --nofilesystem=host appstream-utils mirror-screenshots` after finalization, which can lead
    to issues even with the `--nofilesystem=host` protection. In normal use, the only issue is that these
    empty directories can be created wherever the user has write permissions. However, a malicious application
    could replace the `appstream-util` binary and potentially do something more hostile. This has been
    resolved in Flatpak 1.12.3 and 1.10.6 by changing the behaviour of `--nofilesystem=home` and
    `--nofilesystem=host`. (CVE-2022-21682)

  - Flatpak is a system for building, distributing, and running sandboxed desktop applications on Linux.
    Versions prior to 1.10.8, 1.12.8, 1.14.4, and 1.15.4 contain a vulnerability similar to CVE-2017-5226, but
    using the `TIOCLINUX` ioctl command instead of `TIOCSTI`. If a Flatpak app is run on a Linux virtual
    console such as `/dev/tty1`, it can copy text from the virtual console and paste it into the command
    buffer, from which the command might be run after the Flatpak app has exited. Ordinary graphical terminal
    emulators like xterm, gnome-terminal and Konsole are unaffected. This vulnerability is specific to the
    Linux virtual consoles `/dev/tty1`, `/dev/tty2` and so on. A patch is available in versions 1.10.8,
    1.12.8, 1.14.4, and 1.15.4. As a workaround, don't run Flatpak on a Linux virtual console. Flatpak is
    primarily designed to be used in a Wayland or X11 graphical environment. (CVE-2023-28100)

  - Flatpak is a system for building, distributing, and running sandboxed desktop applications on Linux. In
    versions prior to 1.10.8, 1.12.8, 1.14.4, and 1.15.4, if an attacker publishes a Flatpak app with elevated
    permissions, they can hide those permissions from users of the `flatpak(1)` command-line interface by
    setting other permissions to crafted values that contain non-printable control characters such as `ESC`. A
    fix is available in versions 1.10.8, 1.12.8, 1.14.4, and 1.15.4. As a workaround, use a GUI like GNOME
    Software rather than the command-line interface, or only install apps whose maintainers you trust.
    (CVE-2023-28101)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202312-12");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=775365");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=816951");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=831087");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=901507");
  script_set_attribute(attribute:"solution", value:
"All Flatpak users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=sys-apps/flatpak-1.14.4");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-43860");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:flatpak");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gentoo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list");

  exit(0);
}
include('qpkg.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/Gentoo/release')) audit(AUDIT_OS_NOT, 'Gentoo');
if (!get_kb_item('Host/Gentoo/qpkg-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var flag = 0;

var packages = [
  {
    'name' : 'sys-apps/flatpak',
    'unaffected' : make_list("ge 1.14.4"),
    'vulnerable' : make_list("lt 1.14.4")
  }
];

foreach var package( packages ) {
  if (isnull(package['unaffected'])) package['unaffected'] = make_list();
  if (isnull(package['vulnerable'])) package['vulnerable'] = make_list();
  if (qpkg_check(package: package['name'] , unaffected: package['unaffected'], vulnerable: package['vulnerable'])) flag++;
}


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : qpkg_report_get()
  );
  exit(0);
}
else
{
  qpkg_tests = list_uniq(qpkg_tests);
  var tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Flatpak');
}
