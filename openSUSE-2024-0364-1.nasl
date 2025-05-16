#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2024:0364-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(210739);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/24");

  script_cve_id(
    "CVE-2024-21248",
    "CVE-2024-21259",
    "CVE-2024-21263",
    "CVE-2024-21273"
  );
  script_xref(name:"IAVA", value:"2024-A-0661-S");

  script_name(english:"openSUSE 15 Security Update : virtualbox (openSUSE-SU-2024:0364-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote openSUSE 15 host has packages installed that are affected by multiple vulnerabilities as referenced in the
openSUSE-SU-2024:0364-1 advisory.

    Update to release 7.1.4:

    * NAT: Fixed DHCP problems with certain guests when domain is
      empty
    * VMSVGA: Improved flickering, black screen and other screen
      update issues with recent Linux kernels
    * Linux Guest Additions: Introduce initial support for kernel 6.12
    * EFI: Added missing LsiLogic MPT SCSI driver again to fix
      booting from devices attached to this device if the EFI
      firmware is used (7.1.0 regression)
    * EFI: Restored broken network boot support (7.1.0 regression)
    * Adressed CVE-2024-21248 [boo#1231735],
      CVE-2024-21273 [boo#1231736], CVE-2024-21259 [boo#1231737],
      CVE-2024-21263 [boo#1231738]

    - Make the Extension Pack work with our compiler flags and RT_NOEXCEPT choices. [boo#1231225]

    Update to release 7.1:

    * The GUI now offers a selection between Basic and Experienced
      user level with reduced or full UI functionality.
    * VRDE: If user does not set up TLS with custom certificates,
      enable it with self-signed certificate, including issuing a
      new one before the old one expires
    * NAT: New engine with IPv6 support.
    * Linux host and guest: Added Wayland support for Clipboard
      sharing.

    - Changed license from Gpl-2.0 to Gpl-3.0

    Version bump to VirtualBox 7.0.20 (released July 16 2024 by Oracle))

    This is a maintenance release. The following items were fixed and/or added:

    - TPM: Fixed errors appearing the event viewer with Windows guests
    - macOS Hosts: Fixed passing USB devices to the VM (bug #21218)
    - Audio: Fixed recording with HDA emulation after newer Windows 10 / 11 guests got rebooted
    - USB: Fixed a deadlock in OHCI triggered when saving the current state of a VM or taking a snapshot (bug
    #22059)
    - Linux Guest and Host: Introduced initial support for OpenSuse 15.6 kernel
    - Linux Guest and Host: Introduced initial support for RHEL 9.5 kernel (bug #22099)
    - Guest Additions: Shared Clipboard: Fixed issue when extra new lines were pasted when copying text
    between Win and X11 (bug #21716)
    - UEFI Secure Boot: Add new Microsoft certificates to list for new VMs

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231225");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231735");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231736");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231737");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231738");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/ELCE6LNULD7SDN6FX3HW5773W3KTCWXS/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d4f06258");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-21248");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-21259");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-21263");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-21273");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-21259");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kbuild");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-virtualbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-desktop-icons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-vnc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-websrv");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'kbuild-0.1.9998+svn3613-bp156.2.3.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kbuild-0.1.9998+svn3613-bp156.2.3.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-virtualbox-7.1.4-lp156.2.4.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'virtualbox-7.1.4-lp156.2.4.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'virtualbox-devel-7.1.4-lp156.2.4.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'virtualbox-guest-desktop-icons-7.1.4-lp156.2.4.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'virtualbox-guest-source-7.1.4-lp156.2.4.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'virtualbox-guest-tools-7.1.4-lp156.2.4.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'virtualbox-host-source-7.1.4-lp156.2.4.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'virtualbox-kmp-default-7.1.4_k6.4.0_150600.23.25-lp156.2.4.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'virtualbox-qt-7.1.4-lp156.2.4.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'virtualbox-vnc-7.1.4-lp156.2.4.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'virtualbox-websrv-7.1.4-lp156.2.4.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kbuild / python3-virtualbox / virtualbox / virtualbox-devel / etc');
}
