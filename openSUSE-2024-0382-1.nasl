#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2024:0382-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(212494);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/11");

  script_cve_id("CVE-2024-47533");

  script_name(english:"openSUSE 15 Security Update : cobbler (openSUSE-SU-2024:0382-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote openSUSE 15 host has packages installed that are affected by a vulnerability as referenced in the openSUSE-
SU-2024:0382-1 advisory.

    Update to 3.3.7:

      * Security: Fix issue that allowed anyone to connect to the API
        as admin (CVE-2024-47533, boo#1231332)

      * bind - Fix bug that prevents cname entries from being
        generated successfully
      * Fix build on RHEL9 based distributions (fence-agents-all split)
      * Fix for Windows systems
      * Docs: Add missing dependencies for source installation
      * Fix issue that prevented systems from being synced when the
        profile was edited

    Update to 3.3.6:

      * Upstream all openSUSE specific patches that were maintained in Git
      * Fix rename of items that had uppercase letters
      * Skip inconsistent collections instead of crashing the daemon

    - Update to 3.3.5:
      * Added collection indicies for UUID's, MAC's, IP addresses and hostnames
        boo#1219933
      * Re-added to_dict() caching
      * Added lazy loading for the daemon (off by default)

    - Update to 3.3.4:

      * Added cobbler-tests-containers subpackage
      * Updated the distro_signatures.json database
      * The default name for grub2-efi changed to grubx64.efi to match
        the DHCP template

    - Do generate boot menus even if no profiles or systems - only local boot
    - Avoid crashing running buildiso in certain conditions.
    - Fix settings migration schema to work while upgrading on existing running
      Uyuni and SUSE Manager servers running with old Cobbler settings (boo#1203478)
    - Consider case of 'next_server' being a hostname during migration
      of Cobbler collections.
    - Fix problem with 'proxy_url_ext' setting being None type.
    - Update v2 to v3 migration script to allow migration of collections
      that contains settings from Cobbler 2. (boo#1203478)
    - Fix problem for the migration of 'autoinstall' collection attribute.
    - Fix failing Cobbler tests after upgrading to 3.3.3.
    - Fix regression: allow empty string as interface_type value (boo#1203478)
    - Avoid possible override of existing values during migration
      of collections to 3.0.0 (boo#1206160)
    - Add missing code for previous patch file around boot_loaders migration.
    - Improve Cobbler performance with item cache and threadpool (boo#1205489)
    - Skip collections that are inconsistent instead of crashing (boo#1205749)
    - Items: Fix creation of 'default' NetworkInterface (boo#1206520)
    - S390X systems require their kernel options to have a linebreak at
      79 characters (boo#1207595)
    - settings-migration-v1-to-v2.sh will now handle paths with whitespace
      correct
    - Fix renaming Cobbler items (boo#1204900, boo#1209149)
    - Fix cobbler buildiso so that the artifact can be booted by EFI firmware.
      (boo#1206060)
    - Add input_string_*, input_boolean, input_int functiont to public API

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203478");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204900");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205489");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205749");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206060");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206160");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206520");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207595");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209149");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219933");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231332");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/CGWWFM26ZMG5SCPMDNQQNYHHTROXVX2Q/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eb3be425");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47533");
  script_set_attribute(attribute:"solution", value:
"Update the affected cobbler, cobbler-tests and / or cobbler-tests-containers packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-47533");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cobbler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cobbler-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cobbler-tests-containers");
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
    {'reference':'cobbler-3.3.7-bp155.2.3.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cobbler-tests-3.3.7-bp155.2.3.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cobbler-tests-containers-3.3.7-bp155.2.3.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cobbler / cobbler-tests / cobbler-tests-containers');
}
