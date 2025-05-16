#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2024-49ddbf447d
#

include('compat.inc');

if (description)
{
  script_id(190823);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/15");

  script_cve_id("CVE-2024-23301");
  script_xref(name:"FEDORA", value:"2024-49ddbf447d");

  script_name(english:"Fedora 38 : rear (2024-49ddbf447d)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 38 host has a package installed that is affected by multiple vulnerabilities as referenced in the
FEDORA-2024-49ddbf447d advisory.

    * Fri Feb  9 2024 Luk Zaoral <lzaoral@redhat.com> - 2.7-8
    - Sync with patches in CentOS Stream 9 (kudos to @pcahyna!) chronologically
      from the latest:
      - Resolve libs for executable links in COPY_AS_IS, PR 3073
      - Skip invalid disk drives when saving layout PR 3047
      - Do not delete NetBackup logs in case of errors and save
        /usr/openv/netbackup/logs to the restored system after a successful recovery
      - Add /usr/openv/var to COPY_AS_IS_NBU, fixes an issue seen
        with NetBackup 10.2.0.1
      - Support saving and restoring hybrid BIOS/UEFI bootloader, PRs 3145 3136
    * Thu Feb  8 2024 Luk Zaoral <lzaoral@redhat.com> - 2.7-7
    - do not generate /etc/rear/os.conf during build
    * Wed Feb  7 2024 Luk Zaoral <lzaoral@redhat.com> - 2.7-6
    - copy the console= kernel arguments from the original system
    * Tue Feb  6 2024 Luk Zaoral <lzaoral@redhat.com> - 2.7-5
    - replace dhcp-client with dhcpcd (rhbz#2247060)
    * Tue Feb  6 2024 Luk Zaoral <lzaoral@redhat.com> - 2.7-4
    - make initrd accessible only by root (CVE-2024-23301)
    * Tue Feb  6 2024 Luk Zaoral <lzaoral@redhat.com> - 2.7-3
    - fix unusable recovery with newer systemd (rbhz#2254871)
    * Mon Feb  5 2024 Luk Zaoral <lzaoral@redhat.com> - 2.7-2
    - migrate to SPDX license format
    - properly use %license and %doc macros
    - use https in URLs
    * Fri Feb  2 2024 Luk Zaoral <lzaoral@redhat.com> - 2.7-1
    - rebase to version 2.7 (rhbz#2215778)
    - drop obsolete patches
    - rebase remaining patches
    * Fri Feb  2 2024 Luk Zaoral <lzaoral@redhat.com> - 2.6-14
    - Sync with patches in CentOS Stream 9 (kudos to @pcahyna!) chronologically
      from the latest:
      - Backport PR 3061 to save LVM pool metadata volume size in disk layout
        and restore it
      - Backport PR 3058 to skip useless xfs mount options when mounting
        during recovery, prevents mount errors like logbuf size must be greater
        than or equal to log stripe size
      - Add patch to force removal of lvmdevices, prevents LVM problems after
        restoring to different disks/cloning. Upstream PR 3043
      - Add patch to start rsyslog and include NBU systemd units
      - Apply PR 3027 to ensure correct creation of the rescue environment
        when a file is shrinking while being read
      - Backport PR 2774 to increase USB_UEFI_PART_SIZE to 1024 MiB
      - Apply upstream patch for temp dir usage with LUKS to ensure
        that during recovery an encrypted disk can be unlocked using a keyfile
      - Backport upstream PR 3031: Secure Boot support for OUTPUT=USB
      - Correct a mistake done when backporting PR 2691
      - Backport PR2943 to fix s390x dasd formatting
      - Require s390utils-{core,base} on s390x
      - Apply PR2903 to protect against colons in pvdisplay output
      - Apply PR2873 to fix initrd regeneration on s390x
      - Apply PR2431 to migrate XFS configuration files
      - Exclude /etc/lvm/devices from the rescue system to work around a segfault
        in lvm pvcreate
      - Avoid stderr message about irrelevant broken links
      - Changes for NetBackup (NBU) 9.x support
      - Backport PR2831 - rsync URL refactoring
        fixes rsync OUTPUT_URL when different from BACKUP_URL
      - Apply PR2795 to detect changes in system files between backup
        and rescue image
      - Apply PR2808 to exclude dev/watchdog* from recovery system
      - Backport upstream PRs 2827 and 2839 to pass -y to lvcreate instead of one y
        on stdin
      - Apply PR2811 to add the PRE/POST_RECOVERY_COMMANDS directives
      - Recommend dosfstools on x86_64, needed for EFI System Partition
      - Backport PR2825 to replace defunct mkinitrd with dracut
      - Apply PR2580 to load the nvram module in the rescue environment in order
        to be able to set the boot order on ppc64le LPARs
      - Backport PR2822 to include the true vi executable in rescue ramdisk
      - Apply PR2675 to fix leftover temp dir bug (introduced in backported PR2625)
      - Apply PR2603 to ignore unused PV devices
      - Apply upstream PR2750 to avoid exclusion of wanted multipath devices
      - Remove unneeded xorriso dep on s390x (no ISO image support there)
      - Apply upstream PR2736 to add the EXCLUDE_{IP_ADDRESSES,NETWORK_INTERFACES}
        options
      - Add patch for better handling of thin pools and other LV types not supported
        by vgcfgrestore
      - Sync spec changes and downstream patches from RHEL 8 rear-2.6-2
        - Fix multipath performance regression in 2.6, introduced by upstream PR #2299.
          Resolves: rhbz1993296
        - On POWER add bootlist & ofpathname to the list of required programs
          conditionally (bootlist only if running under PowerVM, ofpathname
          always except on PowerNV) - upstream PR2665, add them to package
          dependencies
          Resolves: rhbz1983013
        - Backport PR2608:
          Fix setting boot path in case of UEFI partition (ESP) on MD RAID
          Resolves: rhbz1945869
        - Backport PR2625
          Prevents accidental backup removal in case of errors
          Resolves: rhbz1958247
        - Fix rsync error and option handling
          Resolves: rhbz1930662
      - Put TMPDIR on /var/tmp by default, otherwise it may lack space
        RHBZ #1988420, upstream PR2664
      - Sync spec changes and downstream patches from RHEL 8
        - Require xorriso instead of genisoimage
        - Add S/390 support and forgotten dependency on the file utility
        - Backport upstream code related to LUKS2 support
        - Modify the cron command to avoid an e-mail with error message after
          ReaR is installed but not properly configured when the cron command
          is triggered for the first time
        - Changes for NetBackup (NBU) support, upstream PR2544
      - Add dependency on dhcp-client, RHBZ #1926451


Tenable has extracted the preceding description block directly from the Fedora security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-49ddbf447d");
  script_set_attribute(attribute:"solution", value:
"Update the affected rear package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-23301");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:38");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rear");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Fedora' >!< os_release) audit(AUDIT_OS_NOT, 'Fedora');
var os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Fedora');
os_ver = os_ver[1];
if (! preg(pattern:"^38([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 38', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

var pkgs = [
    {'reference':'rear-2.7-8.fc38', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && _release) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'rear');
}
