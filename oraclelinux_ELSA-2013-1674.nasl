#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2013:1674 and 
# Oracle Linux Security Advisory ELSA-2013-1674 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(71111);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/01");

  script_cve_id("CVE-2012-4453");
  script_bugtraq_id(55713);
  script_xref(name:"RHSA", value:"2013:1674");

  script_name(english:"Oracle Linux 6 : dracut (ELSA-2013-1674)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 6 host has packages installed that are affected by a vulnerability as referenced in the
ELSA-2013-1674 advisory.

    [004-336.0.1]
    - do not strip modules with signatures. [orabug 17458249] (Jerry Snitselaar)
    - scsi_wait module removed in 3.8. Mute errors. [orabug 16977193] (Maxim Uvarov)
      find firmware in /lib/modules/firmware/2.6.32-400.1.1.el5uek first
      and /lib/modules/firmware second (<maxim.uvarov@oracle.com)
      Resolves: Orabug: 13351090
    - Fix btrfs discovery [orabug 13388545]

    [004-336]
    - install /etc/system-fips in the initramfs
    Resolves: rhbz#1012626

    [004-335]
    - fixed interface renaming
    Resolves: rhbz#1019104

    [004-334]
    - fcoe: add --link-retry=100 to fipvlan call
    Resolves: rhbz#1012316
    - ldd: redirect error to /dev/null
    - do not turn off biosdevname, if not given on kernel cmdline
    Resolves: rhbz#1011508
    - network: fixed ibft parsing
    Resolves: rhbz#1011508

    [004-330]
    - changed /etc/redhat-fips to /etc/system-fips
    Resolves: rhbz#1012626

    [004-329]
    - add /etc/redhat-fips
    Resolves: rhbz#1012626

    [004-328]
    - fixed crypt: add support for keyfiles in the initramfs
    Resolves: rhbz#886194

    [004-327]
    - fixed crypt: add support for keyfiles in the initramfs
    Resolves: rhbz#886194
    - fixed booting with iSCSI and without network config
    Resolves: rhbz#910605

    [004-322]
    - fixed crypt: add support for keyfiles in the initramfs
    Resolves: rhbz#886194
    - fixed FIPS module checking
    Resolves: rhbz#947729

    [004-316]
    - create the initramfs non-world readable
    - unset LD_LIBRARY_PATH and GREP_OPTIONS
    Resolves: rhbz#912299
    - add mkinitrd man page
    Resolves: rhbz#610462
    - add bonding
    Resolves: rhbz#851666
    - lvm: add '--yes' to lvchange
    Resolves: rhbz#720684
    - crypt: add support for keyfiles in the initramfs
    Resolves: rhbz#886194
    - start iscsi regardless of network, if requested
    Resolves: rhbz#813687
    - install multipath module only, when root is multipath in generic mode
    Resolves: rhbz#916144
    - fips: handle checksum checks for RHEV kernels
    Resolves: rhbz#947729
    - add xhci-hcd driver
    Resolves: rhbz#960729

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2013-1674.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-4453");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dracut");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dracut-caps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dracut-fips");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dracut-fips-aesni");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dracut-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dracut-kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dracut-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dracut-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 6', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);
if ('x86_64' >!< cpu) audit(AUDIT_ARCH_NOT, 'x86_64', cpu);

var pkgs = [
    {'reference':'dracut-004-336.0.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dracut-caps-004-336.0.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dracut-fips-004-336.0.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dracut-fips-aesni-004-336.0.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dracut-generic-004-336.0.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dracut-kernel-004-336.0.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dracut-network-004-336.0.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dracut-tools-004-336.0.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'dracut / dracut-caps / dracut-fips / etc');
}
