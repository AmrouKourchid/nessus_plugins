#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2012:0152 and 
# Oracle Linux Security Advisory ELSA-2012-0152 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(68470);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/29");

  script_cve_id("CVE-2011-3588", "CVE-2011-3589", "CVE-2011-3590");
  script_bugtraq_id(50415, 50416, 50420);
  script_xref(name:"RHSA", value:"2012:0152");

  script_name(english:"Oracle Linux 5 : kexec-tools (ELSA-2012-0152)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 5 host has a package installed that is affected by multiple vulnerabilities as referenced in the
ELSA-2012-0152 advisory.

    [1.102pre-154.0.3]
    - mkdumprd.orig get packed, remove it.

    [1.102pre-154.0.2]
    - fix mounting root fs on labeled disk (Maxim Uvarov) [orabug: 13709374]

    [1.102pre-154.0.1]
    Merge following patches from mkinitrd:
    - mkinitrd-fix-san-boot.patch
    - mkinitrd-fix-shared-lib-library-path.patch
    - mkinitrd-5.1.19.6-libfirmware-subdir-include.patch
    - mkinitrd-fix-setquiet-for-non-verbose.patch
    - add-option-to-forceload-multipath.patch
    - Update kexec-kdump-howto.txt with Oracle references
    - Add mkdumprd load firmware support [orabug 10432768]
    - Updated makedumpfile to el6 version (Herbert van den Bergh) [orabug 10088607]
    - Merged UEK modification,Updated Source1 kdump.init
      Added --allow-missing for rebuilding kdump_initrd
    - Updated kexec-kdump-howto.txt with Oracle references

    [1.102pre-154]
    - Add xfs support, resolve bug 668706.

    [1.102pre-153]
    - Avoid recursive directory deletion when unmount failed, from Cai Qian.
      Resolve bug 781907.

    [1.102pre-152]
    - Replace sed with awk in interface-mapping code,
      resolve bug 765702.

    [1.102pre-151]
    - Set pipefail to catch errors in a pipe, resolve bug 761336.

    [1.102pre-150]
    - Remove the restriction for Xen HVM guests, resolve bug 743217.

    [1.102pre-149]
    - Honor the resettable flag, resolve bug 761048.

    [1.102pre-148]
    - Revert the patch in -144, resolve bug 755781. From Cai Qian.

    [1.102pre-147]
    - Poll every ifcfg file to get bridge members, resolve bug 760844.

    [1.102pre-146]
    - Don't add default gateway when there is none. Resolve bug 759006.

    [1.102pre-145]
    - Bypass blacklist option for target checking. Resolve bug 690678.

    [1.102pre-144]
    - Change the default core_collector for raw dump to makedumpfile.
      Resolve bug 755781.

    [1.102pre-143]
    - Support static route. Resolve bug 715531.

    [1.102pre-142]
    - Fix some security flaws. Resolve bug 743163.

    [1.102pre-141]
    - Remove two unused patches.

    [1.102pre-140]
    - Fix link_delay regression since -135, resolve bug 753684.

    [1.102pre-139]
    - Improve debugfs mounting code, from Dave Young. Resolve bug 748749.

    [1.102pre-138]
    - Backport blacklist option. Resolve bug 690678.

    [1.102pre-137]
    - Fix link_delay handling code. Resolve bug 682359.

    [1.102pre-136]
    - Add /etc/fstab into initrd, resolve Bug 748319.

    [1.102pre-135]
    - Support dump over vlan tagged bond. Resolve bug 682359.

    [1.102pre-134]
    - Fix two trivial bugs, Bug 709622 and Bug 662530.

    [1.102pre-133]
    - Support software iscsi as dump target, from Vivek Goyal.
      Resolve bug 719384.

    [1.102pre-132]
    - Add the missing part of the previous patch. Resolve bug 696547.

    [1.102pre-131]
    - Get the backup memory region dynamically. Resolve bug 678308.

    [1.102pre-130]
    - Add ext4 module. Resolve bug 667791.

    [1.102pre-129]
    - Updating release to force brew rebuild

    [1.102pre-128]
    - Check fsck.ext4 binary before include it. Resolve bug 667791.

    [1.102pre-127]
    - Add ext4 support, from Dave Maley. Resolve bug 667791.

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2012-0152.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected kexec-tools package.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2011-3590");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kexec-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 5', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var pkgs = [
    {'reference':'kexec-tools-1.102pre-154.0.3.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kexec-tools-1.102pre-154.0.3.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kexec-tools');
}
