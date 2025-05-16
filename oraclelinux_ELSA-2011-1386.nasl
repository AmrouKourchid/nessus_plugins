#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2011:1386 and 
# Oracle Linux Security Advisory ELSA-2011-1386 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(68375);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/01");

  script_cve_id(
    "CVE-2009-4067",
    "CVE-2011-1160",
    "CVE-2011-1585",
    "CVE-2011-1833",
    "CVE-2011-2484",
    "CVE-2011-2496",
    "CVE-2011-2695",
    "CVE-2011-2699",
    "CVE-2011-2723",
    "CVE-2011-2942",
    "CVE-2011-3131",
    "CVE-2011-3188",
    "CVE-2011-3191",
    "CVE-2011-3209",
    "CVE-2011-3347"
  );
  script_bugtraq_id(
    46866,
    47321,
    47381,
    48383,
    48687,
    48697,
    48802,
    48929,
    49108,
    49146,
    49289,
    49295,
    50311,
    50312,
    50313
  );
  script_xref(name:"RHSA", value:"2011:1386");

  script_name(english:"Oracle Linux 5 : kernel (ELSA-2011-1386)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 5 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2011-1386 advisory.

    - Revert: [xen] passthrough: block VT-d MSI trap injection (Paolo Bonzini) [716301 716302] {CVE-2011-1898}
    - [net] bridge: fix use after free in __br_deliver (Amerigo Wang) [730949 703045] {CVE-2011-2942}
    - [misc] remove div_long_long_rem (Prarit Bhargava) [732879 732614] {CVE-2011-3209}
    - [net] be2net: fix crash receiving non-member VLAN packets (Ivan Vecera) [736430 730239] {CVE-2011-3347}
    - [net] be2net: Use NTWK_RX_FILTER command for promiscous mode (Ivan Vecera) [736430 730239]
    {CVE-2011-3347}
    - [net] be2net: non-member vlan pkts not received in promisc mode (Ivan Vecera) [736430 730239]
    {CVE-2011-3347}
    - [net] be2net: remove bogus unlikely on vlan check (Ivan Vecera) [736430 730239] {CVE-2011-3347}
    - [net] Compute protocol seq numbers and fragment IDs using MD5 (Jiri Pirko) [732662 732663]
    {CVE-2011-3188}
    - [crypto] Move md5_transform to lib/md5.c (Jiri Pirko) [732662 732663] {CVE-2011-3188}
    - [mm] avoid wrapping vm_pgoff in mremap and stack expansion (Jerome Marchand) [716543 716544]
    {CVE-2011-2496}
    - [fs] ecryptfs: Add mount option to check uid of mounting device (Eric Sandeen) [731173 731174]
    {CVE-2011-1833}
    - [net] ipv6: make fragment identifications less predictable (Jiri Pirko) [723430 723431] {CVE-2011-2699}
    - [net] ipv6: Remove unused skb argument of ipv6_select_ident (Jiri Pirko) [723430 723431] {CVE-2011-2699}
    - [misc] taskstats: don't allow duplicate entries in listener mode (Jerome Marchand) [715449 715450]
    {CVE-2011-2484}
    - [net] gro: Only reset frag0 when skb can be pulled (Herbert Xu) [726553 679682] {CVE-2011-2723}
    - [xen] passthrough: block VT-d MSI trap injection (Paolo Bonzini) [716301 716302] {CVE-2011-1898}
    - [xen] iommu: disable bus-mastering on hw that causes IOMMU fault (Laszlo Ersek) [730342 730343]
    {CVE-2011-3131}
    - [usb] auerswald: fix buffer overflow (Don Zickus) [722395 722396] {CVE-2009-4067}
    - [fs] cifs: fix possible memory corruption in CIFSFindNext (Jeff Layton) [732870 736654 732869 732471]
    {CVE-2011-3191}
    - [fs] cifs: revert special handling for matching krb5 sessions (Jeff Layton) [697395 697396]
    {CVE-2011-1585}
    - [fs] cifs: check for NULL session password (Jeff Layton) [697395 697396] {CVE-2011-1585}
    - [fs] cifs: fix NULL pointer dereference in cifs_find_smb_ses (Jeff Layton) [697395 697396]
    {CVE-2011-1585}
    - [fs] cifs: clean up cifs_find_smb_ses (Jeff Layton) [697395 697396] {CVE-2011-1585}
    - [char] tpm: Fix uninitialized usage of data buffer (Stanislaw Gruszka) [684672 684673] {CVE-2011-1160}
    - [fs] ext4: Fix max size and logical block counting of extent file (Lukas Czerner) [722562 722563]
    {CVE-2011-2695}

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2011-1386.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2011-3191");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2011-3188");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/06/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-PAE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-PAE-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ocfs2-2.6.18-274.7.1.0.1.el5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ocfs2-2.6.18-274.7.1.0.1.el5PAE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ocfs2-2.6.18-274.7.1.0.1.el5debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ocfs2-2.6.18-274.7.1.0.1.el5xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:oracleasm-2.6.18-274.7.1.0.1.el5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:oracleasm-2.6.18-274.7.1.0.1.el5PAE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:oracleasm-2.6.18-274.7.1.0.1.el5debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:oracleasm-2.6.18-274.7.1.0.1.el5xen");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include('ksplice.inc');
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

var machine_uptrack_level = get_one_kb_item('Host/uptrack-uname-r');
if (machine_uptrack_level)
{
  var trimmed_uptrack_level = ereg_replace(string:machine_uptrack_level, pattern:"\.(x86_64|i[3-6]86|aarch64)$", replace:'');
  var fixed_uptrack_levels = ['2.6.18-274.7.1.0.1.el5'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2011-1386');
    }
  }
  __rpm_report = 'Running KSplice level of ' + trimmed_uptrack_level + ' does not meet the minimum fixed level of ' + join(fixed_uptrack_levels, sep:' / ') + ' for this advisory.\n\n';
}

var kernel_major_minor = get_kb_item('Host/uname/major_minor');
if (empty_or_null(kernel_major_minor)) exit(1, 'Unable to determine kernel major-minor level.');
var expected_kernel_major_minor = '2.6';
if (kernel_major_minor != expected_kernel_major_minor)
  audit(AUDIT_OS_NOT, 'running kernel level ' + expected_kernel_major_minor + ', it is running kernel level ' + kernel_major_minor);

var pkgs = [
    {'reference':'kernel-PAE-2.6.18-274.7.1.0.1.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-PAE-2.6.18'},
    {'reference':'kernel-PAE-devel-2.6.18-274.7.1.0.1.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-PAE-devel-2.6.18'},
    {'reference':'kernel-headers-2.6.18-274.7.1.0.1.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-2.6.18'},
    {'reference':'kernel-xen-2.6.18-274.7.1.0.1.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-xen-2.6.18'},
    {'reference':'kernel-xen-devel-2.6.18-274.7.1.0.1.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-xen-devel-2.6.18'},
    {'reference':'ocfs2-2.6.18-274.7.1.0.1.el5-1.4.9-1.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocfs2-2.6.18-274.7.1.0.1.el5PAE-1.4.9-1.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocfs2-2.6.18-274.7.1.0.1.el5debug-1.4.9-1.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocfs2-2.6.18-274.7.1.0.1.el5xen-1.4.9-1.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oracleasm-2.6.18-274.7.1.0.1.el5-2.0.5-1.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oracleasm-2.6.18-274.7.1.0.1.el5PAE-2.0.5-1.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oracleasm-2.6.18-274.7.1.0.1.el5debug-2.0.5-1.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oracleasm-2.6.18-274.7.1.0.1.el5xen-2.0.5-1.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-2.6.18-274.7.1.0.1.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-2.6.18'},
    {'reference':'kernel-PAE-2.6.18-274.7.1.0.1.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-PAE-2.6.18'},
    {'reference':'kernel-PAE-devel-2.6.18-274.7.1.0.1.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-PAE-devel-2.6.18'},
    {'reference':'kernel-debug-2.6.18-274.7.1.0.1.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-2.6.18'},
    {'reference':'kernel-debug-devel-2.6.18-274.7.1.0.1.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-devel-2.6.18'},
    {'reference':'kernel-devel-2.6.18-274.7.1.0.1.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-devel-2.6.18'},
    {'reference':'kernel-headers-2.6.18-274.7.1.0.1.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-2.6.18'},
    {'reference':'kernel-xen-2.6.18-274.7.1.0.1.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-xen-2.6.18'},
    {'reference':'kernel-xen-devel-2.6.18-274.7.1.0.1.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-xen-devel-2.6.18'},
    {'reference':'ocfs2-2.6.18-274.7.1.0.1.el5-1.4.9-1.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocfs2-2.6.18-274.7.1.0.1.el5PAE-1.4.9-1.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocfs2-2.6.18-274.7.1.0.1.el5debug-1.4.9-1.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocfs2-2.6.18-274.7.1.0.1.el5xen-1.4.9-1.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oracleasm-2.6.18-274.7.1.0.1.el5-2.0.5-1.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oracleasm-2.6.18-274.7.1.0.1.el5PAE-2.0.5-1.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oracleasm-2.6.18-274.7.1.0.1.el5debug-2.0.5-1.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oracleasm-2.6.18-274.7.1.0.1.el5xen-2.0.5-1.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-2.6.18-274.7.1.0.1.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-2.6.18'},
    {'reference':'kernel-debug-2.6.18-274.7.1.0.1.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-2.6.18'},
    {'reference':'kernel-debug-devel-2.6.18-274.7.1.0.1.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-devel-2.6.18'},
    {'reference':'kernel-devel-2.6.18-274.7.1.0.1.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-devel-2.6.18'},
    {'reference':'kernel-headers-2.6.18-274.7.1.0.1.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-2.6.18'},
    {'reference':'kernel-xen-2.6.18-274.7.1.0.1.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-xen-2.6.18'},
    {'reference':'kernel-xen-devel-2.6.18-274.7.1.0.1.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-xen-devel-2.6.18'},
    {'reference':'ocfs2-2.6.18-274.7.1.0.1.el5-1.4.9-1.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocfs2-2.6.18-274.7.1.0.1.el5debug-1.4.9-1.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocfs2-2.6.18-274.7.1.0.1.el5xen-1.4.9-1.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oracleasm-2.6.18-274.7.1.0.1.el5-2.0.5-1.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oracleasm-2.6.18-274.7.1.0.1.el5debug-2.0.5-1.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oracleasm-2.6.18-274.7.1.0.1.el5xen-2.0.5-1.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel / kernel-PAE / kernel-PAE-devel / etc');
}
