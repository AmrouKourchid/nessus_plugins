#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2024:0790.
##

include('compat.inc');

if (description)
{
  script_id(190514);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/14");

  script_cve_id("CVE-2023-6135");
  script_xref(name:"ALSA", value:"2024:0790");

  script_name(english:"AlmaLinux 9 : nss (ALSA-2024:0790)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 9 host has packages installed that are affected by a vulnerability as referenced in the
ALSA-2024:0790 advisory.

  - Multiple NSS NIST curves were susceptible to a side-channel attack known as Minerva. This attack could
    potentially allow an attacker to recover the private key. This vulnerability affects Firefox < 121.
    (CVE-2023-6135)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/9/ALSA-2024-0790.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-6135");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(200);

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/12/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nspr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nss-softokn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nss-softokn-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nss-softokn-freebl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nss-softokn-freebl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nss-sysinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nss-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nss-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nss-util-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::appstream");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::baseos");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::crb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::highavailability");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::nfv");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::realtime");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::resilientstorage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::sap");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::sap_hana");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::supplementary");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Alma Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AlmaLinux/release", "Host/AlmaLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/AlmaLinux/release');
if (isnull(os_release) || 'AlmaLinux' >!< os_release) audit(AUDIT_OS_NOT, 'AlmaLinux');
var os_ver = pregmatch(pattern: "AlmaLinux release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'AlmaLinux');
os_ver = os_ver[1];
if (! preg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'AlmaLinux 9.x', 'AlmaLinux ' + os_ver);

if (!get_kb_item('Host/AlmaLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'AlmaLinux', cpu);

var pkgs = [
    {'reference':'nspr-4.35.0-6.el9_3', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nspr-devel-4.35.0-6.el9_3', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-3.90.0-6.el9_3', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-devel-3.90.0-6.el9_3', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-softokn-3.90.0-6.el9_3', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-softokn-devel-3.90.0-6.el9_3', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-softokn-freebl-3.90.0-6.el9_3', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-softokn-freebl-devel-3.90.0-6.el9_3', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-sysinit-3.90.0-6.el9_3', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-tools-3.90.0-6.el9_3', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-util-3.90.0-6.el9_3', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-util-devel-3.90.0-6.el9_3', 'release':'9', 'rpm_spec_vers_cmp':TRUE}
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
  if (!empty_or_null(package_array['release'])) _release = 'Alma-' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'nspr / nspr-devel / nss / nss-devel / nss-softokn / etc');
}
