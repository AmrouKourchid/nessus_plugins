#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2023:2987.
##

include('compat.inc');

if (description)
{
  script_id(176188);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/27");

  script_cve_id("CVE-2022-1615");
  script_xref(name:"ALSA", value:"2023:2987");

  script_name(english:"AlmaLinux 8 : samba (ALSA-2023:2987)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 8 host has packages installed that are affected by a vulnerability as referenced in the
ALSA-2023:2987 advisory.

  - In Samba, GnuTLS gnutls_rnd() can fail and give predictable random values. (CVE-2022-1615)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/8/ALSA-2023-2987.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-1615");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(252, 330);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:ctdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libnetapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libnetapi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libsmbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libwbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libwbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python3-samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python3-samba-dc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python3-samba-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python3-samba-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:samba-client-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:samba-common-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:samba-common-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:samba-dc-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:samba-dcerpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:samba-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:samba-krb5-printing");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:samba-ldb-ldap-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:samba-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:samba-pidl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:samba-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:samba-test-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:samba-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:samba-usershares");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:samba-vfs-iouring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:samba-winbind-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:samba-winbind-krb5-locator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:samba-winbind-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:samba-winexe");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::appstream");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::baseos");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::highavailability");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::nfv");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::powertools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::realtime");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::resilientstorage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::sap");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::sap_hana");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::supplementary");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Alma Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'AlmaLinux 8.x', 'AlmaLinux ' + os_ver);

if (!get_kb_item('Host/AlmaLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'AlmaLinux', cpu);

var pkgs = [
    {'reference':'ctdb-4.17.5-2.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnetapi-4.17.5-2.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnetapi-devel-4.17.5-2.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsmbclient-4.17.5-2.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsmbclient-devel-4.17.5-2.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libwbclient-4.17.5-2.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libwbclient-devel-4.17.5-2.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-samba-4.17.5-2.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-samba-dc-4.17.5-2.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-samba-devel-4.17.5-2.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-samba-test-4.17.5-2.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-4.17.5-2.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-client-4.17.5-2.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-client-libs-4.17.5-2.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-common-4.17.5-2.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-common-libs-4.17.5-2.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-common-tools-4.17.5-2.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-dc-libs-4.17.5-2.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-dcerpc-4.17.5-2.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-devel-4.17.5-2.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-krb5-printing-4.17.5-2.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-ldb-ldap-modules-4.17.5-2.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-libs-4.17.5-2.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-pidl-4.17.5-2.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-test-4.17.5-2.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-test-libs-4.17.5-2.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-tools-4.17.5-2.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-usershares-4.17.5-2.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-vfs-iouring-4.17.5-2.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-winbind-4.17.5-2.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-winbind-clients-4.17.5-2.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-winbind-krb5-locator-4.17.5-2.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-winbind-modules-4.17.5-2.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-winexe-4.17.5-2.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ctdb / libnetapi / libnetapi-devel / libsmbclient / libsmbclient-devel / etc');
}
