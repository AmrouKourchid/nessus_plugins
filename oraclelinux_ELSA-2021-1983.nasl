#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2021-1983.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149995);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/01");

  script_cve_id("CVE-2021-3480");

  script_name(english:"Oracle Linux 8 : idm:DL1 (ELSA-2021-1983)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has packages installed that are affected by a vulnerability as referenced in the
ELSA-2021-1983 advisory.

    slapi-nis
    [0.56.6-2]
    - CVE 2021-3480:  idm:DL1/slapi-nis: NULL dereference (DoS) with specially crafted Binding DN
    - Resolves: rhbz#1944713

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2021-1983.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3480");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind-dyndb-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:custodia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ipa-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ipa-client-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ipa-client-epn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ipa-client-samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ipa-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ipa-healthcheck");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ipa-healthcheck-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ipa-python-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ipa-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ipa-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ipa-server-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ipa-server-dns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ipa-server-trust-ad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:opendnssec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-custodia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-ipaclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-ipalib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-ipaserver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-ipatests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-jwcrypto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-kdcproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-pyusb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-qrcode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-qrcode-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-yubico");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:slapi-nis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:softhsm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:softhsm-devel");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

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
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 8', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var module_ver = get_kb_item('Host/RedHat/appstream/idm');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module idm:DL1');
if ('DL1' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module idm:' + module_ver);

var appstreams = {
    'idm:DL1': [
      {'reference':'bind-dyndb-ldap-11.6-2.module+el8.4.0+20088+3d202164', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'custodia-0.6.0-3.module+el8.3.0+7868+2151076c', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-client-4.9.2-3.0.1.module+el8.4.0+20161+5ecb5b37', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-client-common-4.9.2-3.0.1.module+el8.4.0+20161+5ecb5b37', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-client-epn-4.9.2-3.0.1.module+el8.4.0+20161+5ecb5b37', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-client-samba-4.9.2-3.0.1.module+el8.4.0+20161+5ecb5b37', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-common-4.9.2-3.0.1.module+el8.4.0+20161+5ecb5b37', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-healthcheck-0.7-3.module+el8.4.0+20088+3d202164', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-healthcheck-core-0.7-3.module+el8.4.0+20088+3d202164', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-python-compat-4.9.2-3.0.1.module+el8.4.0+20161+5ecb5b37', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-selinux-4.9.2-3.0.1.module+el8.4.0+20161+5ecb5b37', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-server-4.9.2-3.0.1.module+el8.4.0+20161+5ecb5b37', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-server-common-4.9.2-3.0.1.module+el8.4.0+20161+5ecb5b37', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-server-dns-4.9.2-3.0.1.module+el8.4.0+20161+5ecb5b37', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-server-trust-ad-4.9.2-3.0.1.module+el8.4.0+20161+5ecb5b37', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'opendnssec-2.1.7-1.module+el8.4.0+20088+3d202164', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-custodia-0.6.0-3.module+el8.3.0+7868+2151076c', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-ipaclient-4.9.2-3.0.1.module+el8.4.0+20161+5ecb5b37', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-ipalib-4.9.2-3.0.1.module+el8.4.0+20161+5ecb5b37', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-ipaserver-4.9.2-3.0.1.module+el8.4.0+20161+5ecb5b37', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-ipatests-4.9.2-3.0.1.module+el8.4.0+20161+5ecb5b37', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-jwcrypto-0.5.0-1.module+el8.3.0+7868+2151076c', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-kdcproxy-0.4-5.module+el8.3.0+7868+2151076c', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-pyusb-1.0.0-9.module+el8.3.0+7868+2151076c', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-qrcode-5.1-12.module+el8.3.0+7868+2151076c', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-qrcode-core-5.1-12.module+el8.3.0+7868+2151076c', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-yubico-1.3.2-9.module+el8.3.0+7868+2151076c', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'slapi-nis-0.56.6-2.module+el8.4.0+20174+ae9fc984', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'softhsm-2.6.0-5.module+el8.4.0+20161+5ecb5b37', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'softhsm-devel-2.6.0-5.module+el8.4.0+20161+5ecb5b37', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'bind-dyndb-ldap-11.6-2.module+el8.4.0+20088+3d202164', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'custodia-0.6.0-3.module+el8.3.0+7868+2151076c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-client-4.9.2-3.0.1.module+el8.4.0+20161+5ecb5b37', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-client-common-4.9.2-3.0.1.module+el8.4.0+20161+5ecb5b37', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-client-epn-4.9.2-3.0.1.module+el8.4.0+20161+5ecb5b37', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-client-samba-4.9.2-3.0.1.module+el8.4.0+20161+5ecb5b37', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-common-4.9.2-3.0.1.module+el8.4.0+20161+5ecb5b37', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-healthcheck-0.7-3.module+el8.4.0+20088+3d202164', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-healthcheck-core-0.7-3.module+el8.4.0+20088+3d202164', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-python-compat-4.9.2-3.0.1.module+el8.4.0+20161+5ecb5b37', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-selinux-4.9.2-3.0.1.module+el8.4.0+20161+5ecb5b37', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-server-4.9.2-3.0.1.module+el8.4.0+20161+5ecb5b37', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-server-common-4.9.2-3.0.1.module+el8.4.0+20161+5ecb5b37', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-server-dns-4.9.2-3.0.1.module+el8.4.0+20161+5ecb5b37', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-server-trust-ad-4.9.2-3.0.1.module+el8.4.0+20161+5ecb5b37', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'opendnssec-2.1.7-1.module+el8.4.0+20088+3d202164', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-custodia-0.6.0-3.module+el8.3.0+7868+2151076c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-ipaclient-4.9.2-3.0.1.module+el8.4.0+20161+5ecb5b37', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-ipalib-4.9.2-3.0.1.module+el8.4.0+20161+5ecb5b37', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-ipaserver-4.9.2-3.0.1.module+el8.4.0+20161+5ecb5b37', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-ipatests-4.9.2-3.0.1.module+el8.4.0+20161+5ecb5b37', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-jwcrypto-0.5.0-1.module+el8.3.0+7868+2151076c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-kdcproxy-0.4-5.module+el8.3.0+7868+2151076c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-pyusb-1.0.0-9.module+el8.3.0+7868+2151076c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-qrcode-5.1-12.module+el8.3.0+7868+2151076c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-qrcode-core-5.1-12.module+el8.3.0+7868+2151076c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-yubico-1.3.2-9.module+el8.3.0+7868+2151076c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'slapi-nis-0.56.6-2.module+el8.4.0+20174+ae9fc984', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'softhsm-2.6.0-5.module+el8.4.0+20161+5ecb5b37', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'softhsm-devel-2.6.0-5.module+el8.4.0+20161+5ecb5b37', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
    ]
};

var flag = 0;
var appstreams_found = 0;
foreach var module (keys(appstreams)) {
  var appstream = NULL;
  var appstream_name = NULL;
  var appstream_version = NULL;
  var appstream_split = split(module, sep:':', keep:FALSE);
  if (!empty_or_null(appstream_split)) {
    appstream_name = appstream_split[0];
    appstream_version = appstream_split[1];
    if (!empty_or_null(appstream_name)) appstream = get_one_kb_item('Host/RedHat/appstream/' + appstream_name);
  }
  if (!empty_or_null(appstream) && appstream_version == appstream || appstream_name == 'all') {
    appstreams_found++;
    foreach var package_array ( appstreams[module] ) {
      var reference = NULL;
      var _release = NULL;
      var sp = NULL;
      var _cpu = NULL;
      var el_string = NULL;
      var rpm_spec_vers_cmp = NULL;
      var epoch = NULL;
      var allowmaj = NULL;
      if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
      if (!empty_or_null(package_array['release'])) _release = 'EL' + package_array['release'];
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
  }
}

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module idm:DL1');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bind-dyndb-ldap / custodia / ipa-client / etc');
}
