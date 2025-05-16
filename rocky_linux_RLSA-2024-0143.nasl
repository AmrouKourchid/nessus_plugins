#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Rocky Linux Security Advisory RLSA-2024:0143.
##

include('compat.inc');

if (description)
{
  script_id(188017);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/21");

  script_cve_id("CVE-2020-17049", "CVE-2023-5455");
  script_xref(name:"RLSA", value:"2024:0143");

  script_name(english:"Rocky Linux 8 : idm:DL1 (RLSA-2024:0143)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Rocky Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Rocky Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
RLSA-2024:0143 advisory.

  - <p>A security feature bypass vulnerability exists in the way Key Distribution Center (KDC) determines if a
    service ticket can be used for delegation via Kerberos Constrained Delegation (KCD).</p> <p>To exploit the
    vulnerability, a compromised service that is configured to use KCD could tamper with a service ticket that
    is not valid for delegation to force the KDC to accept it.</p> <p>The update addresses this vulnerability
    by changing how the KDC validates service tickets used with KCD.</p> (CVE-2020-17049)

  - A Cross-site request forgery vulnerability exists in ipa/session/login_password in all supported versions
    of IPA. This flaw allows an attacker to trick the user into submitting a request that could perform
    actions as the user, resulting in a loss of confidentiality and system integrity. During community
    penetration testing it was found that for certain HTTP end-points FreeIPA does not ensure CSRF protection.
    Due to implementation details one cannot use this flaw for reflection of a cookie representing already
    logged-in user. An attacker would always have to go through a new authentication attempt. (CVE-2023-5455)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.rockylinux.org/RLSA-2024:0143");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2025721");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2242828");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-17049");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:bind-dyndb-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:bind-dyndb-ldap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:bind-dyndb-ldap-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:custodia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:ipa-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:ipa-client-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:ipa-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:ipa-client-epn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:ipa-client-samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:ipa-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:ipa-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:ipa-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:ipa-healthcheck");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:ipa-healthcheck-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:ipa-python-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:ipa-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:ipa-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:ipa-server-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:ipa-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:ipa-server-dns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:ipa-server-trust-ad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:ipa-server-trust-ad-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:opendnssec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:opendnssec-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:opendnssec-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-custodia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-ipaclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-ipalib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-ipaserver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-ipatests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-jwcrypto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-kdcproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-pyusb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-qrcode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-qrcode-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-yubico");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:slapi-nis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:slapi-nis-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:slapi-nis-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:softhsm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:softhsm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:softhsm-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:softhsm-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rocky:linux:8");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Rocky Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RockyLinux/release", "Host/RockyLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RockyLinux/release');
if (isnull(os_release) || 'Rocky Linux' >!< os_release) audit(AUDIT_OS_NOT, 'Rocky Linux');
var os_ver = pregmatch(pattern: "Rocky(?: Linux)? release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Rocky Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Rocky Linux 8.x', 'Rocky Linux ' + os_ver);

if (!get_kb_item('Host/RockyLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Rocky Linux', cpu);

var pkgs = [
    {'reference':'bind-dyndb-ldap-11.6-4.module+el8.9.0+1371+ffa84eb9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bind-dyndb-ldap-debuginfo-11.6-4.module+el8.9.0+1371+ffa84eb9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bind-dyndb-ldap-debugsource-11.6-4.module+el8.9.0+1371+ffa84eb9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'custodia-0.6.0-3.module+el8.9.0+1371+ffa84eb9', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-client-4.9.12-11.module+el8.9.0+1652+4ee71f6a', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-client-common-4.9.12-11.module+el8.9.0+1652+4ee71f6a', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-client-debuginfo-4.9.12-11.module+el8.9.0+1652+4ee71f6a', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-client-epn-4.9.12-11.module+el8.9.0+1652+4ee71f6a', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-client-samba-4.9.12-11.module+el8.9.0+1652+4ee71f6a', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-common-4.9.12-11.module+el8.9.0+1652+4ee71f6a', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-debuginfo-4.9.12-11.module+el8.9.0+1652+4ee71f6a', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-debugsource-4.9.12-11.module+el8.9.0+1652+4ee71f6a', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-healthcheck-0.12-3.module+el8.9.0+1434+912e18bd', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-healthcheck-core-0.12-3.module+el8.9.0+1433+5bd2f890', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-python-compat-4.9.12-11.module+el8.9.0+1652+4ee71f6a', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-selinux-4.9.12-11.module+el8.9.0+1652+4ee71f6a', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-server-4.9.12-11.module+el8.9.0+1652+4ee71f6a', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-server-common-4.9.12-11.module+el8.9.0+1652+4ee71f6a', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-server-debuginfo-4.9.12-11.module+el8.9.0+1652+4ee71f6a', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-server-dns-4.9.12-11.module+el8.9.0+1652+4ee71f6a', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-server-trust-ad-4.9.12-11.module+el8.9.0+1652+4ee71f6a', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-server-trust-ad-debuginfo-4.9.12-11.module+el8.9.0+1652+4ee71f6a', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'opendnssec-2.1.7-1.module+el8.9.0+1371+ffa84eb9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'opendnssec-debuginfo-2.1.7-1.module+el8.9.0+1371+ffa84eb9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'opendnssec-debugsource-2.1.7-1.module+el8.9.0+1371+ffa84eb9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-custodia-0.6.0-3.module+el8.9.0+1371+ffa84eb9', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-ipaclient-4.9.12-11.module+el8.9.0+1652+4ee71f6a', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-ipalib-4.9.12-11.module+el8.9.0+1652+4ee71f6a', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-ipaserver-4.9.12-11.module+el8.9.0+1652+4ee71f6a', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-ipatests-4.9.12-11.module+el8.9.0+1652+4ee71f6a', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-jwcrypto-0.5.0-1.1.module+el8.9.0+1371+ffa84eb9', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-kdcproxy-0.4-5.module+el8.9.0+1371+ffa84eb9', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-pyusb-1.0.0-9.1.module+el8.9.0+1371+ffa84eb9', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-qrcode-5.1-12.module+el8.9.0+1371+ffa84eb9', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-qrcode-core-5.1-12.module+el8.9.0+1371+ffa84eb9', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-yubico-1.3.2-9.1.module+el8.9.0+1371+ffa84eb9', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'slapi-nis-0.60.0-4.module+el8.9.0+1573+39ab85f4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'slapi-nis-debuginfo-0.60.0-4.module+el8.9.0+1573+39ab85f4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'slapi-nis-debugsource-0.60.0-4.module+el8.9.0+1573+39ab85f4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'softhsm-2.6.0-5.module+el8.9.0+1371+ffa84eb9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'softhsm-debuginfo-2.6.0-5.module+el8.9.0+1371+ffa84eb9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'softhsm-debugsource-2.6.0-5.module+el8.9.0+1371+ffa84eb9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'softhsm-devel-2.6.0-5.module+el8.9.0+1371+ffa84eb9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
  if (!empty_or_null(package_array['release'])) _release = 'Rocky-' + package_array['release'];
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
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bind-dyndb-ldap / bind-dyndb-ldap-debuginfo / etc');
}
