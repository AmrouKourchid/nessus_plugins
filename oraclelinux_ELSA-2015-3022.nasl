#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2015-3022.
##

include('compat.inc');

if (description)
{
  script_id(181036);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/22");

  script_cve_id(
    "CVE-2015-0209",
    "CVE-2015-0286",
    "CVE-2015-0287",
    "CVE-2015-0288",
    "CVE-2015-0289",
    "CVE-2015-0292",
    "CVE-2015-0293"
  );

  script_name(english:"Oracle Linux 6 : openssl-fips (ELSA-2015-3022)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 6 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2015-3022 advisory.

    - fix CVE-2010-5298 - possible use of memory after free
    - fix CVE-2014-0195 - buffer overflow via invalid DTLS fragment
    - fix CVE-2014-0198 - possible NULL pointer dereference
    - fix CVE-2014-0221 - DoS from invalid DTLS handshake packet
    - fix CVE-2014-0224 - SSL/TLS MITM vulnerability
    - fix CVE-2014-3470 - client-side DoS when using anonymous ECDH
    - fix CVE-2014-0160 - information disclosure in TLS heartbeat extension
    - fix CVE-2013-4353 - Invalid TLS handshake crash
    - fix CVE-2013-6450 - possible MiTM attack on DTLS1
    - fix CVE-2013-6449 - crash when version in SSL structure is incorrect
    - fix for CVE-2013-0169 - SSL/TLS CBC timing attack (#907589)
    - fix for CVE-2013-0166 - DoS in OCSP signatures checking (#908052)
    - enable compression only if explicitly asked for or OPENSSL_DEFAULT_ZLIB
      environment variable is set (fixes CVE-2012-4929 #857051)
    - fix for CVE-2012-2333 - improper checking for record length in DTLS (#820686)
    - properly initialize tkeylen in the CVE-2012-0884 fix
    - fix for CVE-2012-2110 - memory corruption in asn1_d2i_read_bio() (#814185)
    - fix for CVE-2012-0884 - MMA weakness in CMS and PKCS#7 code (#802725)
    - fix for CVE-2012-1165 - NULL read dereference on bad MIME headers (#802489)
    - fix for CVE-2011-4108 & CVE-2012-0050 - DTLS plaintext recovery
      vulnerability and additional DTLS fixes (#771770)
    - fix for CVE-2011-4576 - uninitialized SSL 3.0 padding (#771775)
    - fix for CVE-2011-4577 - possible DoS through malformed RFC 3779 data (#771778)
    - fix for CVE-2011-4619 - SGC restart DoS attack (#771780)
    - initialize the X509_STORE_CTX properly for CRL lookups - CVE-2011-3207
      (#736087)
    - fix OCSP stapling vulnerability - CVE-2011-0014 (#676063)
    - disable code for SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG - CVE-2010-3864
      (#649304)
    - fix race in extension parsing code - CVE-2010-3864 (#649304)
    - fix wrong ASN.1 definition of OriginatorInfo - CVE-2010-0742 (#598738)
    - fix information leak in rsa_verify_recover - CVE-2010-1633 (#598732)
    - fix CVE-2009-4355 - leak in applications incorrectly calling
      CRYPTO_free_all_ex_data() before application exit (#546707)
    - fix CVE-2009-3555 - note that the fix is bypassed if SSL_OP_ALL is used
      so the compatibility with unfixed clients is not broken. The
      protocol extension is also not final.
    - fix CVE-2009-1377 CVE-2009-1378 CVE-2009-1379
      (DTLS DoS problems) (#501253, #501254, #501572)
    - fix CVE-2008-0891 - server name extension crash (#448492)
    - fix CVE-2008-1672 - server key exchange message omit crash (#448495)
    - fix CVE-2007-5135 - off-by-one in SSL_get_shared_ciphers (#309801)
    - fix CVE-2007-4995 - out of order DTLS fragments buffer overflow (#321191)
    - CVE-2007-3108 - fix side channel attack on private keys (#250577)
    - CVE-2006-2940 fix was incorrect (#208744)
    - fix CVE-2006-2937 - mishandled error on ASN.1 parsing (#207276)
    - fix CVE-2006-2940 - parasitic public keys DoS (#207274)
    - fix CVE-2006-3738 - buffer overflow in SSL_get_shared_ciphers (#206940)
    - fix CVE-2006-4343 - sslv2 client DoS (#206940)
    - fix CVE-2006-4339 - prevent attack on PKCS#1 v1.5 signatures (#205180)

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2015-3022.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-0292");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssl-fips");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssl-fips-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssl-fips-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssl-fips-static");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 6', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);
if ('x86_64' >!< cpu) audit(AUDIT_ARCH_NOT, 'x86_64', cpu);

var pkgs = [
    {'reference':'openssl-fips-1.0.1m-2.0.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-fips-devel-1.0.1m-2.0.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-fips-perl-1.0.1m-2.0.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-fips-static-1.0.1m-2.0.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'openssl-fips / openssl-fips-devel / openssl-fips-perl / etc');
}
