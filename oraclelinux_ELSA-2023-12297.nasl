#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2023-12297.
##

include('compat.inc');

if (description)
{
  script_id(174721);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/23");

  script_cve_id("CVE-2023-0286");
  script_xref(name:"IAVA", value:"2022-A-0518-S");

  script_name(english:"Oracle Linux 6 : openssl (ELSA-2023-12297)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 6 host has packages installed that are affected by a vulnerability as referenced in the
ELSA-2023-12297 advisory.

    - Backport fixes for CVE-2023-0286 [Orabug: 35212597]
    - Fix possible infinite loop in BN_mod_sqrt() [CVE-2022-0778][Orabug: 33969800]
    - Backport fixes for CVE-2020-1971 [Orabug: 32654738]
    - Oracle bug 28730228: backport CVE-2018-0732
    - Oracle bug 28758493: backport CVE-2018-0737
    - Merge upstream patch to fix CVE-2018-0739
    - fix CVE-2019-1559 - 0-byte record padding oracle
    - fix CVE-2017-3731 - DoS via truncated packets with RC4-MD5 cipher
    - fix CVE-2016-8610 - DoS of single-threaded servers via excessive alerts
    - fix CVE-2016-2177 - possible integer overflow
    - fix CVE-2016-2178 - non-constant time DSA operations
    - fix CVE-2016-2179 - further DoS issues in DTLS
    - fix CVE-2016-2180 - OOB read in TS_OBJ_print_bio()
    - fix CVE-2016-2181 - DTLS1 replay protection and unprocessed records issue
    - fix CVE-2016-2182 - possible buffer overflow in BN_bn2dec()
    - fix CVE-2016-6302 - insufficient TLS session ticket HMAC length check
    - fix CVE-2016-6304 - unbound memory growth with OCSP status request
    - fix CVE-2016-6306 - certificate message OOB reads
    - mitigate CVE-2016-2183 - degrade all 64bit block ciphers and RC4 to
      112 bit effective strength
    - fix CVE-2016-2105 - possible overflow in base64 encoding
    - fix CVE-2016-2106 - possible overflow in EVP_EncryptUpdate()
    - fix CVE-2016-2107 - padding oracle in stitched AES-NI CBC-MAC
    - fix CVE-2016-2108 - memory corruption in ASN.1 encoder
    - fix CVE-2016-2109 - possible DoS when reading ASN.1 data from BIO
    - fix CVE-2016-0799 - memory issues in BIO_printf
    - fix CVE-2016-0702 - side channel attack on modular exponentiation
    - fix CVE-2016-0705 - double-free in DSA private key parsing
    - fix CVE-2016-0797 - heap corruption in BN_hex2bn and BN_dec2bn
    - fix CVE-2015-3197 - SSLv2 ciphersuite enforcement
    - fix CVE-2015-7575 - disallow use of MD5 in TLS1.2
    - fix CVE-2015-3194 - certificate verify crash with missing PSS parameter
    - fix CVE-2015-3195 - X509_ATTRIBUTE memory leak
    - fix CVE-2015-3196 - race condition when handling PSK identity hint
    - fix regression caused by mistake in fix for CVE-2015-1791
    - improved fix for CVE-2015-1791
    - add missing parts of CVE-2015-0209 fix for corectness although unexploitable
    - fix CVE-2014-8176 - invalid free in DTLS buffering code
    - fix CVE-2015-1789 - out-of-bounds read in X509_cmp_time
    - fix CVE-2015-1790 - PKCS7 crash with missing EncryptedContent
    - fix CVE-2015-1791 - race condition handling NewSessionTicket
    - fix CVE-2015-1792 - CMS verify infinite loop with unknown hash function
    - fix CVE-2015-3216 - regression in RAND locking that can cause segfaults on
      read in multithreaded applications
    - fix CVE-2015-4000 - prevent the logjam attack on client - restrict
      the DH key size to at least 768 bits (limit will be increased in future)
    - update fix for CVE-2015-0287 to what was released upstream
    - fix CVE-2015-0209 - potential use after free in d2i_ECPrivateKey()
    - fix CVE-2015-0286 - improper handling of ASN.1 boolean comparison
    - fix CVE-2015-0287 - ASN.1 structure reuse decoding memory corruption
    - fix CVE-2015-0288 - X509_to_X509_REQ NULL pointer dereference
    - fix CVE-2015-0289 - NULL dereference decoding invalid PKCS#7 data
    - fix CVE-2015-0292 - integer underflow in base64 decoder
    - fix CVE-2015-0293 - triggerable assert in SSLv2 server
    - fix CVE-2014-3570 - incorrect computation in BN_sqr()
    - fix CVE-2014-3571 - possible crash in dtls1_get_record()
    - fix CVE-2014-3572 - possible downgrade of ECDH ciphersuite to non-PFS state
    - fix CVE-2014-8275 - various certificate fingerprint issues
    - fix CVE-2015-0204 - remove support for RSA ephemeral keys for non-export
      ciphersuites and on server
    - fix CVE-2015-0205 - do not allow unauthenticated client DH certificate
    - fix CVE-2015-0206 - possible memory leak when buffering DTLS records
    - fix CVE-2014-3567 - memory leak when handling session tickets
    - fix CVE-2014-3513 - memory leak in srtp support
    - add support for fallback SCSV to partially mitigate CVE-2014-3566
      (padding attack on SSL3)
    - fix CVE-2014-3505 - doublefree in DTLS packet processing
    - fix CVE-2014-3506 - avoid memory exhaustion in DTLS
    - fix CVE-2014-3507 - avoid memory leak in DTLS
    - fix CVE-2014-3508 - fix OID handling to avoid information leak
    - fix CVE-2014-3509 - fix race condition when parsing server hello
    - fix CVE-2014-3510 - fix DoS in anonymous (EC)DH handling in DTLS
    - fix CVE-2014-3511 - disallow protocol downgrade via fragmentation
    - fix CVE-2014-0224 fix that broke EAP-FAST session resumption support
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

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2023-12297.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_supplemental", value:"CVSS:4.0/U:Red");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:U");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-0286");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssl-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssl-static");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

var pkgs = [
    {'reference':'openssl-1.0.1e-59.0.4.el6_10', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-devel-1.0.1e-59.0.4.el6_10', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-perl-1.0.1e-59.0.4.el6_10', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-static-1.0.1e-59.0.4.el6_10', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-1.0.1e-59.0.4.el6_10', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-devel-1.0.1e-59.0.4.el6_10', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-perl-1.0.1e-59.0.4.el6_10', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-static-1.0.1e-59.0.4.el6_10', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'openssl / openssl-devel / openssl-perl / etc');
}
