#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Rocky Linux Security Advisory RLSA-2023:0946.
##

include('compat.inc');

if (description)
{
  script_id(173651);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/06");

  script_cve_id(
    "CVE-2022-4203",
    "CVE-2022-4304",
    "CVE-2022-4450",
    "CVE-2023-0215",
    "CVE-2023-0216",
    "CVE-2023-0217",
    "CVE-2023-0286",
    "CVE-2023-0401"
  );
  script_xref(name:"RLSA", value:"2023:0946");
  script_xref(name:"IAVA", value:"2022-A-0518-S");

  script_name(english:"Rocky Linux 9 : openssl (RLSA-2023:0946)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Rocky Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Rocky Linux 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
RLSA-2023:0946 advisory.

  - A read buffer overrun can be triggered in X.509 certificate verification, specifically in name constraint
    checking. Note that this occurs after certificate chain signature verification and requires either a CA to
    have signed the malicious certificate or for the application to continue certificate verification despite
    failure to construct a path to a trusted issuer. The read buffer overrun might result in a crash which
    could lead to a denial of service attack. In theory it could also result in the disclosure of private
    memory contents (such as private keys, or sensitive plaintext) although we are not aware of any working
    exploit leading to memory contents disclosure as of the time of release of this advisory. In a TLS client,
    this can be triggered by connecting to a malicious server. In a TLS server, this can be triggered if the
    server requests client authentication and a malicious client connects. (CVE-2022-4203)

  - A timing based side channel exists in the OpenSSL RSA Decryption implementation which could be sufficient
    to recover a plaintext across a network in a Bleichenbacher style attack. To achieve a successful
    decryption an attacker would have to be able to send a very large number of trial messages for decryption.
    The vulnerability affects all RSA padding modes: PKCS#1 v1.5, RSA-OEAP and RSASVE. For example, in a TLS
    connection, RSA is commonly used by a client to send an encrypted pre-master secret to the server. An
    attacker that had observed a genuine connection between a client and a server could use this flaw to send
    trial messages to the server and record the time taken to process them. After a sufficiently large number
    of messages the attacker could recover the pre-master secret used for the original connection and thus be
    able to decrypt the application data sent over that connection. (CVE-2022-4304)

  - The function PEM_read_bio_ex() reads a PEM file from a BIO and parses and decodes the name (e.g.
    CERTIFICATE), any header data and the payload data. If the function succeeds then the name_out,
    header and data arguments are populated with pointers to buffers containing the relevant decoded data.
    The caller is responsible for freeing those buffers. It is possible to construct a PEM file that results
    in 0 bytes of payload data. In this case PEM_read_bio_ex() will return a failure code but will populate
    the header argument with a pointer to a buffer that has already been freed. If the caller also frees this
    buffer then a double free will occur. This will most likely lead to a crash. This could be exploited by an
    attacker who has the ability to supply malicious PEM files for parsing to achieve a denial of service
    attack. The functions PEM_read_bio() and PEM_read() are simple wrappers around PEM_read_bio_ex() and
    therefore these functions are also directly affected. These functions are also called indirectly by a
    number of other OpenSSL functions including PEM_X509_INFO_read_bio_ex() and SSL_CTX_use_serverinfo_file()
    which are also vulnerable. Some OpenSSL internal uses of these functions are not vulnerable because the
    caller does not free the header argument if PEM_read_bio_ex() returns a failure code. These locations
    include the PEM_read_bio_TYPE() functions as well as the decoders introduced in OpenSSL 3.0. The OpenSSL
    asn1parse command line application is also impacted by this issue. (CVE-2022-4450)

  - The public API function BIO_new_NDEF is a helper function used for streaming ASN.1 data via a BIO. It is
    primarily used internally to OpenSSL to support the SMIME, CMS and PKCS7 streaming capabilities, but may
    also be called directly by end user applications. The function receives a BIO from the caller, prepends a
    new BIO_f_asn1 filter BIO onto the front of it to form a BIO chain, and then returns the new head of the
    BIO chain to the caller. Under certain conditions, for example if a CMS recipient public key is invalid,
    the new filter BIO is freed and the function returns a NULL result indicating a failure. However, in this
    case, the BIO chain is not properly cleaned up and the BIO passed by the caller still retains internal
    pointers to the previously freed filter BIO. If the caller then goes on to call BIO_pop() on the BIO then
    a use-after-free will occur. This will most likely result in a crash. This scenario occurs directly in the
    internal function B64_write_ASN1() which may cause BIO_new_NDEF() to be called and will subsequently call
    BIO_pop() on the BIO. This internal function is in turn called by the public API functions
    PEM_write_bio_ASN1_stream, PEM_write_bio_CMS_stream, PEM_write_bio_PKCS7_stream, SMIME_write_ASN1,
    SMIME_write_CMS and SMIME_write_PKCS7. Other public API functions that may be impacted by this include
    i2d_ASN1_bio_stream, BIO_new_CMS, BIO_new_PKCS7, i2d_CMS_bio_stream and i2d_PKCS7_bio_stream. The OpenSSL
    cms and smime command line applications are similarly affected. (CVE-2023-0215)

  - An invalid pointer dereference on read can be triggered when an application tries to load malformed PKCS7
    data with the d2i_PKCS7(), d2i_PKCS7_bio() or d2i_PKCS7_fp() functions. The result of the dereference is
    an application crash which could lead to a denial of service attack. The TLS implementation in OpenSSL
    does not call this function however third party applications might call these functions on untrusted data.
    (CVE-2023-0216)

  - An invalid pointer dereference on read can be triggered when an application tries to check a malformed DSA
    public key by the EVP_PKEY_public_check() function. This will most likely lead to an application crash.
    This function can be called on public keys supplied from untrusted sources which could allow an attacker
    to cause a denial of service attack. The TLS implementation in OpenSSL does not call this function but
    applications might call the function if there are additional security requirements imposed by standards
    such as FIPS 140-3. (CVE-2023-0217)

  - There is a type confusion vulnerability relating to X.400 address processing inside an X.509 GeneralName.
    X.400 addresses were parsed as an ASN1_STRING but the public structure definition for GENERAL_NAME
    incorrectly specified the type of the x400Address field as ASN1_TYPE. This field is subsequently
    interpreted by the OpenSSL function GENERAL_NAME_cmp as an ASN1_TYPE rather than an ASN1_STRING. When CRL
    checking is enabled (i.e. the application sets the X509_V_FLAG_CRL_CHECK flag), this vulnerability may
    allow an attacker to pass arbitrary pointers to a memcmp call, enabling them to read memory contents or
    enact a denial of service. In most cases, the attack requires the attacker to provide both the certificate
    chain and CRL, neither of which need to have a valid signature. If the attacker only controls one of these
    inputs, the other input must already contain an X.400 address as a CRL distribution point, which is
    uncommon. As such, this vulnerability is most likely to only affect applications which have implemented
    their own functionality for retrieving CRLs over a network. (CVE-2023-0286)

  - A NULL pointer can be dereferenced when signatures are being verified on PKCS7 signed or
    signedAndEnveloped data. In case the hash algorithm used for the signature is known to the OpenSSL library
    but the implementation of the hash algorithm is not available the digest initialization will fail. There
    is a missing check for the return value from the initialization function which later leads to invalid
    usage of the digest API most likely leading to a crash. The unavailability of an algorithm can be caused
    by using FIPS enabled configuration of providers or more commonly by not loading the legacy provider.
    PKCS7 data is processed by the SMIME library calls and also by the time stamp (TS) library calls. The TLS
    implementation in OpenSSL does not call these functions however third party applications would be affected
    if they call these functions to verify signatures on untrusted data. (CVE-2023-0401)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.rockylinux.org/RLSA-2023:0946");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2144000");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2144003");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2144006");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2144008");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2144010");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2144012");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2144015");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2144017");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2144019");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2145170");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2158412");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2164440");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2164487");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2164488");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2164492");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2164494");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2164497");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2164499");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2164500");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-0286");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:openssl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:openssl-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:openssl-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:openssl-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:openssl-perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rocky:linux:9");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Rocky Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Rocky Linux 9.x', 'Rocky Linux ' + os_ver);

if (!get_kb_item('Host/RockyLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Rocky Linux', cpu);

var pkgs = [
    {'reference':'openssl-3.0.1-47.el9_1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'openssl-3.0.1-47.el9_1', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'openssl-3.0.1-47.el9_1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'openssl-debuginfo-3.0.1-47.el9_1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'openssl-debuginfo-3.0.1-47.el9_1', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'openssl-debuginfo-3.0.1-47.el9_1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'openssl-debugsource-3.0.1-47.el9_1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'openssl-debugsource-3.0.1-47.el9_1', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'openssl-debugsource-3.0.1-47.el9_1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'openssl-devel-3.0.1-47.el9_1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'openssl-devel-3.0.1-47.el9_1', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'openssl-devel-3.0.1-47.el9_1', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'openssl-devel-3.0.1-47.el9_1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'openssl-libs-3.0.1-47.el9_1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'openssl-libs-3.0.1-47.el9_1', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'openssl-libs-3.0.1-47.el9_1', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'openssl-libs-3.0.1-47.el9_1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'openssl-libs-debuginfo-3.0.1-47.el9_1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'openssl-libs-debuginfo-3.0.1-47.el9_1', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'openssl-libs-debuginfo-3.0.1-47.el9_1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'openssl-perl-3.0.1-47.el9_1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'openssl-perl-3.0.1-47.el9_1', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'openssl-perl-3.0.1-47.el9_1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'openssl / openssl-debuginfo / openssl-debugsource / openssl-devel / etc');
}
