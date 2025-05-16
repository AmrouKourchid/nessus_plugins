#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# the CentOS Stream Build Service.
##

include('compat.inc');

if (description)
{
  script_id(200325);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/14");

  script_cve_id("CVE-2024-2511", "CVE-2024-4603", "CVE-2024-4741");
  script_xref(name:"IAVA", value:"2024-A-0208-S");
  script_xref(name:"IAVA", value:"2024-A-0321-S");

  script_name(english:"CentOS 9 : openssl-3.2.2-1.el9");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing one or more security updates for openssl.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
openssl-3.2.2-1.el9 build changelog.

  - Issue summary: Some non-default TLS server configurations can cause unbounded memory growth when
    processing TLSv1.3 sessions Impact summary: An attacker may exploit certain server configurations to
    trigger unbounded memory growth that would lead to a Denial of Service This problem can occur in TLSv1.3
    if the non-default SSL_OP_NO_TICKET option is being used (but not if early_data support is also configured
    and the default anti-replay protection is in use). In this case, under certain conditions, the session
    cache can get into an incorrect state and it will fail to flush properly as it fills. The session cache
    will continue to grow in an unbounded manner. A malicious client could deliberately create the scenario
    for this failure to force a Denial of Service. It may also happen by accident in normal operation. This
    issue only affects TLS servers supporting TLSv1.3. It does not affect TLS clients. The FIPS modules in
    3.2, 3.1 and 3.0 are not affected by this issue. OpenSSL 1.0.2 is also not affected by this issue.
    (CVE-2024-2511)

  - Issue summary: Checking excessively long DSA keys or parameters may be very slow. Impact summary:
    Applications that use the functions EVP_PKEY_param_check() or EVP_PKEY_public_check() to check a DSA
    public key or DSA parameters may experience long delays. Where the key or parameters that are being
    checked have been obtained from an untrusted source this may lead to a Denial of Service. The functions
    EVP_PKEY_param_check() or EVP_PKEY_public_check() perform various checks on DSA parameters. Some of those
    computations take a long time if the modulus (`p` parameter) is too large. Trying to use a very large
    modulus is slow and OpenSSL will not allow using public keys with a modulus which is over 10,000 bits in
    length for signature verification. However the key and parameter check functions do not limit the modulus
    size when performing the checks. An application that calls EVP_PKEY_param_check() or
    EVP_PKEY_public_check() and supplies a key or parameters obtained from an untrusted source could be
    vulnerable to a Denial of Service attack. These functions are not called by OpenSSL itself on untrusted
    DSA keys so only applications that directly call these functions may be vulnerable. Also vulnerable are
    the OpenSSL pkey and pkeyparam command line applications when using the `-check` option. The OpenSSL
    SSL/TLS implementation is not affected by this issue. The OpenSSL 3.0 and 3.1 FIPS providers are affected
    by this issue. (CVE-2024-4603)

  - Issue summary: Calling the OpenSSL API function SSL_free_buffers may cause memory to be accessed that was
    previously freed in some situations Impact summary: A use after free can have a range of potential
    consequences such as the corruption of valid data, crashes or execution of arbitrary code. However, only
    applications that directly call the SSL_free_buffers function are affected by this issue. Applications
    that do not call this function are not vulnerable. Our investigations indicate that this function is
    rarely used by applications. The SSL_free_buffers function is used to free the internal OpenSSL buffer
    used when processing an incoming record from the network. The call is only expected to succeed if the
    buffer is not currently in use. However, two scenarios have been identified where the buffer is freed even
    when still in use. The first scenario occurs where a record header has been received from the network and
    processed by OpenSSL, but the full record body has not yet arrived. In this case calling SSL_free_buffers
    will succeed even though a record has only been partially processed and the buffer is still in use. The
    second scenario occurs where a full record containing application data has been received and processed by
    OpenSSL but the application has only read part of this data. Again a call to SSL_free_buffers will succeed
    even though the buffer is still in use. While these scenarios could occur accidentally during normal
    operation a malicious attacker could attempt to engineer a stituation where this occurs. We are not aware
    of this issue being actively exploited. The FIPS modules in 3.3, 3.2, 3.1 and 3.0 are not affected by this
    issue. Found by William Ahern (Akamai). Fix developed by Matt Caswell. Fix developed by Watson Ladd
    (Akamai). Fixed in OpenSSL 3.3.1 (Affected since 3.3.0). (CVE-2024-4741)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kojihub.stream.centos.org/koji/buildinfo?buildID=62270");
  script_set_attribute(attribute:"solution", value:
"Update the CentOS 9 Stream openssl package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-2511");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-4741");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:centos:centos:9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl-perl");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/CentOS/release');
if (isnull(os_release) || 'CentOS' >!< os_release) audit(AUDIT_OS_NOT, 'CentOS');
var os_ver = pregmatch(pattern: "CentOS(?: Stream)?(?: Linux)? release ([0-9]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'CentOS');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '9')) audit(AUDIT_OS_NOT, 'CentOS 9.x', 'CentOS ' + os_ver);

if (!get_kb_item('Host/CentOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'CentOS', cpu);

var pkgs = [
    {'reference':'openssl-3.2.2-1.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'openssl-devel-3.2.2-1.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'openssl-libs-3.2.2-1.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'openssl-perl-3.2.2-1.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
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
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = 'CentOS-' + package_array['release'];
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'openssl / openssl-devel / openssl-libs / openssl-perl');
}
