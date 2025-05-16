#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(195274);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/09");

  script_cve_id("CVE-2023-5678", "CVE-2024-0727");

  script_name(english:"EulerOS 2.0 SP10 : linux-sgx (EulerOS-SA-2024-1596)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the linux-sgx packages installed, the EulerOS installation on the remote host is affected
by the following vulnerabilities :

  - Issue summary: Generating excessively long X9.42 DH keys or checking excessively long X9.42 DH keys or
    parameters may be very slow. Impact summary: Applications that use the functions DH_generate_key() to
    generate an X9.42 DH key may experience long delays. Likewise, applications that use DH_check_pub_key(),
    DH_check_pub_key_ex() or EVP_PKEY_public_check() to check an X9.42 DH key or X9.42 DH parameters may
    experience long delays. Where the key or parameters that are being checked have been obtained from an
    untrusted source this may lead to a Denial of Service. While DH_check() performs all the necessary checks
    (as of CVE-2023-3817), DH_check_pub_key() doesn't make any of these checks, and is therefore vulnerable
    for excessively large P and Q parameters. Likewise, while DH_generate_key() performs a check for an
    excessively large P, it doesn't check for an excessively large Q. An application that calls
    DH_generate_key() or DH_check_pub_key() and supplies a key or parameters obtained from an untrusted source
    could be vulnerable to a Denial of Service attack. DH_generate_key() and DH_check_pub_key() are also
    called by a number of other OpenSSL functions. An application calling any of those other functions may
    similarly be affected. The other functions affected by this are DH_check_pub_key_ex(),
    EVP_PKEY_public_check(), and EVP_PKEY_generate(). Also vulnerable are the OpenSSL pkey command line
    application when using the '-pubcheck' option, as well as the OpenSSL genpkey command line application.
    The OpenSSL SSL/TLS implementation is not affected by this issue. The OpenSSL 3.0 and 3.1 FIPS providers
    are not affected by this issue. (CVE-2023-5678)

  - Issue summary: Processing a maliciously formatted PKCS12 file may lead OpenSSL to crash leading to a
    potential Denial of Service attack Impact summary: Applications loading files in the PKCS12 format from
    untrusted sources might terminate abruptly. A file in PKCS12 format can contain certificates and keys and
    may come from an untrusted source. The PKCS12 specification allows certain fields to be NULL, but OpenSSL
    does not correctly check for this case. This can lead to a NULL pointer dereference that results in
    OpenSSL crashing. If an application processes PKCS12 files from an untrusted source using the OpenSSL APIs
    then that application will be vulnerable to this issue. OpenSSL APIs that are vulnerable to this are:
    PKCS12_parse(), PKCS12_unpack_p7data(), PKCS12_unpack_p7encdata(), PKCS12_unpack_authsafes() and
    PKCS12_newpass(). We have also fixed a similar issue in SMIME_write_PKCS7(). However since this function
    is related to writing data we do not consider it security significant. The FIPS modules in 3.2, 3.1 and
    3.0 are not affected by this issue. (CVE-2024-0727)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2024-1596
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0896653c");
  script_set_attribute(attribute:"solution", value:
"Update the affected linux-sgx packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-5678");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-0727");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/11/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libsgx-ae-le");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libsgx-aesm-launch-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libsgx-enclave-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libsgx-launch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libsgx-urts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:sgx-aesm-service");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var _release = get_kb_item("Host/EulerOS/release");
if (isnull(_release) || _release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (_release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP10");

var sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(10)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP10");

if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP10", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "x86" >!< cpu) audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

var flag = 0;

var pkgs = [
  "libsgx-ae-le-2.11.100-9.h14.r1.eulerosv2r10",
  "libsgx-aesm-launch-plugin-2.11.100-9.h14.r1.eulerosv2r10",
  "libsgx-enclave-common-2.11.100-9.h14.r1.eulerosv2r10",
  "libsgx-launch-2.11.100-9.h14.r1.eulerosv2r10",
  "libsgx-urts-2.11.100-9.h14.r1.eulerosv2r10",
  "sgx-aesm-service-2.11.100-9.h14.r1.eulerosv2r10"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"10", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-sgx");
}
