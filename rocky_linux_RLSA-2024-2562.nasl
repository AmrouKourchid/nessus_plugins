#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Rocky Linux Security Advisory RLSA-2024:2562.
##

include('compat.inc');

if (description)
{
  script_id(196964);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/06");

  script_cve_id(
    "CVE-2023-45288",
    "CVE-2023-45289",
    "CVE-2023-45290",
    "CVE-2024-1394",
    "CVE-2024-24783",
    "CVE-2024-24784",
    "CVE-2024-24785"
  );
  script_xref(name:"IAVB", value:"2024-B-0020-S");
  script_xref(name:"IAVB", value:"2024-B-0032-S");
  script_xref(name:"RLSA", value:"2024:2562");

  script_name(english:"Rocky Linux 9 : golang (RLSA-2024:2562)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Rocky Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Rocky Linux 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
RLSA-2024:2562 advisory.

  - An attacker may cause an HTTP/2 endpoint to read arbitrary amounts of header data by sending an excessive
    number of CONTINUATION frames. Maintaining HPACK state requires parsing and processing all HEADERS and
    CONTINUATION frames on a connection. When a request's headers exceed MaxHeaderBytes, no memory is
    allocated to store the excess headers, but they are still parsed. This permits an attacker to cause an
    HTTP/2 endpoint to read arbitrary amounts of header data, all associated with a request which is going to
    be rejected. These headers can include Huffman-encoded data which is significantly more expensive for the
    receiver to decode than for an attacker to send. The fix sets a limit on the amount of excess header
    frames we will process before closing a connection. (CVE-2023-45288)

  - When following an HTTP redirect to a domain which is not a subdomain match or exact match of the initial
    domain, an http.Client does not forward sensitive headers such as Authorization or Cookie. For
    example, a redirect from foo.com to www.foo.com will forward the Authorization header, but a redirect to
    bar.com will not. A maliciously crafted HTTP redirect could cause sensitive headers to be unexpectedly
    forwarded. (CVE-2023-45289)

  - When parsing a multipart form (either explicitly with Request.ParseMultipartForm or implicitly with
    Request.FormValue, Request.PostFormValue, or Request.FormFile), limits on the total size of the parsed
    form were not applied to the memory consumed while reading a single form line. This permits a maliciously
    crafted input containing very long lines to cause allocation of arbitrarily large amounts of memory,
    potentially leading to memory exhaustion. With fix, the ParseMultipartForm function now correctly limits
    the maximum size of form lines. (CVE-2023-45290)

  - A memory leak flaw was found in Golang in the RSA encrypting/decrypting code, which might lead to a
    resource exhaustion vulnerability using attacker-controlled inputs. The memory leak happens in
    github.com/golang-fips/openssl/openssl/rsa.go#L113. The objects leaked are pkey and ctx. That function
    uses named return parameters to free pkey and ctx if there is an error initializing the context or
    setting the different properties. All return statements related to error cases follow the return nil,
    nil, fail(...) pattern, meaning that pkey and ctx will be nil inside the deferred function that should
    free them. (CVE-2024-1394)

  - Verifying a certificate chain which contains a certificate with an unknown public key algorithm will cause
    Certificate.Verify to panic. This affects all crypto/tls clients, and servers that set Config.ClientAuth
    to VerifyClientCertIfGiven or RequireAndVerifyClientCert. The default behavior is for TLS servers to not
    verify client certificates. (CVE-2024-24783)

  - The ParseAddressList function incorrectly handles comments (text within parentheses) within display names.
    Since this is a misalignment with conforming address parsers, it can result in different trust decisions
    being made by programs using different parsers. (CVE-2024-24784)

  - If errors returned from MarshalJSON methods contain user controlled data, they may be used to break the
    contextual auto-escaping behavior of the html/template package, allowing for subsequent actions to inject
    unexpected content into templates. (CVE-2024-24785)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.rockylinux.org/RLSA-2024:2562");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2262921");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2268017");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2268018");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2268019");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2268021");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2268022");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2268273");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-24785");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-24784");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:go-toolset");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:golang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:golang-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:golang-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:golang-misc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:golang-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:golang-tests");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rocky:linux:9");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (! preg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Rocky Linux 9.x', 'Rocky Linux ' + os_ver);

if (!get_kb_item('Host/RockyLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Rocky Linux', cpu);

var pkgs = [
    {'reference':'go-toolset-1.21.9-2.el9_4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'go-toolset-1.21.9-2.el9_4', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'go-toolset-1.21.9-2.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-1.21.9-2.el9_4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-1.21.9-2.el9_4', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-1.21.9-2.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-bin-1.21.9-2.el9_4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-bin-1.21.9-2.el9_4', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-bin-1.21.9-2.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-docs-1.21.9-2.el9_4', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-misc-1.21.9-2.el9_4', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-src-1.21.9-2.el9_4', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-tests-1.21.9-2.el9_4', 'release':'9', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'go-toolset / golang / golang-bin / golang-docs / golang-misc / etc');
}
