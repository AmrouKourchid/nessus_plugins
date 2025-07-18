#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2023 Security Advisory ALAS2023-2025-834.
##

include('compat.inc');

if (description)
{
  script_id(215029);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/14");

  script_cve_id("CVE-2024-45337", "CVE-2024-45338", "CVE-2024-51744");

  script_name(english:"Amazon Linux 2023 : runfinch-finch (ALAS2023-2025-834)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2023 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"It is, therefore, affected by multiple vulnerabilities as referenced in the ALAS2023-2025-834 advisory.

    2025-02-11: CVE-2024-45338 was added to this advisory.

    2025-02-11: CVE-2024-51744 was added to this advisory.

    Applications and libraries which misuse the ServerConfig.PublicKeyCallback callback may be susceptible to
    an authorization bypass. The documentation for ServerConfig.PublicKeyCallback says that A call to this
    function does not guarantee that the key offered is in fact used to authenticate. Specifically, the SSH
    protocol allows clients to inquire about whether a public key is acceptable before proving control of the
    corresponding private key. PublicKeyCallback may be called with multiple keys, and the order in which the
    keys were provided cannot be used to infer which key the client successfully authenticated with, if any.
    Some applications, which store the key(s) passed to PublicKeyCallback (or derived information) and make
    security relevant determinations based on it once the connection is established, may make incorrect
    assumptions. For example, an attacker may send public keys A and B, and then authenticate with A.
    PublicKeyCallback would be called only twice, first with A and then with B. A vulnerable application may
    then make authorization decisions based on key B for which the attacker does not actually control the
    private key. Since this API is widely misused, as a partial mitigation golang.org/x/cry...@v0.31.0
    enforces the property that, when successfully authenticating via public key, the last key passed to
    ServerConfig.PublicKeyCallback will be the key used to authenticate the connection. PublicKeyCallback will
    now be called multiple times with the same key, if necessary. Note that the client may still not control
    the last key passed to PublicKeyCallback if the connection is then authenticated with a different method,
    such as PasswordCallback, KeyboardInteractiveCallback, or NoClientAuth. Users should be using the
    Extensions field of the Permissions return value from the various authentication callbacks to record data
    associated with the authentication attempt instead of referencing external state. Once the connection is
    established the state corresponding to the successful authentication attempt can be retrieved via the
    ServerConn.Permissions field. Note that some third-party libraries misuse the Permissions type by sharing
    it across authentication attempts; users of third-party libraries should refer to the relevant projects
    for guidance. (CVE-2024-45337)

    An attacker can craft an input to the Parse functions that would be processed non-linearly with respect to
    its length, resulting in extremely slow parsing. This could cause a denial of service. (CVE-2024-45338)

    golang-jwt is a Go implementation of JSON Web Tokens. Unclear documentation of the error behavior in
    `ParseWithClaims` can lead to situation where users are potentially not checking errors in the way they
    should be. Especially, if a token is both expired and invalid, the errors returned by `ParseWithClaims`
    return both error codes. If users only check for the `jwt.ErrTokenExpired ` using `error.Is`, they will
    ignore the embedded `jwt.ErrTokenSignatureInvalid` and thus potentially accept invalid tokens. A fix has
    been back-ported with the error handling logic from the `v5` branch to the `v4` branch. In this logic, the
    `ParseWithClaims` function will immediately return in dangerous situations (e.g., an invalid signature),
    limiting the combined errors only to situations where the signature is valid, but further validation
    failed (e.g., if the signature is valid, but is expired AND has the wrong audience). This fix is part of
    the 4.5.1 release. We are aware that this changes the behaviour of an established function and is not 100
    % backwards compatible, so updating to 4.5.1 might break your code. In case you cannot update to 4.5.0,
    please make sure that you are properly checking for all errors (dangerous ones first), so that you are
    not running in the case detailed above. (CVE-2024-51744)

Tenable has extracted the preceding description block directly from the tested product security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2023/ALAS-2025-834.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-45337.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-45338.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-51744.html");
  script_set_attribute(attribute:"solution", value:
"");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-45337");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/12/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:runfinch-finch");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2023");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var alas_release = get_kb_item("Host/AmazonLinux/release");
if (isnull(alas_release) || !strlen(alas_release)) audit(AUDIT_OS_NOT, "Amazon Linux");
var os_ver = pregmatch(pattern: "^AL(A|\d+|-\d+)", string:alas_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "-2023")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2023", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var pkgs = [
    {'reference':'runfinch-finch-1.6.0-1.amzn2023.0.1', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'runfinch-finch-1.6.0-1.amzn2023.0.1', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE}
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
  var cves = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['cves'])) cves = package_array['cves'];
  if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj, cves:cves)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "runfinch-finch");
}
