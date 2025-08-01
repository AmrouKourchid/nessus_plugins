#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2023:5738.
##

include('compat.inc');

if (description)
{
  script_id(183218);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/23");

  script_cve_id("CVE-2023-29409", "CVE-2023-39325", "CVE-2023-44487");
  script_xref(name:"ALSA", value:"2023:5738");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/10/31");
  script_xref(name:"IAVB", value:"2023-B-0064-S");
  script_xref(name:"IAVB", value:"2023-B-0080-S");
  script_xref(name:"CEA-ID", value:"CEA-2024-0004");
  script_xref(name:"IAVB", value:"2023-B-0083-S");

  script_name(english:"AlmaLinux 9 : go-toolset and golang (ALSA-2023:5738)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ALSA-2023:5738 advisory.

  - Extremely large RSA keys in certificate chains can cause a client/server to expend significant CPU time
    verifying signatures. With fix, the size of RSA keys transmitted during handshakes is restricted to <=
    8192 bits. Based on a survey of publicly trusted RSA keys, there are currently only three certificates in
    circulation with keys larger than this, and all three appear to be test certificates that are not actively
    deployed. It is possible there are larger keys in use in private PKIs, but we target the web PKI, so
    causing breakage here in the interests of increasing the default safety of users of crypto/tls seems
    reasonable. (CVE-2023-29409)

  - A malicious HTTP/2 client which rapidly creates requests and immediately resets them can cause excessive
    server resource consumption. While the total number of requests is bounded by the
    http2.Server.MaxConcurrentStreams setting, resetting an in-progress request allows the attacker to create
    a new request while the existing one is still executing. With the fix applied, HTTP/2 servers now bound
    the number of simultaneously executing handler goroutines to the stream concurrency limit
    (MaxConcurrentStreams). New requests arriving when at the limit (which can only happen after the client
    has reset an existing, in-flight request) will be queued until a handler exits. If the request queue grows
    too large, the server will terminate the connection. This issue is also fixed in golang.org/x/net/http2
    for users manually configuring HTTP/2. The default stream concurrency limit is 250 streams (requests) per
    HTTP/2 connection. This value may be adjusted using the golang.org/x/net/http2 package; see the
    Server.MaxConcurrentStreams setting and the ConfigureServer function. (CVE-2023-39325)

  - The HTTP/2 protocol allows a denial of service (server resource consumption) because request cancellation
    can reset many streams quickly, as exploited in the wild in August through October 2023. (CVE-2023-44487)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/9/ALSA-2023-5738.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-44487");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(400);

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:go-toolset");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:golang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:golang-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:golang-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:golang-misc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:golang-race");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:golang-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:golang-tests");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::appstream");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::baseos");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::crb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::highavailability");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::nfv");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::realtime");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::resilientstorage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::sap");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::sap_hana");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::supplementary");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Alma Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'AlmaLinux 9.x', 'AlmaLinux ' + os_ver);

if (!get_kb_item('Host/AlmaLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'AlmaLinux', cpu);

var pkgs = [
    {'reference':'go-toolset-1.19.13-1.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'go-toolset-1.19.13-1.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-1.19.13-1.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-1.19.13-1.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-bin-1.19.13-1.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-bin-1.19.13-1.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-docs-1.19.13-1.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-misc-1.19.13-1.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-race-1.19.13-1.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-race-1.19.13-1.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-src-1.19.13-1.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-tests-1.19.13-1.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE}
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
