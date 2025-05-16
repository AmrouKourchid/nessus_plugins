#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2024:1787.
##

include('compat.inc');

if (description)
{
  script_id(208495);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/10");

  script_cve_id(
    "CVE-2023-46724",
    "CVE-2023-46728",
    "CVE-2023-49285",
    "CVE-2023-49286",
    "CVE-2023-50269",
    "CVE-2024-25617"
  );
  script_xref(name:"RHSA", value:"2024:1787");

  script_name(english:"CentOS 7 : squid (RHSA-2024:1787)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 7 host has packages installed that are affected by multiple vulnerabilities as referenced in the
RHSA-2024:1787 advisory.

  - Squid is a caching proxy for the Web. Due to an Improper Validation of Specified Index bug, Squid versions
    3.3.0.1 through 5.9 and 6.0 prior to 6.4 compiled using `--with-openssl` are vulnerable to a Denial of
    Service attack against SSL Certificate validation. This problem allows a remote server to perform Denial
    of Service against Squid Proxy by initiating a TLS Handshake with a specially crafted SSL Certificate in a
    server certificate chain. This attack is limited to HTTPS and SSL-Bump. This bug is fixed in Squid version
    6.4. In addition, patches addressing this problem for the stable releases can be found in Squid's patch
    archives. Those who you use a prepackaged version of Squid should refer to the package vendor for
    availability information on updated packages. (CVE-2023-46724)

  - Squid is a caching proxy for the Web supporting HTTP, HTTPS, FTP, and more. Due to a NULL pointer
    dereference bug Squid is vulnerable to a Denial of Service attack against Squid's Gopher gateway. The
    gopher protocol is always available and enabled in Squid prior to Squid 6.0.1. Responses triggering this
    bug are possible to be received from any gopher server, even those without malicious intent. Gopher
    support has been removed in Squid version 6.0.1. Users are advised to upgrade. Users unable to upgrade
    should reject all gopher URL requests. (CVE-2023-46728)

  - Squid is a caching proxy for the Web supporting HTTP, HTTPS, FTP, and more. Due to a Buffer Overread bug
    Squid is vulnerable to a Denial of Service attack against Squid HTTP Message processing. This bug is fixed
    by Squid version 6.5. Users are advised to upgrade. There are no known workarounds for this vulnerability.
    (CVE-2023-49285)

  - Squid is a caching proxy for the Web supporting HTTP, HTTPS, FTP, and more. Due to an Incorrect Check of
    Function Return Value bug Squid is vulnerable to a Denial of Service attack against its Helper process
    management. This bug is fixed by Squid version 6.5. Users are advised to upgrade. There are no known
    workarounds for this vulnerability. (CVE-2023-49286)

  - Squid is a caching proxy for the Web. Due to an Uncontrolled Recursion bug in versions 2.6 through
    2.7.STABLE9, versions 3.1 through 5.9, and versions 6.0.1 through 6.5, Squid may be vulnerable to a Denial
    of Service attack against HTTP Request parsing. This problem allows a remote client to perform Denial of
    Service attack by sending a large X-Forwarded-For header when the follow_x_forwarded_for feature is
    configured. This bug is fixed by Squid version 6.6. In addition, patches addressing this problem for the
    stable releases can be found in Squid's patch archives. (CVE-2023-50269)

  - Squid is an open source caching proxy for the Web supporting HTTP, HTTPS, FTP, and more. Due to a Collapse
    of Data into Unsafe Value bug ,Squid may be vulnerable to a Denial of Service attack against HTTP header
    parsing. This problem allows a remote client or a remote server to perform Denial of Service when sending
    oversized headers in HTTP messages. In versions of Squid prior to 6.5 this can be achieved if the
    request_header_max_size or reply_header_max_size settings are unchanged from the default. In Squid version
    6.5 and later, the default setting of these parameters is safe. Squid will emit a critical warning in
    cache.log if the administrator is setting these parameters to unsafe values. Squid will not at this time
    prevent these settings from being changed to unsafe values. Users are advised to upgrade to version 6.5.
    There are no known workarounds for this vulnerability. This issue is also tracked as SQUID-2024:2
    (CVE-2024-25617)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2024:1787");
  script_set_attribute(attribute:"solution", value:
"Update the affected squid, squid-migration-script and / or squid-sysvinit packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-25617");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/11/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:squid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:squid-migration-script");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:squid-sysvinit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/CentOS/release');
if (isnull(os_release) || 'CentOS' >!< os_release) audit(AUDIT_OS_NOT, 'CentOS');
var os_ver = pregmatch(pattern: "CentOS(?: Linux)? release ([0-9]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'CentOS');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '7')) audit(AUDIT_OS_NOT, 'CentOS 7.x', 'CentOS ' + os_ver);

if (!get_kb_item('Host/CentOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'CentOS', cpu);

var pkgs = [
    {'reference':'squid-3.5.20-17.el7_9.10', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'squid-3.5.20-17.el7_9.10', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'squid-migration-script-3.5.20-17.el7_9.10', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'squid-migration-script-3.5.20-17.el7_9.10', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'squid-sysvinit-3.5.20-17.el7_9.10', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'squid-sysvinit-3.5.20-17.el7_9.10', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'}
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
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
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
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'squid / squid-migration-script / squid-sysvinit');
}
