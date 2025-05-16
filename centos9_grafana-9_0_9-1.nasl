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
  script_id(191236);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/26");

  script_cve_id(
    "CVE-2021-23648",
    "CVE-2021-39226",
    "CVE-2021-43813",
    "CVE-2021-44716",
    "CVE-2022-1705",
    "CVE-2022-1962",
    "CVE-2022-21673",
    "CVE-2022-21698",
    "CVE-2022-21702",
    "CVE-2022-21703",
    "CVE-2022-21713",
    "CVE-2022-28131",
    "CVE-2022-30630",
    "CVE-2022-30631",
    "CVE-2022-30632",
    "CVE-2022-30633",
    "CVE-2022-30635",
    "CVE-2022-31107",
    "CVE-2022-32148",
    "CVE-2022-35957"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/09/15");

  script_name(english:"CentOS 9 : grafana-9.0.9-1.el9");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing one or more security updates for grafana.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 9 host has a package installed that is affected by multiple vulnerabilities as referenced in the
grafana-9.0.9-1.el9 build changelog.

  - XSS (CVE-2021-23648)

  - Grafana is an open source data visualization platform. In affected versions unauthenticated and
    authenticated users are able to view the snapshot with the lowest database key by accessing the literal
    paths: /dashboard/snapshot/:key, or /api/snapshots/:key. If the snapshot public_mode configuration
    setting is set to true (vs default of false), unauthenticated users are able to delete the snapshot with
    the lowest database key by accessing the literal path: /api/snapshots-delete/:deleteKey. Regardless of the
    snapshot public_mode setting, authenticated users are able to delete the snapshot with the lowest
    database key by accessing the literal paths: /api/snapshots/:key, or /api/snapshots-delete/:deleteKey. The
    combination of deletion and viewing enables a complete walk through all snapshot data while resulting in
    complete snapshot data loss. This issue has been resolved in versions 8.1.6 and 7.5.11. If for some reason
    you cannot upgrade you can use a reverse proxy or similar to block access to the literal paths:
    /api/snapshots/:key, /api/snapshots-delete/:deleteKey, /dashboard/snapshot/:key, and /api/snapshots/:key.
    They have no normal function and can be disabled without side effects. (CVE-2021-39226)

  - directory traversal vulnerability for *.md files (CVE-2021-43813)

  - net/http: limit growth of header canonicalization cache (CVE-2021-44716)

  - net/http: improper sanitization of Transfer-Encoding header (CVE-2022-1705)

  - go/parser: stack exhaustion in all Parse* functions (CVE-2022-1962)

  - Forward OAuth Identity Token can allow users to access some data sources (CVE-2022-21673)

  - client_golang is the instrumentation library for Go applications in Prometheus, and the promhttp package
    in client_golang provides tooling around HTTP servers and clients. In client_golang prior to version
    1.11.1, HTTP server is susceptible to a Denial of Service through unbounded cardinality, and potential
    memory exhaustion, when handling requests with non-standard HTTP methods. In order to be affected, an
    instrumented software must use any of `promhttp.InstrumentHandler*` middleware except `RequestsInFlight`;
    not filter any specific methods (e.g GET) before middleware; pass metric with `method` label name to our
    middleware; and not have any firewall/LB/proxy that filters away requests with unknown `method`.
    client_golang version 1.11.1 contains a patch for this issue. Several workarounds are available, including
    removing the `method` label name from counter/gauge used in the InstrumentHandler; turning off affected
    promhttp handlers; adding custom middleware before promhttp handler that will sanitize the request method
    given by Go http.Request; and using a reverse proxy or web application firewall, configured to only allow
    a limited set of methods. (CVE-2022-21698)

  - XSS vulnerability in data source handling (CVE-2022-21702)

  - CSRF vulnerability can lead to privilege escalation (CVE-2022-21703)

  - IDOR vulnerability can lead to information disclosure (CVE-2022-21713)

  - encoding/xml: stack exhaustion in Decoder.Skip (CVE-2022-28131)

  - io/fs: stack exhaustion in Glob (CVE-2022-30630)

  - compress/gzip: stack exhaustion in Reader.Read (CVE-2022-30631)

  - path/filepath: stack exhaustion in Glob (CVE-2022-30632)

  - encoding/xml: stack exhaustion in Unmarshal (CVE-2022-30633)

  - encoding/gob: stack exhaustion in Decoder.Decode (CVE-2022-30635)

  - OAuth account takeover (CVE-2022-31107)

  - net/http/httputil: NewSingleHostReverseProxy (CVE-2022-32148)

  - Escalation from admin to server admin when auth proxy is used (rhbz#2125530) (CVE-2022-35957)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kojihub.stream.centos.org/koji/buildinfo?buildID=25085");
  script_set_attribute(attribute:"solution", value:
"Update the CentOS 9 Stream grafana package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-21703");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:centos:centos:9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:grafana");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
if ('aarch64' >!< cpu && 's390' >!< cpu && 'x86_64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'CentOS', cpu);

var pkgs = [
    {'reference':'grafana-9.0.9-1.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'grafana');
}
