#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2024:0319-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(207881);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/28");

  script_cve_id(
    "CVE-2022-27191",
    "CVE-2022-28948",
    "CVE-2023-28452",
    "CVE-2023-30464",
    "CVE-2024-0874",
    "CVE-2024-22189"
  );

  script_name(english:"openSUSE 15 Security Update : coredns (openSUSE-SU-2024:0319-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote openSUSE 15 host has packages installed that are affected by multiple vulnerabilities as referenced in the
openSUSE-SU-2024:0319-1 advisory.

    Update to version 1.11.3:

      * optimize the performance for high qps (#6767)
      * bump deps
      * Fix zone parser error handling (#6680)
      * Add alternate option to forward plugin (#6681)
      * fix: plugin/file: return error when parsing the file fails (#6699)
      * [fix:documentation] Clarify autopath README (#6750)
      * Fix outdated test (#6747)
      * Bump go version from 1.21.8 to 1.21.11 (#6755)
      * Generate zplugin.go correctly with third-party plugins (#6692)
      * dnstap: uses pointer receiver for small response writer (#6644)
      * chore: fix function name in comment (#6608)
      * [plugin/forward] Strip local zone from IPV6 nameservers (#6635)
    - fixes CVE-2023-30464
    - fixes CVE-2023-28452

    Update to upstream head (git commit #5a52707):

      * bump deps to address security issue CVE-2024-22189
      * Return RcodeServerFailure when DNS64 has no next plugin (#6590)
      * add plusserver to adopters (#6565)
      * Change the log flags to be a variable that can be set prior to calling Run (#6546)
      * Enable Prometheus native histograms (#6524)
      * forward: respect context (#6483)
      * add client labels to k8s plugin metadata (#6475)
      * fix broken link in webpage (#6488)
      * Repo controlled Go version (#6526)
      * removed the mutex locks with atomic bool (#6525)

    Update to version 1.11.2:

      * rewrite: fix multi request concurrency issue in cname rewrite  (#6407)
      * plugin/tls: respect the path specified by root plugin (#6138)
      * plugin/auto: warn when auto is unable to read elements of the directory tree (#6333)
      * fix: make the codeowners link relative (#6397)
      * plugin/etcd: the etcd client adds the DialKeepAliveTime parameter (#6351)
      * plugin/cache: key cache on Checking Disabled (CD) bit (#6354)
      * Use the correct root domain name in the proxy plugin's TestHealthX tests (#6395)
      * Add PITS Global Data Recovery Services as an adopter (#6304)
      * Handle UDP responses that overflow with TC bit with test case (#6277)
      * plugin/rewrite: add rcode as a rewrite option (#6204)

    - CVE-2024-0874: coredns: CD bit response is cached and served later

    - Update to version 1.11.1:

      * Revert plugin/forward: Continue waiting after receiving malformed responses
      * plugin/dnstap: add support for extra field in payload
      * plugin/cache: fix keepttl parsing

    - Update to version 1.11.0:

      * Adds support for accepting DNS connections over QUIC (doq).
      * Adds CNAME target rewrites to the rewrite plugin.
      * Plus many bug fixes, and some security improvements.
      * This release introduces the following backward incompatible changes:
       + In the kubernetes plugin, we have dropped support for watching Endpoint and Endpointslice v1beta,
         since all supported K8s versions now use Endpointslice.
       + The bufsize plugin changed its default size limit value to 1232
       + Some changes to forward plugin metrics.

    - Update to version 1.10.1:

      * Corrected architecture labels in multi-arch image manifest
      * A new plugin timeouts that allows configuration of server listener timeout durations
      * acl can drop queries as an action
      * template supports creating responses with extended DNS errors
      * New weighted policy in loadbalance
      * Option to serve original record TTLs from cache

    - Update to version 1.10.0:

            * core: add log listeners for k8s_event plugin (#5451)
            * core: log DoH HTTP server error logs in CoreDNS format (#5457)
            * core: warn when domain names are not in RFC1035 preferred syntax (#5414)
            * plugin/acl: add support for extended DNS errors (#5532)
            * plugin/bufsize: do not expand query UDP buffer size if already set to a smaller value (#5602)
            * plugin/cache: add cache disable option (#5540)
            * plugin/cache: add metadata for wildcard record responses (#5308)
            * plugin/cache: add option to adjust SERVFAIL response cache TTL (#5320)
            * plugin/cache: correct responses to Authenticated Data requests (#5191)
            * plugin/dnstap: add identity and version support for the dnstap plugin (#5555)
            * plugin/file: add metadata for wildcard record responses (#5308)
            * plugin/forward: enable multiple forward declarations (#5127)
            * plugin/forward: health_check needs to normalize a specified domain name (#5543)
            * plugin/forward: remove unused coredns_forward_sockets_open metric (#5431)
            * plugin/header: add support for query modification (#5556)
            * plugin/health: bypass proxy in self health check (#5401)
            * plugin/health: don't go lameduck when reloading (#5472)
            * plugin/k8s_external: add support for PTR requests (#5435)
            * plugin/k8s_external: resolve headless services (#5505)
            * plugin/kubernetes: make kubernetes client log in CoreDNS format (#5461)
            * plugin/ready: reset list of readiness plugins on startup (#5492)
            * plugin/rewrite: add PTR records to supported types (#5565)
            * plugin/rewrite: fix a crash in rewrite plugin when rule type is missing (#5459)
            * plugin/rewrite: fix out-of-index issue in rewrite plugin (#5462)
            * plugin/rewrite: support min and max TTL values (#5508)
            * plugin/trace : make zipkin HTTP reporter more configurable using Corefile (#5460)
            * plugin/trace: read trace context info from headers for DOH (#5439)
            * plugin/tsig: add new plugin TSIG for validating TSIG requests and signing responses (#4957)
            * core: update gopkg.in/yaml.v3 to fix CVE-2022-28948
            * core: update golang.org/x/crypto to fix CVE-2022-27191
            * plugin/acl: adding a check to parse out zone info
            * plugin/dnstap: support FQDN TCP endpoint
            * plugin/errors: add stacktrace option to log a stacktrace during panic recovery
            * plugin/template: return SERVFAIL for zone-match regex-no-match case

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/2JLUFKCHWHJJ2MQ6XRREF7D4OOWB23V2/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5ffe2594");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-27191");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-28948");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-28452");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-30464");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-0874");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-22189");
  script_set_attribute(attribute:"solution", value:
"Update the affected coredns and / or coredns-extras packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-28948");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-28452");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:coredns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:coredns-extras");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/SuSE/release');
if (isnull(os_release) || os_release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, 'openSUSE');
var _os_ver = pregmatch(pattern: "^SUSE([\d.]+)", string:os_release);
if (isnull(_os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
_os_ver = _os_ver[1];
if (os_release !~ "^(SUSE15\.6)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.6', os_release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + _os_ver, cpu);

var pkgs = [
    {'reference':'coredns-1.11.3-bp156.4.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'coredns-extras-1.11.3-bp156.4.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var _cpu = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (rpm_check(release:_release, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'coredns / coredns-extras');
}
