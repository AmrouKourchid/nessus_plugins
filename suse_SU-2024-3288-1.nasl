#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:3288-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(207376);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/18");

  script_cve_id(
    "CVE-2022-41715",
    "CVE-2022-41723",
    "CVE-2023-45142",
    "CVE-2024-6104"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2024:3288-1");

  script_name(english:"SUSE SLES15 / openSUSE 15 Security Update : golang-github-prometheus-prometheus (SUSE-SU-2024:3288-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / openSUSE 15 host has packages installed that are affected by multiple vulnerabilities as
referenced in the SUSE-SU-2024:3288-1 advisory.

    - Require Go > 1.20 for building

    - Bump go-retryablehttp to version 0.7.7
      (CVE-2024-6104, bsc#1227038)
    - Migrate from `disabled` to `manual` service mode
    - Add0003-Bump-go-retryablehttp.patch
    - Update to 2.45.6 (jsc#PED-3577):
      * Security fixes in dependencies
    - Update to 2.45.5:
      * [BUGFIX] tsdb/agent: ensure that new series get written to WAL
        on rollback.
      * [BUGFIX] Remote write: Avoid a race condition when applying
        configuration.
    - Update to 2.45.4:
      * [BUGFIX] Remote read: Release querier resources before encoding
        the results.
    - Update to 2.45.3:
      * Security fixes in dependencies
      * [BUGFIX] TSDB: Remove double memory snapshot on shutdown.
    - Update to 2.45.2:
      * Security fixes in dependencies
      * [SECURITY] Updated otelhttp to version 0.46.1
        (CVE-2023-45142, bsc#1228556)
      * [BUGFIX] TSDB: Fix PostingsForMatchers race with creating new
        series.
    - Update to 2.45.1:
      * [ENHANCEMENT] Hetzner SD: Support larger ID's that will be used
        by Hetzner in September.
      * [BUGFIX] Linode SD: Cast InstanceSpec values to int64 to avoid
        overflows on 386 architecture.
      * [BUGFIX] TSDB: Handle TOC parsing failures.

    - update to 2.45.0 (jsc#PED-5406):
      * [FEATURE] API: New limit parameter to limit the number of items
        returned by `/api/v1/status/tsdb` endpoint.
      * [FEATURE] Config: Add limits to global config.
      * [FEATURE] Consul SD: Added support for `path_prefix`.
      * [FEATURE] Native histograms: Add option to scrape both classic
        and native histograms.
      * [FEATURE] Native histograms: Added support for two more
        arithmetic operators `avg_over_time` and `sum_over_time`.
      * [FEATURE] Promtool: When providing the block id, only one block
        will be loaded and analyzed.
      * [FEATURE] Remote-write: New Azure ad configuration to support
        remote writing directly to Azure Monitor workspace.
      * [FEATURE] TSDB: Samples per chunk are now configurable with
        flag `storage.tsdb.samples-per-chunk`. By default set to its
        former value 120.
      * [ENHANCEMENT] Native histograms: bucket size can now be limited
        to avoid scrape fails.
      * [ENHANCEMENT] TSDB: Dropped series are now deleted from the WAL
        sooner.
      * [BUGFIX] Native histograms: ChunkSeries iterator now checks if
        a new sample can be appended to the open chunk.
      * [BUGFIX] Native histograms: Fix Histogram Appender
        `Appendable()` segfault.
      * [BUGFIX] Native histograms: Fix setting reset header to gauge
        histograms in seriesToChunkEncoder.
      * [BUGFIX] TSDB: Tombstone intervals are not modified after Get()
        call.
      * [BUGFIX] TSDB: Use path/filepath to set the WAL directory.
    - update to 2.44.0:
      * [FEATURE] Remote-read: Handle native histograms.
      * [FEATURE] Promtool: Health and readiness check of prometheus
        server in CLI.
      * [FEATURE] PromQL: Add `query_samples_total` metric, the total
        number of samples loaded by all queries.
      * [ENHANCEMENT] Storage: Optimise buffer used to iterate through
        samples.
      * [ENHANCEMENT] Scrape: Reduce memory allocations on target
        labels.
      * [ENHANCEMENT] PromQL: Use faster heap method for `topk()` /
        `bottomk()`.
      * [ENHANCEMENT] Rules API: Allow filtering by rule name.
      * [ENHANCEMENT] Native Histograms: Various fixes and
        improvements.
      * [ENHANCEMENT] UI: Search of scraping pools is now
        case-insensitive.
      * [ENHANCEMENT] TSDB: Add an affirmative log message for
        successful WAL repair.
      * [BUGFIX] TSDB: Block compaction failed when shutting down.
      * [BUGFIX] TSDB: Out-of-order chunks could be ignored if the
        write-behind log was deleted.
    - rebase patch 0001-Do-not-force-the-pure-Go-name-resolver.patch
      onto v2.44.0
    - update to 2.43.1
      * [BUGFIX] Labels: Set() after Del() would be ignored, which
        broke some relabeling rules.
    - update to 2.43.0:
      * [FEATURE] Promtool: Add HTTP client configuration to query
        commands.
      * [FEATURE] Scrape: Add `include_scrape_configs` to include
        scrape configs from different files.
      * [FEATURE] HTTP client: Add `no_proxy` to exclude URLs from
        proxied requests.
      * [FEATURE] HTTP client: Add `proxy_from_enviroment` to read
        proxies from env variables.
      * [ENHANCEMENT] API: Add support for setting lookback delta per
        query via the API.
      * [ENHANCEMENT] API: Change HTTP status code from 503/422 to 499
        if a request is canceled.
      * [ENHANCEMENT] Scrape: Allow exemplars for all metric types.
      * [ENHANCEMENT] TSDB: Add metrics for head chunks and WAL folders
        size.
      * [ENHANCEMENT] TSDB: Automatically remove incorrect snapshot
        with index that is ahead of WAL.
      * [ENHANCEMENT] TSDB: Improve Prometheus parser error outputs to
        be more comprehensible.
      * [ENHANCEMENT] UI: Scope `group by` labels to metric in
        autocompletion.
      * [BUGFIX] Scrape: Fix
        `prometheus_target_scrape_pool_target_limit` metric not set
        before reloading.
      * [BUGFIX] TSDB: Correctly update
        `prometheus_tsdb_head_chunks_removed_total` and
        `prometheus_tsdb_head_chunks` metrics when reading WAL.
      * [BUGFIX] TSDB: Use the correct unit (seconds) when recording
        out-of-order append deltas in the
        `prometheus_tsdb_sample_ooo_delta` metric.
    - update to 2.42.0:
      This release comes with a bunch of feature coverage for native
      histograms and breaking changes.
      If you are trying native histograms already, we recommend you
      remove the `wal` directory when upgrading.
      Because the old WAL record for native histograms is not
      backward compatible in v2.42.0, this will lead to some data
      loss for the latest data.
      Additionally, if you scrape 'float histograms' or use recording
      rules on native histograms in v2.42.0 (which writes float
      histograms), it is a one-way street since older versions do not
      support float histograms.
      * [CHANGE] **breaking** TSDB: Changed WAL record format for the
        experimental native histograms.
      * [FEATURE] Add 'keep_firing_for' field to alerting rules.
      * [FEATURE] Promtool: Add support of selecting timeseries for
        TSDB dump.
      * [ENHANCEMENT] Agent: Native histogram support.
      * [ENHANCEMENT] Rules: Support native histograms in recording
        rules.
      * [ENHANCEMENT] SD: Add container ID as a meta label for pod
        targets for Kubernetes.
      * [ENHANCEMENT] SD: Add VM size label to azure service
        discovery.
      * [ENHANCEMENT] Support native histograms in federation.
      * [ENHANCEMENT] TSDB: Add gauge histogram support.
      * [ENHANCEMENT] TSDB/Scrape: Support FloatHistogram that
        represents buckets as float64 values.
      * [ENHANCEMENT] UI: Show individual scrape pools on /targets
        page.
    - update to 2.41.0:
      * [FEATURE] Relabeling: Add keepequal and dropequal relabel
        actions.
      * [FEATURE] Add support for HTTP proxy headers.
      * [ENHANCEMENT] Reload private certificates when changed on disk.
      * [ENHANCEMENT] Add max_version to specify maximum TLS version in
        tls_config.
      * [ENHANCEMENT] Add goos and goarch labels to
        prometheus_build_info.
      * [ENHANCEMENT] SD: Add proxy support for EC2 and LightSail SDs.
      * [ENHANCEMENT] SD: Add new metric
        prometheus_sd_file_watcher_errors_total.
      * [ENHANCEMENT] Remote Read: Use a pool to speed up marshalling.
      * [ENHANCEMENT] TSDB: Improve handling of tombstoned chunks in
        iterators.
      * [ENHANCEMENT] TSDB: Optimize postings offset table reading.
      * [BUGFIX] Scrape: Validate the metric name, label names, and
        label values after relabeling.
      * [BUGFIX] Remote Write receiver and rule manager: Fix error
        handling.
    - update to 2.40.7:
      * [BUGFIX] TSDB: Fix queries involving negative buckets of native
        histograms.
    - update to 2.40.5:
      * [BUGFIX] TSDB: Fix queries involving native histograms due to
        improper reset of iterators.
    - update to 2.40.3:
      * [BUGFIX] TSDB: Fix compaction after a deletion is called.
    - update to 2.40.2:
      * [BUGFIX] UI: Fix black-on-black metric name color in dark mode.
    - update to 2.40.1:
      * [BUGFIX] TSDB: Fix alignment for atomic int64 for 32 bit
        architecture.
      * [BUGFIX] Scrape: Fix accept headers.
    - update to 2.40.0:
      * [FEATURE] Add experimental support for native histograms.
        Enable with the flag --enable-feature=native-histograms.
      * [FEATURE] SD: Add service discovery for OVHcloud.
      * [ENHANCEMENT] Kubernetes SD: Use protobuf encoding.
      * [ENHANCEMENT] TSDB: Use golang.org/x/exp/slices for improved
        sorting speed.
      * [ENHANCEMENT] Consul SD: Add enterprise admin partitions. Adds
        __meta_consul_partition label. Adds partition config in
        consul_sd_config.
      * [BUGFIX] API: Fix API error codes for /api/v1/labels and
        /api/v1/series.
    - update to 2.39.1:
      * [BUGFIX] Rules: Fix notifier relabel changing the labels on
        active alerts.
    - update to 2.39.0:
      * [FEATURE] experimental TSDB: Add support for ingesting
        out-of-order samples. This is configured via
        out_of_order_time_window field in the config file; check config
        file docs for more info.
      * [ENHANCEMENT] API: /-/healthy and /-/ready API calls now also
        respond to a HEAD request on top of existing GET support.
      * [ENHANCEMENT] PuppetDB SD: Add __meta_puppetdb_query label.
      * [ENHANCEMENT] AWS EC2 SD: Add __meta_ec2_region label.
      * [ENHANCEMENT] AWS Lightsail SD: Add __meta_lightsail_region
        label.
      * [ENHANCEMENT] Scrape: Optimise relabeling by re-using memory.
      * [ENHANCEMENT] TSDB: Improve WAL replay timings.
      * [ENHANCEMENT] TSDB: Optimise memory by not storing unnecessary
        data in the memory.
      * [ENHANCEMENT] TSDB: Allow overlapping blocks by default.
        --storage.tsdb.allow-overlapping-blocks now has no effect.
      * [ENHANCEMENT] UI: Click to copy label-value pair from query
        result to clipboard.
      * [BUGFIX] TSDB: Turn off isolation for Head compaction to fix a
        memory leak.
      * [BUGFIX] TSDB: Fix 'invalid magic number 0' error on Prometheus
        startup.
      * [BUGFIX] PromQL: Properly close file descriptor when logging
        unfinished queries.
      * [BUGFIX] Agent: Fix validation of flag options and prevent WAL
        from growing more than desired.
    - update to 2.38.0:
      * [FEATURE]: Web: Add a /api/v1/format_query HTTP API endpoint
        that allows pretty-formatting PromQL expressions.
      * [FEATURE]: UI: Add support for formatting PromQL expressions in
        the UI.
      * [FEATURE]: DNS SD: Support MX records for discovering targets.
      * [FEATURE]: Templates: Add toTime() template function that
        allows converting sample timestamps to Go time.Time values.
      * [ENHANCEMENT]: Kubernetes SD: Add
        __meta_kubernetes_service_port_number meta label indicating the
        service port number.
      * [ENHANCEMENT]: Kubernetes SD: Add
        __meta_kubernetes_pod_container_image meta label indicating the
        container image.
      * [ENHANCEMENT]: PromQL: When a query panics, also log the query
        itself alongside the panic message.
      * [ENHANCEMENT]: UI: Tweak colors in the dark theme to improve
        the contrast ratio.
      * [ENHANCEMENT]: Web: Speed up calls to /api/v1/rules by avoiding
        locks and using atomic types instead.
      * [ENHANCEMENT]: Scrape: Add a no-default-scrape-port feature
        flag, which omits or removes any default HTTP (:80) or HTTPS
        (:443) ports in the target's scrape address.
      * [BUGFIX]: TSDB: In the WAL watcher metrics, expose the
        type='exemplar' label instead of type='unknown' for exemplar
        records.
      * [BUGFIX]: TSDB: Fix race condition around allocating series IDs
        during chunk snapshot loading.

    - Remove npm_licenses.tar.bz2 during 'make clean'

    - Remove web-ui archives during 'make clean'.

      * [SECURITY] CVE-2022-41715: Limit memory used by parsing regexps
        (bsc#1204023).
    - Fix uncontrolled resource consumption by updating Go to version
      1.20.1 (CVE-2022-41723, bsc#1208298)

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204023");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208298");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227038");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228556");
  # https://lists.suse.com/pipermail/sle-security-updates/2024-September/019440.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e8def975");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-41715");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-41723");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-45142");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-6104");
  script_set_attribute(attribute:"solution", value:
"Update the affected firewalld-prometheus-config and / or golang-github-prometheus-prometheus packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-6104");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:golang-github-prometheus-prometheus");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
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
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES|SUSE)") audit(AUDIT_OS_NOT, "SUSE / openSUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+|SUSE([\d.]+))", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE / openSUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES15|SUSE15\.5|SUSE15\.6)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(4|5|6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP4/5/6", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'golang-github-prometheus-prometheus-2.45.6-150100.4.20.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Proxy-release-4.3']},
    {'reference':'firewalld-prometheus-config-0.1-150100.4.20.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'golang-github-prometheus-prometheus-2.45.6-150100.4.20.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'firewalld-prometheus-config-0.1-150100.4.20.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'golang-github-prometheus-prometheus-2.45.6-150100.4.20.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'golang-github-prometheus-prometheus-2.45.6-150100.4.20.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'golang-github-prometheus-prometheus-2.45.6-150100.4.20.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.6']}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (exists_check) {
      var check_flag = 0;
      foreach var check (exists_check) {
        if (!rpm_exists(release:_release, rpm:check)) continue;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'firewalld-prometheus-config / golang-github-prometheus-prometheus');
}
