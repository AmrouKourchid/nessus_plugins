#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-647.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149569);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/01");

  script_cve_id(
    "CVE-2018-18836",
    "CVE-2018-18837",
    "CVE-2018-18838",
    "CVE-2018-18839"
  );

  script_name(english:"openSUSE Security Update : netdata (openSUSE-2021-647)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for netdata fixes the following issues :

  - Update to 1.29.3 Release v1.29.3 is a patch release to     improve the stability of the Netdata Agent. We     discovered a bug that when proc.plugin attempts to     collect the operstate parameter for a virtual network     interface. If the chart is obsoleted, the Netdata Agent     crashes. This release also contains additional bug fixes     and improvements. Bug fixes

  - Fix proc.plugin to invalidate RRDSETVAR pointers on     obsoletion.

  - Update to 1.29.2 Release v1.29.2 is a patch release to     improve the stability of the Netdata Agent. We     discovered that an improvement introduced in v1.29.0     could inadvertently set all os_* host labels to unknown,     which could affect users who leverage these host labels     to organize their nodes, deploy health entities, or     export metrics to external time-series databases. This     bug has been fixed. This release also contains     additional bug fixes and improvements. Improvements

  - Make the Opsgenie API URL configurable.

  - Add k8s_cluster_id host label.

  - Enable apps.plugin aggregation debug messages.

  - Add configuration parameter to disable stock alarms.

  - Add ACLK proxy setting as host label.

  - Add freeswitch to apps_groups.conf.

  - Simplify thread creation and remove unnecessary     variables in the eBPF plugin. Bug fixes

  - Fix the context filtering on the data query endpoint.

  - Fix container/host detection in the system-info.sh     script.

  - Add a small delay to the ipv4_tcp_resets alarms.

  - Fix collecting operstate for virtual network interfaces.

  - Fix sendmail unrecognized option F error.

  - Fix so that raw binary data should never be printed.

  - Change KSM memory chart type to stacked.

  - Allow the REMOVED alarm status via ACLK if the previous     status was WARN/CRIT.

  - Reduce excessive logging in the ACLK.

  - Changes in 1.29.1 Release v1.29.1 is a hotfix release to     address a crash in the Netdata Agent. A locking bug in     one of the internal collectors in Netdata could cause it     to crash during shutdown in a way that would result in     the Netdata Agent taking an excessively long time to     exit. Bug fixes

  - Fix crash during shutdown of cgroups internal plugin.

  - Update to 1.29.0 (go.d.plugin 0.27.0) The v1.29.0     release of the Netdata Agent is a maintenance release     that brings incremental but necessary improvements that     make your monitoring experience more robust. We've     pushed improvements and bug fixes to the installation     and update scripts, enriched our library of collectors,     and focused on fixing bugs reported by the community. At     a glance Netdata now collects and meaningfully organizes     metrics from both the Couchbase JSON document database     and the nginx-module-vts module for exposing metrics     about NGINX virtual hosts. We've also migrated more     collectors from Python to Go in our continued efforts to     make data collection faster and more robust. The newest     effort includes our Redis, Pika, and Energi Core Wallet     collectors. On the dashboard, we improved the     responsiveness of panning forward and backward through     historical metrics data by preventing unnecessary     updates and reducing the number of calls. The charts     should also now immediately update when you stop     panning. Improvements

  - Reduce the number of alarm updates on ACLK.

  - Remove unused entries from structures.

  - Improve the retry/backoff during claiming.

  - Support multiple chart label keys in data queries.

  - Truncate excessive information from titles for apps and     cgroups collectors.

  - Use mguid instead of hostname in the ACLK collector     list.

  - Cleanup and minor fixes to eBPF collector.

  - Add _is_k8s_node label to the host labels.

  - Move ACLK into a legacy subfolder.

  - Exclude autofs by default in the diskspace plugin.

  - Mark internal functions as static in health code.

  - Remove unused struct in health code.

  - Add support for per series styling for dygraphs.
    Dashboard

  - Fix minor vulnerability alert by updating socket-io     dependency.

  - Fix dygraph panning responsiveness, chart heights and     performance improvements.

  - Make legend position configurable. Collectors

  - Add Go version of the redis collector.

  - Add Go version of the pika collector.

  - Add Go version of the energis collector.

  - Add a new nginxvts collector.

  - Add a new couchbase collector.

  - Add Traefik v2 to the prometheus collector default     configuration.

  - Add an expected_prefix configuration option to the     prometheus collector.

  - Add patterns support to the filecheck collector. Bug     fixes

  - Fix container detection from systemd-detect-virt.

  - Fix handling of TLS config so that cURL works in all     cases.

  - Fix disconnect message sent via ACLK on agent shutdown

  - Fix prometheus remote write header

  - Fix values in Prometheus export for metrics, collected     by the Prometheus collector

  - Fix handling spaces in labels values in the Prometheus     collector

  - Fix mysql.slave_status alarm for go mysql collector

  - Make mdstat_mismatch_cnt alarm less strict

  - Dispatch cgroup discovery into another thread

  - Fix data source option for Prometheus web API in     exporting configuration

  - Fix anomalies collector custom model bug

  - Fix broken dbengine stress tests.

  - Fix segmentation fault in the agent

  - Fix memory allocation when computing standard deviation

  - Fix temperature parsing in the hddtemp collector

  - Fix postgres password bug and change default config

  - Add handling 'yes' and 'no' and flexible space match in     the python.d/fail2ban plugin

  - Fix spelling mistakes in the Python plugin and     documentation.

  - Update to v1.28 Release v1.28.0 is a hotfix release to     address a deadlock in the Netdata Agent. If the     Agent-Cloud link (ACLK) connection drops and the Agent     fails to queue an on_connect message, it also fails to     properly release a lock in the web server thread.

  - Enable additional dependencies (gprc, json, libcurl,     libelf, libwebsockets, protobuf, snappy, xenstat, yajl)

  - Update to v1.27.0 (go.d.plugin 0.26.2) The v1.27.0     release of the Netdata Agent brings dramatic     improvements to long-term metrics storage via the     database engine, and new dashboard features like a time     & date picker for visualizing precise timeframes. Two     new collectors bring incredible new value to existing     features, including a bit of machine learning magic.
    This release contains 8 new collectors, 1 new     notification method (2 others enhanced), 54     improvements, 41 documentation updates, and 58 bug     fixes. Improvements

  - Add labels for Kubernetes pods and containers.

  - Add plugin and module health entities.

  - Migrate the metadata log to SQLite.

  - Add an extent cache to the database engine.

  - Added new data query option allow_past. Netdata Cloud

  - Add the ability to query child nodes by their GUID.

  - Add child availability messages to the ACLK.

  - Add a metric showing how long a query spent in the     queue.

  - Completely hide the SSO iframe. Collectors

  - Add alarms obsoletion and disable alarms collector by     default.

  - Add calls for tcp_sendmsg, tcp_retransmit_skb,     tcp_cleanup_rcv, udp_sendmsg, udp_recvmsg functions     charts to the eBPF collector.

  - Add two more insignificant warnings to suppress in     anomalies collector.

  - Add the number of allocated/stored objects within each     storage to the varnish collector.

  - Add a wireless statistics collector.

  - Add support for MSE (Massive Storage Engine) to the     varnish collector.

  - Remove remove crit from unmatched alarms in the web_log     collector.

  - Add GPU key metrics (nvidia_smi collector) to     dashboard_info.js.

  - Add allocated space metrics to the oracledb collector.

  - Restructure the eBPF collector to improve usability.

  - Add an anomaly detection collector.

  - Add a Netdata alarms collector.

  - Add a configuration option to exclude users with zero     memory allocated to the nvidia_smi collector.

  - Add per queue charts to the rabbitmq collector.

  - Add support for HBA drives to the hpssa collector.

  - Update the cgroups collector default filtering by adding     pod level cgroups.

  - Add a Go version of the CouchDB collector (couchdb).

  - Add collecting HTTP method per URL pattern (url_pattern     option) to the web_log collector.

  - Add custom time fields feature to the web_log collector.

  - Add a Go version of the PowerDNS Authoritative     Nameserver collector (powerdns).

  - Add a Go version of the PowerDNS Recursor collector     (powerdns_recursor).

  - Add a Go version of the PowerDNS DNSdist collector     (dnsdist).

  - Add a Dnsmasq DNS Forwarder collector (dnsmasq).

  - Add collecting directories size to the filecheck     collector.

  - Add old systemd versions support to the systemdunits     collector.

  - Add unmatched lines logging to the web_log collector.
    Notifications

  - Add API V2 support to the PagerDuty health integration.

  - Add threads support to the Google Hangouts health     integration.

  - Add a Opsgenie health integration. Exporting

  - Add HTTP and HTTPS support to the simple exporting     connector. Packaging/installation

  - Update React dashboard v2.11.

  - Update go.d.plugin version to v0.26.2.

  - Update eBPF collector to 0.4.9.

  - Add ability to use system libwebsockets instead of     bundled version.

  - Update the version of libJudy that we bundle to     1.0.5-netdata2. Bug fixes

  - Fix crash in the eBPF plugin by initializing variables.

  - Fix sending chart definition on every data collection in     alarms collector.

  - Fix a lock check.

  - Fix issue with chart metadata sent multiple times over     ACLK.

  - Fix a buffer overflow when extracting information from a     streaming connection.

  - Fix hostname configuration in the exporting engine.

  - Fix units and data source exporting options.

  - Fix exporting config.

  - Fix health by disabling used_file_descriptors alarm.

  - Fix GPU data filtering in the nvidia_smi collector.

  - Fix username resolution in the nvidia_smi collector.

  - Fix compilation with HTTPS disabled.

  - Fix hostname when syslog is used in syslog health     integration.

  - Fix streaming buffer size.

  - Fix database endless loop when cleaning obsolete charts.

  - Disable chart obsoletion code for archived chart     creation.

  - Fix Prometheus remote write exporter so that it doesn't     stop when data is not available for dimension     formatting.

  - Fix memory calculation by moving shared from cached to     used dimension.

  - Fix parsing in the libreswan collector.

  - Fix an infinite loop in the statsd plugin

  - Disregard host tags configuration pointer.

  - Fix platform dependent printf format.

  - Fix cgroups collector resolving container names in k8s.

  - Fix python.d plugin runtime chart creation.

  - Fix race condition in rrdset_first_entry_t() and     rrdset_last_entry_t().

  - Fix the data endpoint so that the context param is     correctly applied to children.

  - Fix Coverity errors (CID 364045,364046).

  - Fix the elasticsearch_last_collected alarm.

  - Fix spelling error in xenstat.plugin.

  - Fix chart filtering.

  - Fix libnetdata headers to be compatible with C++.

  - Fix registry responses to remove caching.

  - Fix eBPF memory management.

  - Fix overlapping memory issue.

  - Fix response and upstream response time histogram charts     in the web_log collector.

  - Fix logs timestamps always in UTC issue in the     go.d.plugin

  - Fix collecting slave status for MariaDB v10.2.0- in the     mysql collector

  - Fix cumulative_stats configuration option in the unbound     collector

  - Fix parsing configuration file (respect     'include-toplevel' directive) in unbound collector

  - Fix handling charts with type.id >= 200 (netdata limit)     in go.d.plugin

  - Fix parsing version query response in the mysql     collector

  - Fix Netsplits chart dimensions algorithm in the the     vernemq collector.

  - Fix a typo in dashboard_info.js for VerneMQ.

  - Allow go plugin to build for Tumbleweed

  - Fix RPM file list

  - Update to v1.26.0 (go.d.plugin 0.23.0): Improvements

  - Add the ability to send Agent alarm notifications to     StackPulse

  - Add a way to get build configuration info from the Agent

  - Add chart for churn rates to python.d/rabbitmq

  - Add failed dim to the connection_fails alarm in the     Portcheck alarm

  - Improve the data query when using the context parameter

  - Add a context parameter to the data endpoint (Netdata     Cloud)

  - Change default ACLK query thread count

  - Remove leading whitespace before JSON in ACLK

  - Allow using libwebsockets without SOCKS5

  - Add information about Cloud disabled status to -W     buildinfo (Collectors)

  - Update go.d.plugin version to v0.23.0

  + Add new filecheck collector

  + Add new systemd unit state collector

  + Add new ISC DHCP collector (Dashboard)

  - Add missing period in Netdata dashboard Bug Fixes

  - Fix systemd comment syntax

  - Fix file descriptor leak in Infiniband collector     (proc.plugin)

  - Fix the data endpoint to prioritize chart over context     if both are present

  - Fix cleanup of obsolete charts

  - Fix build for the AWS Kinesis exporting connector

  - Fix gauges for go.d.plugin/web_log collector

  - Fix locking order to address CID_362348

  - Fix chart's last accessed time during context queries

  - Fix resource leak in case of malformed request to     Netdata Cloud

  - Move edit-config to libexeddir

  - Fix conf.d path in edit-config

  - Fix building with go support on openSUSE 15.2

  - Build with python3

  - Protect /etc/netdata as it contains sensitive data     (passwords, secrets)

  - update to 1.25.0: Improvements

  - Add code to release memory used by the global GUID map     (#9729, @stelfrag)

  - Add check for spurious wakeups Netdata Cloud

  - Add v2 HTTP message with compression to ACLK (#9895,     @underhood)

  - Add version negotiation to ACLK (#9819, @underhood)

  - Add claimed_id for child nodes streamed to their parents     (#9804, @underhood)

  - Update netdata-installer.sh to enable Netdata Cloud     support in macOS (#9360, @mrbrutti) Collectors

  - Update go.d.plugin version to v0.22.0 (#9898, @ilyam8)

  - Add support for IP ranges to Python-based isc_dhcpd     collector (#9755, @vsc55)

  - Add Network viewer charts to ebpf.plugin (#9591,     @thiagoftsm)

  - Add collecting active processes limit on Linux systems     (#9843, @Ancairon)

  - Improve eBPF plugin by removing unnecessary debug     messages (#9754, @thiagoftsm)

  - Add CAP_SYS_CHROOT for netdata service to read LXD     network interfaces (#9726, @vlvkobal)

  - Add collecting maxmemory to python.d/redis (#9767,     @ilyam8)

  - Add option for multiple storage backends in     python.d/varnish (#9668, @florianmagnin)

  - Dashboard

  - Update dashboard v1.4.2 (#9837, @jacekkolasa)

  - Lots of documentation improvements and bug fixes

  - update to 1.24.0 :

  - The v1.24.0 release of the Netdata Agent brings     enhancements to the breadth of metrics we collect with a     new generic Prometheus/OpenMetrics collector and     enhanced storage and querying with a new multi-host     database mode.

  - Add generic Prometheus/OpenMetrics collector (#9644,     @ilyam8)

  - Add locking between different collectors for the same     application, implemented in different technologies     (#9584, @vlvkobal), (#9564, @ilyam8)

  - Implement multihost database (#9556, @stelfrag)

  - Add alarms for FreeBSD interface errors (#8340,     @lassebm)

  - Many bugfixes, see     https://github.com/netdata/netdata/releases/tag/v1.24.0

  - Update to v1.23.2 :

  - Fixed a buffer overrun vulnerability in Netdata's JSON     parsing code. This vulnerability could be used to crash     Agents remotely, and in some circumstances, could be     used in an arbitrary code execution (ACE) exploit.
    Improvements :

  - Add support for multiple ACLK query processing threads

  - Add Infiniband monitoring to collector proc.plugin

  - Change the HTTP method to make the IPFS collector     compatible with 0.5.0+

  - Add support for returning headers using python.d's     UrlService Bug fixes :

  - Fix vulnerability in JSON parsing

  - Fixed stored number accuracy

  - Fix transition from archived to active charts not     generating alarms

  - Fix PyMySQL library to respect my.cnf parameter

  - Remove health from archived metrics

  - Update exporting engine to read the prefix option from     instance config sections

  - Fix display error in Swagger API documentation

  - Wrap exporting engine header definitions in compilation     conditions

  - Improve cgroups collector to autodetect unified cgroups

  - Fix CMake build failing if ACLK is disabled

  - Fix now_ms in charts.d collector to prevent     tc-qos-helper crashes

  - Fix python.d crashes by adding a lock to stdout write     function

  - Fix an issue with random crashes when updating a chart's     metadata on the fly

  - Fix ACLK protocol version always parsed as 0

  - Fix the check condition for chart name change

  - Fix the exporting engine unit tests

  - Fix a Coverity defect for resource leaks

  - update to v1.23.1 :

  - Lots of fixes and improvements, please see CHANGELOG.md

  - update go.d plugin to v0.19.2

  - Update to v1.22.1: Bug fixes :

  - Fixed the latency issue on the ACLK and suppress the     diagnostics.

  - Restored old semantics of 'netdata -W set' command.

  - Removed check for old alarm status.

  - Changes for v1.22.0: Breaking Changes :

  - The previous iteration of Netdata Cloud, accessible     through various Sign in and Nodes view (beta) buttons on     the Agent dashboard, is deprecated in favor of the new     Cloud experience.

  - Our old documentation site (docs.netdata.cloud) was     replaced with Netdata Learn. All existing backlinks     redirect to the new site.

  - Our localization project is no longer actively     maintained. We're grateful for the hard work of its     contributors. Improvements :

  - Netdata Cloud :

  - Enabled support for Netdata Cloud.

  - Added TTL headers to ACLK responses.

  - Improved the thread exit fixes in #8750.

  - Improved ACLK reconnection sequence.

  - Improved ACLK memory management and shutdown sequence.

  - Added session-id to ACLK using connect timestamp.

  - Collectors :

  - Improved the index size for the eBPF collector.

  - Added health alarm templates for the whoisquery     collector.

  - Added a whoisquery collector.

  - Removed an automatic restart of apps.plugin.

  - Exporting :

  - Enabled internal statistics for the exporting engine in     the Agent dashboard.

  - Implemented a Prometheus exporter web API endpoint.

  - Notifications :

  - Added a certificate revocation alarm for the x509check     collector.

  - Added the ability to send Agent alarm notifications to     Dynatrace.

  - Other :

  - Updated main copyright and links for the year 2020 in     daemon help output.

  - Moved bind to to [web] section and update     netdata.service.v235.in to sync it with recent changes.

  - Put old dashboard behind a prefix instead of using a     script to switch.

  - Enabled the truthy rule in yamllint.

  - Added Borg backup, Squeezebox servers, Hiawatha web     server, and Microsoft SQL to apps.plugin so that it can     appropriately group them by type of service.

  - Bug fixes :

  - Fixed mdstat failed devices alarm.

  - Fixed rare race condition in old Cloud iframe.

  - Removed no-clear-notification options from portcheck     health templates.

  - Fixed old URLs to silence Netlify's mixed content     warnings.

  - Fixed master streaming fatal exits.

  - Fixed email authentiation to Cloud/Nodes View.

  - Fixed non-escaped characters in private registry URLs.

  - Fixed crash when shutting down an Agent with the ACLK     disabled.

  - Fixed status checks for UPS devices using the apcupsd     collector.

  - Fixed alarm notification script by adding a check to the     Dynatrace notification method.

  - Fixed threads_creation_rate chart context in the     python.d MySQL collector.

  - Fixed sudo check in charts.d libreswan collector to     prevent daily security notices.

  - Update to v1.21.1: Release v1.21.1 is a hotfix release     to improve the performance of the new React dashboard,     which was merged and enabled by default in v1.21.0. The     React dashboard shipped in v1.21.0 did not properly     freeze charts that were outside of the browser's     viewport. If a user who loaded many charts by scrolling     through the dashboard, charts outside of their browser's     viewport continued updating. This excess of chart     updates caused all charts to update more slowly than     every second. v1.21.1 includes improvements to the way     the Netdata dashboard freezes, maintains state, and     restores charts as users scroll.

  - Update to v1.21.0 (go.d.plugin v0.18.0): Improvements :

  - Extended TLS support for 1.3.

  - Switched to the React dashboard code as the default     dashboard.

  - Collectors :

  - Added a new Pulsar collector.

  - Added a new VerneMQ collector.

  - Added high precision timer support for plugins such as     idlejitter.

  - Added an alarm to the dns_query collector that detects     DNS query failure.

  - Added the ability to get the pod name from cgroup with     kubectl in bare-metal deployments.

  - Added the ability to connect to non-admin user IDs for a     Ceph storage cluster.

  - Added connections (backend) usage to Postgres     monitoring.

  - Exporting :

  - Added a MongoDB connector to the exporting engine.

  - Added a Prometheus Remote Write connector to the     exporting engine.

  - Added an AWS Kinesis connector to the exporting engine.
    Bug fixes :

  - Removed notifications from the dashboard and fixed the     /default.html route.

  - Fixed help-tooltips styling, private registry node     deletion, and the right-hand sidebar 'jumping' on     document clicks.

  - Fixed errors reported by Coverity.

  - Fixed broken pipe ignoring in apps.plugin.

  - Fixed the bytespersec chart context in the Python Apache     collector.

  - Fixed charts.d.plugin to exit properly during Netdata     service restart

  - Fixed minimist dependency vulnerability.

  - Fixed how SimpleService truncates Python module names.

  - Added proper prefix to Python module names during     loading.

  - Fixed the flushing error threshold with the database     engine.

  - Fixed memory leak for host labels streaming from slaves     to master.

  - Fixed streaming scaling.

  - Fixed missing characters in kernel version field by     encoding slave fields.

  - Fixed Ceph collector to get osd_perf_infos in versions     14.2 and higher.

  - Removed extraneous commas from chart information in     dashboard.

  - Removed tmem collection from xenstat_plugin to allow     Netdata on Xen 4.13 to compile successfully.

  - Restricted messages to Google Analytics.

  - Fixed Python 3 dict access in OpenLDAP collector module.

  - Update to v1.20.0 (go.d.plugin v0.15.0) Breaking Changes :

  - Removed deprecated bash collectors apache, cpu_apps,     cpufreq, exim, hddtemp, load_average, mem_apps, mysql,     nginx, phpfpm, postfix, squid, tomcat. If you were still     using one of these collectors with custom     configurations, you can find the new collector that     replaces it in the supported collectors list.
    Improvements :

  - Host labels :

  + Added support for host labels

  + Improved the monitored system information detection.
    Added CPU freq & cores, RAM and disk space.

  + Started distinguishing the monitored system's (host)     OS/Kernel etc. from those of the docker container's

  + Started creating host labels from collected system info

  + Started passing labels and container environment     variables via the streaming protocol

  + Started sending host labels via exporting connectors

  + Added label support to alarm definitions and started     recording them in alarm logs

  + Added support for host labels to the API responses

  + Added configurable host labels to netdata.conf

  + Added kubernetes labels

  - New collectors :

  + eBPF kernel collector

  + CockroachDB

  + squidlog: squid access log parser

  - Collector improvements :

  + apps.plugin: Created dns group, improved database group,     improved ceph & samba groups

  + varnish: Added SMF metrics (cache on disk)

  + phpfpm: Fixed per process chart titles and readme

  + python.d: Formatted the code in all modules

  + node.d/snmp: - Added snmpv3 support, formatted the code     in snmp.node.js

  + cgroups: Improved LXC monitoring by filtering out     irrelevant LXC cgroups

  + litespeed: Added support for different .rtreport format

  + proc.plugin: Added pressure stall information

  + sensors: Improved collection logic

  + proc: Started monitoring network interface speed,     duplex, operstate

  + smartd_log: Fixed the setting in the reallocated sectors     count, by setting ATTR5 chart algorithm to absolute

  + nvidia-smi: Allow executing nvidia-smi in normal instead     of loop mode

  + wmi: collect logon metrics, collect logical_disk disk     latency metrics

  + weblog: handle MKCOL, PROPFIND, MOVE, SEARCH http     request methods

  + scaleio: storage pools and sdcs metrics

  - Exporting engine :

  + Implemented the main flow for the Exporting Engine

  - Streaming :

  + Add versioning to the streaming protocol

  - Installation/Packages :

  + Improved the systemd service files, by removing     unecessary ExecStartPre lines and moving global options     to netdata.conf

  - Privacy :

  + Added support for opting out of telemetry via the     DO_NOT_TRACK environment variable (telemetry is disabled     by default on openSUSE)

  - Other :

  + Preparations for the next netdata cloud release. Added     custom libmosquitto, netdata-cli and other     prerequisites.

  + Applied linter fixes in shell scripts

  + Started supporting -fno-common in CFLAGS

  + Completely removed the unbound python collector (dead     code)

  + Added possibility to change badges' text font color

  + Small updates to sample multi-host dashboard, dash.html

  + Added missing quoting in shell scripts

  + Bump handlebars from 4.2.0 to 4.5.3

  + Reduce log level for uv_thread_set_name_np from error to     info

  + Set standard name to non-libnetdata threads (libuv,     pthread)

  - Bug fixes :

  + Fixed problems reported by Coverity for eBPF collector     plugin

  + Fixed invalid literal for float\(\): NN.NNt error in the     elasticsearch python plugin, by adding terabyte unit     parsing

  + Fixed timeout failing in docker containers which broke     some python.d collectors

  + Fixed problem with the httpcheck python collector not     being able to check URLs with the POST method, by adding     body to the URLService. Also record the new options in     httpcheck.conf

  + Fixed dbengine repeated global flushing errors and     collectors being blocked, by dropping dirty dbengine     pages if the disk cannot keep up

  + Fixed issue with alarm notifications occasionally     ignoring the configured severity filter when the ROLE     was set to root

  + Fixed Netlink Connection Tracker charts in the nfacct     plugin

  + Fixed metric values sent via remote write to Prometheus     backends, when using average/sum

  + Fixed unclosed brackets in softnet alarm

  + Fixed SEGFAULT when localhost initialization failed

  + Reduced the number of broken pipe error log entries,     after a SIGKILL

  + Fixed Coverity errors by restoring support for protobuf     3.0

  + Fixed inability to disable Prometheus remote API

  + Fixed SEGFAULT from the cpuidle plugin

  + Fixed samba collector not working, due to inability to     run sudo

  + Fixed invalid css/js resource errors when URL for slave     node has no final / on streaming master

  + Fixed keys_redis chart in the redis collector, by     populating keys at runtime

  + Fixed UrlService bytes decoding and logger unicode     encoding in the python.d plugin

  + Fixed a warning in the prometheus remote write backend

  + Fixed not detecting more than one adapter in the hpssa     collector

  + Fixed race conditions in dbengine

  + Fixed race condition with the dbenging page cache     descriptors

  + Fixed dbengine dirty page flushing warning

  + Fixed missing parenthesis on alarm softnet.conf

  + Fixed 'Master thread EXPORTING takes too long to exit.
    Giving up' error, by cleaning up the main exporting     engine thread on exit

  + Fixed rabbitmq error 'update() unhandled exception:
    invalid literal for int() with base 10'

  + Fixed some LGTM alerts

  + Fixed valgrind errors

  + Fixed monit collector LGTM warnings

  + Fixed the following go.d.plugin collector issues: .
    mysql: panic in Cleanup (#326) . unbound: gather metrics     via unix socket (#319) . logstash: pipelines chart     (#317) . unbound: configuration file parsing. . Support     include mechanism. (#298) . logstash: pipelines metrics     parsing (#293) . phpfpm: processes metrics parsing     (#297)

  - Also package go.d.plugin (v0.14.1)

  - Update to v1.19.0 Improvements :

  - New collectors :

  + AM2320 sensor collector plugin

  + Added parsing of /proc/pagetypeinfo to provide metrics     on fragmentation of free memory pages

  + The unbound collector module was completely rewritten,     in Go

  - Collector improvements :

  + We rewrote our web log parser in Go, drastically     improving its flexibility and performance

  + The Kubernetes kubelet collector now reads the service     account token and uses it for authorization. We also     added a new default job to collect metrics from     https://localhost:10250/metrics

  + Added a new default job to the Kubernetes coredns     collector to collect metrics from     http://kube-dns.kube-system.svc.cluster.local:9153/metri     cs

  + apps.plugin: Synced FRRouting daemons configuration with     the frr 7.2 release

  + apps.plugin: Added process group for git-related     processes

  + apps.plugin: Added balena to the container-engines     application group

  + web_log: Treat 401 Unauthorized requests as successful

  + xenstat.plugin: Prepare for xen 4.13 by checking for     check xenstat_vbd_error presence

  + mysql: Added galera cluster_status alarm

  - Metrics database :

  + Netdata generates alarms if the disk cannot keep up with     data collection

  - Health :

  + Fine tune various default alarm configurations

  + Update SYN cookie alarm to be less aggressive

  + Added support for IRC alarm notifications Bug fixes :

  - Prevented freezes due to isolated CPUs

  - Fixed missing streaming when slave has SSL activated

  - Fixed error 421 in IRC notifications, by removing a line     break from the message

  - proc/pagetypeinfo collection could under particular     circumstances cause high CPU load. As a workaround, we     disabled pagetypeinfo by default

  - Fixed incorrect memory allocation in proc plugin&rsquo;s     pagetypeinfo collector

  - Eliminated cached responses from the postgres collector

  - rabbitmq: Fixed 'disk_free':
    'disk_free_monitoring_disabled' error

  - Fixed Apache module not working with letsencrypt     certificate by allowing the python UrlService to skip     tls_verify for http scheme

  - Fixed invalid spikes appearing in certain charts, by     improving the incremental counter reset/wraparound     detection algorithm

  - Fixed issue with unknown variables in alarm     configuration expressions always being evaluated to zero

  - Fixed issue of automatically picking up Pi-hole stats     from a Pi-hole instance installed on another device by     disabling the default job that collects metrics from     http://pi.hole

  - Update to v1.18.1 Improvements :

  - Disable slabinfo plugin by default to reduce the total     number of metrics collected

  - Add dbengine RAM usage statistics

  - Support Google Hangouts chat notifications

  - Add CMocka unit tests

  - Add prerequisites to enable automatic updates for     installations via the static binary     (kickstart-static64.sh) Bug fixes :

  - Fix unbound collector timings: Convert recursion timings     to milliseconds.

  - Fix unbound collector unhandled exceptions

  - Fix megacli collector binary search and sudo check

  - Fix Clang warnings

  - Fix python.d error logging: change chart suppress msg     level from ERROR to INFO

  - Fix freeipmi update frequency check: was warning that 5     was too frequent and it was setting it to 5.

  - Fix alarm configurations not getting loaded, via better     handling of chart names with special characters

  - Don't write HTTP response 204 messages to the logs

  - Fix build when CMocka isn't installed

  - Prevent zombie processes when a child is re-parented to     netdata when its running in a container, by adding child     process reaper

  - Update to v1.18.0 Improvements :

  - Database engine :

  + Make dbengine the default memory mode

  + Increase dbengine default cache size

  + Reduce overhead during write IO

  + Detect deadlock in dbengine page cache

  + Remove hard cap from page cache size to eliminate     deadlocks.

  - New collectors :

  + SLAB cache mechanism

  + Gearman worker statistics

  + vCenter Server Appliance

  + Zookeeper servers

  + Hadoop Distributed File System (HDFS) nodes

  - Collector improvements :

  + rabbitmq: Add vhosts message metrics from /api/vhosts

  + elasticsearch: collect metrics from _cat/indices

  + mysql: collect galera cluster metrics

  + Allow configuration of the python.d launch command from     netdata.conf

  + x509check: smtp cert check support

  + dnsmasq_dhcp: respect conf-dir,conf-file,dhcp-host     options

  + plugin: respect previously running jobs after plugin     restart

  + httpcheck: add current state duration chart

  + springboot2: fix context

  - Health :

  + Enable alarm templates for chart dimensions

  + Center the chart on the proper chart and time whenever     an alarm link is clicked

  - Other :

  + API: Include family into the allmetrics JSON response

  + API: Add fixed width option to badges

  + Allow hostnames in Access Control Lists Bug fixes :

  - Fix issue error in alarm notification script, when     executed without any arguments

  - Fix Coverity warnings

  - Fix dbengine consistency when a writer modifies a page     concurrently with a reader querying its metrics

  - Fix memory leak on netdata exit

  - Fix for missing boundary data points in certain cases

  - Fix unhandled exception log warnings in the python.d     collector orchestrator start\_job

  - Fix CORS errors when accessing the health management     API, by permitingt x-auth-token in     Access-Control-Allow-Headers

  - Fix misleading error log entries RRDSET: chart name     'XXX' on host 'YYY' already exists, by changing the log     level for chart updates

  - Properly resolve all Kubernetes container names

  - Fix LGTM warnings

  - Fix agent UI redirect loop during cloud sign-in

  - Fix python.d.plugin bug in parsing configuration files     with no explicitly defined jobs

  - Fix potential buffer overflow in the web server

  - Fix netdata group deletion on linux for uninstall script

  - Various cppcheck fixes

  - Fix handling of illegal metric timestamps in database     engine

  - Fix a resource leak

  - Fix rabbitmq collector error when no vhosts are     available.

  - Update to v1.17.0 Improvements :

  - Database engine :

  + Variable granularity support for data collection

  + Added tips on the UI to encourage users to try the new     DB Engine, when they reach the end of their metrics     history

  - Health :

  + Added support for plain text only email notifications

  + Started showing &ldquo;hidden&rdquo; alarm variables in     the responses of the chart and data API calls

  + Added a new API call for alarm status counters, as a     first step towards badges that will show the total     number of alarms

  - Security :

  + Added configurable default locations for trusted CA     certificates

  + Added safer way to get container names

  + Added SSL connection support to the python mongodb     collector

  - New collectors :

  + VSphere collector

  - Archiving :

  + Added a new MongoDB backend

  - Other :

  + Added apps grouping debug messages

  + GCC warning and linting improvements

  + Added global configuration option to show charts with     zero metrics

  + Improved the way we parse HTTP requests, so we can avoid     issues from edge cases

  - Bug fixes :

  + Fixed sensor chips filtering in python sensors collector

  + Fixed user and group names in apps.plugin when running     in a container, by mounting and reading /etc/passwd

  + Fixed possible buffer overflow in the JSON parser used     for health notification silencers

  + Fixed handling of corrupted DB files in dbengine, that     could cause netdata to not start properly (CRC and I/O     error handling)

  + Fixed an issue with Netdata snapshots that could     sometimes cause a problem during import

  + Fixed bug that would cause netdata to attempt to kill     already terminated threads again, on shutdown

  + Fixed out of memory (12) errors by reimplementing the     myopen() function family

  + Fixed wrong redirection of users signing in after     clicking Nodes

  + Fixed python.d smartd collector increasing CPU usage

  + Fixed mongodb python collector stock configuration     mistake, by changing password to pass

  + Fixed handling of UTF8 characters in badges and added     International Support to the URL parser

  + Fixed nodes menu sizing (responsive)

  + Fixed issues with http redirection to https and     streaming encryption

  + Fixed broken links to arcstat.py and arc_summary.py in     dashboard_info.js

  + Fixed bug with the nfacct plugin that resulted in     missing dimensions from the charts

  + Stopped anonymous stats from trying to write a log under     /tmp

  + Properly delete obsolete dimensions for inactive disks     in smartd_log

  + Fixed handling of disconnected sockets in unbound     python.d collector

  + Fixed crash in malloc

  + Fixed issue with mysql collector that resulted in     showing only a single slave_status chart, regardless of     the number of replication channels

  + Fixed a segmentation fault in backends

  + Fixed spigotmc plugin bugs

  + Fixed dbengine 100% CPU usage due to corrupted     transaction payload handling

  - Update to v1.16.0 Improvements :

  - Health :

  + Easily disable alarms, by persisting the silencers     configuration

  + Repeating alarm notifications

  + Simplified the health cmdapi tester - no setup/cleanup     needed

  + &Alpha;dd last_collected alarm to the x509check     collector

  + New alarm for abnormally high number of active     processes.

  - Security :

  + SSL support in the web server and streaming/replication

  + Support encrypted connections to OpenTSDB backends

  - New collectors :

  + Go.d collector modules for WMI, Dnsmasq DHCP leases and     Pihole

  + Riak KV instances collector

  + CPU performance statistics using Performance Monitoring     Units via the perf_event_open() system call. (perf     plugin)

  - Collector improvements :

  + Handle different sensor IDs for the same element in the     freeipmi plugin

  + Increase the cpu_limit chart precision in cgroup plugin

  + Added userstats and deadlocks charts to the python mysql     collector

  + Add perforce server process monitoring to the apps     plugin

  - Backends :

  + Prometheus remote write backend

  - DB engine improvements :

  + Reduced memory requirements by 40-50%

  + Reduced the number of pages needed to be stored and     indexed when using memory mode = dbengine, by adding     empty page detection

  - Rebranding :

  + Updated the netdata logo and changed links to point to     the new website

  - Other :

  + Pass the the cloud base url parameter to the     notifications mechanism, so that modifications to the     configuration are respected when creating the link to     the alarm

  + Improved logging, to be able to trace the CRITICAL:
    main[main] SIGPIPE received. error Bug fixes :

  - Fixed ram_available alarm

  - Stop monitoring /dev and /run in the disk space and     inode usage charts

  - Fixed the monitoring of the &ldquo;time&rdquo; group of     processes

  - Fixed compilation error PERF_COUNT_HW_REF_CPU_CYCLES'     undeclared here in old Linux kernels (perf plugin)

  - Fixed invalid XML page error (tomcat plugin)

  - Remove obsolete monit metrics

  - Fixed Failed to parse error in adaptec_raid

  - Fixed cluster_health_nodes and cluster_stats_nodes     charts in the elasticsearch collector

  - A modified slave chart's 'name' was not properly     transferred to the master

  - Netdata could run out of file descriptors when using the     new DB engine

  - Fixed UI behavior when pressing the End key

  - Fixed UI link to check the configuration file, to open     in a new tab

  - Prevented Error: 'module' object has no attribute     'Retry' messages from python collectors, by enforcing     minimum version check for the UrlService library

  - Fixed typo that causes nfacct.plugin log messages to     incorrectly show freeipmi

  - The daemon could get stuck during collection or during     shutdown, when using the new dbengine. Reduced new     dbengine IO utilization by forcing page alignment per     dimension of chart.

  - Properly handle timeouts/no response in dns_query_time     python collector

  - When a collector restarted after having stopped for a     long time, the new dbengine would consume a lot of CPU     resources.

  - Fixed error Assertion old_state &     PG_CACHE_DESCR_ALLOCATED' failed` of the new dbengine.
    Eliminated a page cache descriptor race condition

  - tv.html failed to load the three left charts when     accessed via https. Turn tv.html links to https

  - Change print level from error to info for messages about     clearing old files from the database

  - Fixed warning regarding the     x509check_last_collected_secs alarms. Changed the     template update frequency to 60s, to match the     chart&rsquo;s update frequency

  - Email notification header lines were not terminated with     \r
 as per the RFC

  - Some log entries would not be caught by the python     web_log plugin. Fixed the regular expressions

  - Corrected the date used in pushbullet notifications

  - Fixed FATAL error when using the new dbengine with no     direct I/O support, by falling back to buffered I/O

  - Fixed compatibility issues with varnish v4 (varnish     collector)

  - The total number of disks in mdstat.XX_disks chart was     displayed incorrectly. Fixed the 'inuse' and 'down'     disks stacking.

  - The config option --disable-telemetry was being checked     after restarting netdata, which means that we would     still send anonymous statistics the first time netdata     was started. (NOTE: Telemetry is disabled by default on     openSUSE.)

  - Fixed apcupsd collector errors, by passing correct info     to the run function.

  - apcupsd and libreswan were not enabled by default

  - Fixed incorrect module name: energi to energid

  - The nodes view did not work properly when a reverse     proxy was configured to access netdata via paths     containing subpaths (e.g. myserver/netdata)

  - Fix error message PLUGINSD : cannot open plugins     directory

  - Corrected invalid links to web_log.conf that appear on     the agent UI

  - Fixed ScaleIO collector endpoint paths

  - Fixed web client timeout handling in the go.d plugin     httpcheck collector

  - Update to v1.15.0 Bug Fixes :

  - Prowl notifications were not being sent, unless another     notification method was also active

  - Fix exception handling in the python.d plugin

  - The node applications group did not include all node     processes.

  - The nvidia_smi collector displayed incorrect power usage

  - The python.d plugin would sometimes hang, because it     lacked a connect timeout

  - The mongodb collector raised errors due to various     KeyErrors

  - The smartd_log collector would show incorrect     temperature values Improvements :

  - Support for aggregate node view

  - Database engine

  - New collector modules :

  + Go.d collectors for OpenVPN, the Tengine web server and     ScaleIO (VxFlex OS) instances

  + Monitor disk access latency like ioping does

  - Energi Core daemon monitoring, suits other Bitcoin forks

  - Collector improvements :

  + Add docker swarm manager metrics to the go.d     docker_engine collector

  + Implement unified cgroup cpu limit

  + python.d.plugin: Allow monitoring of HTTP(S) endpoints     which require POST data and make the UrlService more     flexible

  - Support the AWS Kinesis backend for long-term storage

  - Add a new 'text-only' chart renderer

  - API Improvements :

  + Smarter caching of API calls. Do not cache alarms and     info api calls and extend no-cache headers.

  + Extend the api/v1/info call response with system and     collector information

  + k6 script for API load testing

  - Kubernetes helmchart improvements :

  + Added the init container, where sysctl params could be     managed, to bypass the Cannot allocate memory issue

  + Better startup/shutdown of slaves and reduced memory     usage with liveness/readiness probes and default memory     mode none

  + Added the option of overriding the default settings for     kubelet, kubeproxy and coredns collectors via     values.yaml

  + Make the use of persistent volumes optional, add     apiVersion to fix linting errors and correct the     location of the env field

  - Update to v1.14.0 The release introduces major additions     to Kubernetes monitoring, with tens of new charts for     Kubelet, kube-proxy and coredns metrics, as well as     significant improvements to the netdata helm chart. Two     new collectors were added, to monitor Docker hub and     Docker engine metrics. Finally, v1.14 adds support for     version 2 cgroups, OpenLDAP over TLS, NVIDIA SMI free     and per process memory and configurable syslog     facilities. Bug Fixes :

  - Fixed problem autodetecting failed jobs in python.d     plugin. It now properly restarts jobs that are being     rechecked, as soon as they are able to run.

  - CouchdDB monitoring would stop sometimes with an     exception. Fixed the unhandled exception causing the     issue.

  - The netdata api deliberately returned http error 400     when netdata ran in memory mode none. Modified the     behavior to return responses, regardless of the memory     mode

  - The python.d plugin sometimes does not receive SIGTERM     when netdata exits, resulting in zombie processes. Added     a heartbeat so that the process can exit on SIGPIPE.

  - The new SMS Server Tools notifications did not handle     errors well, resulting in cryptic error messages.
    Improved error handling.

  - Fix segmentation fault in streaming, when two dimensions     had similar names.

  - Kubernetes Helm Chart: Fixed incorrect use of namespaces     in ServiceAccount and ClusterRoleBinding RBAC fixes.

  - Elastic search: The option to enable HTTPS was not     included in the config file, giving the erroneous     impression that HTTPS was not supported. The option was     added.

  - RocketChat notifications were not being sent properly.
    Added default recipients for roles in the health alarm     notification configuration. Improvements :

  - go.d.plugin v0.4.0 : Docker Hub and k8s coredns     collectors, springboot2 URI filters support.

  - go.d.plugin v0.3.1 : Add default job to run     k8s_kubelet.conf, k8s_kubeproxy, activemq modules

  - go.d.plugin v0.3.0 : Docker engine, kubelet and     kub-proxy collectors. x509check module reading certs     from file support

  - Added unified cgroup support that includes v2 cgroups

  - Disk stats: Added preferred disk id pattern, so that     users can see the id they prefer, when multiple ids     appear for the same device

  - NVIDIA SMI: Added memory free and per process memory     usage charts to the collector

  - OpenLDAP: Added TLS support, to allow monitoring of     LDAPS.

  - PHP-FPM: Add health check to raise alarms when the phpfm     server is unreachable

  - PostgreSQL: Our configuration options to connect to a DB     did not support all possible option. Added option to     connect to a PostreSQL instance by defining a connection     string (URI).

  - python.d.plugin: There was no way to delete obsolete     dimensions in charts created by the python.d plugin. The     plugin can now delete dimension at runtime.

  - netdata supports sending its logs to Syslog, but the     facility was hard-coded. We now support configurable     Syslog facilities in netdata.conf.

  - Kubernetes Helm Chart improvements :

  + Added serviceName in statefulset spec to align with the     k8s documentation

  + Added preStart command to persist slave machine GUIDs,     so that pod deletion/addition during upgrades doesn't     lose the slave history.

  + Disabled non-essential master netdata collector plugins     to avoid duplicate data

  + Added preStop command to wait for netdata to exit     gracefully before removing the container

  + Extended configuration file support to provide more     control from the helm command line

  + Added option to disable Role-based access control

  + Added liveness and readiness probes.

  - Update to v1.13.0 netdata has taken the first step into     the world of Kubernetes, with a beta version of a Helm     chart for deployment to a k8s cluster and proper naming     of the cgroup containers. We have big plans for     Kubernetes, so stay tuned! A major refactoring of the     python.d plugin has resulted in a dramatic decrease of     the required memory, making netdata even more resource     efficient. We also added charts for IPC shared memory     segments and total memory used. Improvements :

  - Kubernetes: Helm chart and proper cgroup naming

  - python.d.plugin: Reduce memory usage with separate     process for initial module checking and loaders cleanup

  - IPC shared memory charts

  - mysql module add ssl connection support

  - FreeIPMI: Have the debug option apply the internal     freeipmi debug flags

  - Prometheus backend: Support legacy metric names for     source=avg

  - Registry: Allow deleting the host we are looking at

  - SpigotMC: Use regexes for parsing. Bug Fixes :

  - Postgres: fix connection issues

  - Proxmox container: Fix cgroup naming and use total_*     memory counters for cgroups

  - proc.plugin and plugins.d: Fix memory leaks

  - SpigotMC: Fix UnicodeDecodeError and py2 compatibility     fix

  - Fix non-obsolete dimension deletion

  - UI: Fix incorrect icon for the streaming master

  - Docker container names: Retry renaming when a name is     not found

  - apps.plugin: Don't send zeroes for empty process groups

  - go.d.plugin: Correct sha256sum check

  - Unbound module: Documentation corrected with     troubleshooting section.

  - Streaming: Prevent UI issues upon GUID duplication     between master and slave netdata instances

  - Linux power supply module: Fix missing zero dimensions

  - Minor fixes around plugin_directories initialization

  - Update to v1.12.2 Bug Fixes :

  - Zombie processes exist after restart netdata - add     heartbeat to python.d plugin

  - RocketChat notifications not working

  - SIGSEGV crash during shutdown of tc plugin

  - CMake warning for nfacct plugin Improvements :

  - Oracledb python module

  - Show streamed servers even for users that are not signed     in

  - Drop GPG signature (no longer used)

  - Drop spec compatibility with old distro versions

  - Drop netdata-automake-no-dist-xz.patch

  - Refresh netdata-smartd-log-path.patch

  - Update to v1.12.1 Fixes :

  - Fix SIGSEGV at startup: Don't free vars of charts that     do not exist #5455

  - Prevent invalid Linux power supply alarms during startup     #5447

  - Correct duplicate flag enum in health.h #5441

  - Remove extra 'v' for netdata version from Server     response header #5440 and spec URL #5427

  - apcupsd - Treat ONBATT status the same as ONLINE #5435

  - Fix #5430 - LogService._get_raw_data under python3 fails     on undecodable data #5431

  - Correct version check in UI #5429

  - Fix ERROR 405: Cannot download charts index from server
    - cpuidle handle newlines in names #5425

  - Fix clock_gettime() failures with the CLOCK_BOOTTIME     argument #5415

  - Use netnsid for detecting cgroup networks; #5413

  - Python module sensors fix #5406

  - Fix ceph.chart.py for Python3 #5396 (GaetanF)

  - Fix warning condition for mem.available #5353

  - cups.plugin: Support older versions #5350 Improvements :

  - Add driver-type option to the freeipmi plugin #5384

  - Add support of tera-byte size for Linux bcache. #5373

  - Split nfacct plugin into separate process #5361

  - Add cgroup cpu and memory limits and alarms #5172

  - Add message queue statistics #5115

  - Update to v1.12.0 Key improvements :

  - Introducing netdata.cloud, the free netdata service for     all netdata users

  - High performance plugins with go.d.plugin (data     collection orchestrator written in Go)

  - 7 new data collectors and 11 rewrites of existing data     collectors for improved performance

  - A new management API for all netdata servers

  - Bind different functions of the netdata APIs to     different ports Management API: Netdata now has a     management API. We plan to provide a full set of     configuration commands using this API. In this release,     the management API supports disabling or silencing     alarms during maintenance periods. For more information     about the management API, check     https://docs.netdata.cloud/web/api/health/#health-manage     ment-api Anonymous statistics: Anonymous usage     information can be collected and sent to Google     Analytics. This functionality is disabled by default in     openSUSE. Remove     /etc/netdata/.opt-out-from-anonymous-statistics to     enable. The statistics calculated from this information     will be used for: 1. Quality assurance, to help us     understand if netdata behaves as expected and help us     identify repeating issues for certain distributions or     environment. 2. Usage statistics, to help us focus on     the parts of netdata that are used the most, or help us     identify the extend our development decisions influence     the community. Information is sent to Netdata via two     different channels :

  - Google Tag Manager is used when an agent's dashboard is     accessed.

  - The script anonymous-statistics.sh is executed by the     Netdata daemon, when Netdata starts, stops cleanly, or     fails. Both methods are controlled via the same opt-out     mechanism. For more information, check     https://docs.netdata.cloud/docs/anonymous-statistics/     Data collection: This release introduces a new Go plugin     orchestrator. This plugin has its own github repo     (https://github.com/netdata/go-orchestrator). It is     open-source, using the same license and we welcome     contributions. The orchestrator can also be used to     build custom data collection plugins written in Go. We     have used the orchestrator to write many new Go plugins     in our go.d plugin github repo. For more information,     check     https://github.com/netdata/go-orchestrator#go-orchestrat     or-wip New data collectors :

  - Activemq (Go)

  - Consul (Go)

  - Lighttpd2 (Go)

  - Solr (Go)

  - Springboot2 (Go)

  - mdstat - nonredundant arrays (C)

  - CUPS printing system (C) High performance versions of     older data collectors :

  - apache (Go)

  - dns_query (Go)

  - Freeradius (Go)

  - Httpcheck (Go)

  - Lighttpd (Go)

  - Portcheck (Go)

  - Nginx (Go)

  - cpufreq (C)

  - cpuidle (C)

  - mdstat (C)

  - power supply (C) Other improved data collectors :

  - Fix the python plugin clock (collectors falling behind).

  - adaptec_raid: add to python.d.conf.

  - apcupsd: Detect if UPS is online.

  - apps: Fix process statistics collection for FreeBSD.

  - apps: Properly lookup docker container name when running     in ECS

  - fail2ban: Add 'Restore Ban' action.

  - go_expavar: Don't check for duplicate expvars.

  - hddtemp: Don't use disk model as dim name.

  - megacli: add to python.d.conf.

  - nvidia_smi: handle N/A values.

  - postgres: Fix integer out of range error on Postgres 11,     fix locks count.

  - proc: Don't show zero charts for ZFS filesystem.

  - proc; Fix cached memory calculation.

  - sensors: Don't ignore 0 RPM fans on start.

  - smartd_log: check() unhandled exception: list index out     of range.

  - SNMP: Gracefully ignore the offset if the value is not a     number Health Monitoring :

  - Add Prowl notifications for iOS users.

  - Show count of active alarms per state in email     notifications.

  - Show evaluated expression and expression variable values     in email notifications.

  - Improve support for slack recipients (channels/users).

  - Custom notifications: Fix bug with alarm role     recipients. Dashboards :

  - Server filtering in my-netdata menu when signed in to     netdata.cloud

  - All units are now IEC-compliant abbreviations (KiB, MiB     etc.).

  - GUI: Make entire row clickable in the registry menu     showing the list of servers. Backends :

  - Do not report stale metrics to prometheus. Other :

  - Treat DT_UNKNOWN files as regular files.

  - API: Stricter rules for URL separators.

  - Update to v1.11.1 Improved internal database: Overflown     incremental values (counters) do not show a zero point     at the charts. Netdata detects the width (8bit, 16bit,     32bit, 64bit) of each counter and properly calculates     the delta when the counter overflows. The internal     database format has been extended to support values     above 64bit. New data collection plugins :

  - openldap, to collect performance statistics from     OpenLDAP servers.

  - tor, to collect traffic statistics from Tor.

  - nvidia_smi to monitor NVIDIA GPUs. Improved data     collection plugins :

  - BUG FIX: network interface names with colon (:) in them     were incorrectly parsed and resulted in faulty data     collection values.

  - BUG FIX: smartd_log has been refactored, has better     python v2 compatibility, and now supports SCSI smart     attributes

  - cpufreq has been re-written in C - since this module if     common, we decided to convert to an internal plugin to     lower the pressure on the python ones. There are a few     more that will be transitioned to C in the next release.

  - BUG FIX: sensors got some compatibility fixes and     improved handling for lm-sensors errors. Health     monitoring :

  - BUG FIX: max network interface speed data collection was     faulty, which resulted in false-positive alarms on     systems with multiple interfaces using different speeds     (the speed of the first network interface was used for     all network interfaces). Now the interface speed is     shown as a badge.

  - alerta.io notifications got a few improvements

  - BUG FIX: conntrack_max alarm has been restored (was not     working due to an invalid variable name referenced)     Registry (my-netdata menu) :

  - It has been refactored a bit to reveal the URLs known     for each node and now it supports deleting individual     URLs.

  - Update to 1.11.0

  - Stock config files are now in /usr/lib/netdata; use the     /etc/netdata/edit-config script to copy and edit them.

  - The query engine of netdata has been re-written to     support query plugins. We have already added the     following algorithms that are available for alarm,     charts and badges :

  + stddev, for calculating the standard deviation on any     time-frame.

  + ses or ema or ewma, for calculating the exponential     weighted moving average, or single/simple exponential     smoothing on any time-frame.

  + des, for calculating the double exponential smoothing on     any time-frame.

  + cv or rsd, for calculating the coefficient of variation     for any time-frame. Fixed security issues :

  - CVE-2018-18836 Fixed JSON Header Injection (an attacker     could send 
 encoded in the request to inject a JSON     fragment into the response). boo#1139094

  - CVE-2018-18837 Fixed HTTP Header Injection (an attacker     could send 
 encoded in the request to inject an HTTP     header into the response). boo#1139095

  - CVE-2018-18838 Fixed LOG Injection (an attacker could     send 
 encoded in the request to inject a log line at     access.log). boo#1139098

  - CVE-2018-18839 Not fixed Full Path Disclosure, since     these are intended (netdata reports the absolute     filename of web files, alarm config files and alarm     handlers).

  - Fixed Privilege Escalation by manipulating apps.plugin     or cgroup-network error handling.

  - Fixed LOG injection (by sending URLs with 
 in them).
    New data collection modules :

  - rethinkdbs for monitoring RethinkDB performance

  - proxysql for monitoring ProxySQL performance

  - litespeed for monitoring LiteSpeed web server     performance.

  - uwsgi for monitoring uWSGI performance

  - unbound for monitoring the performance of Unbound DNS     servers.

  - powerdns for monitoring the performance of PowerDNS     servers.

  - dockerd for monitoring the health of dockerd

  - puppet for monitoring Puppet Server and Puppet DB.

  - logind for monitoring the number of active users.

  - adaptec_raid and megacli for monitoring the relevant     raid controller

  - spigotmc for monitoring minecraft server statistics

  - boinc for monitoring Berkeley Open Infrastructure     Network Computing clients.

  - w1sensor for monitoring multiple 1-Wire temperature     sensors.

  - monit for collecting process, host, filesystem, etc     checks from monit.

  - linux_power_supplies for monitoring Linux Power Supplies     attributes Data collection orchestrators changes :

  - node.d.plugin does not use the js command any more.

  - python.d.plugin now uses monotonic clocks. There was a     discrepancy in clocks used in netdata that resulted in a     shift in time of python module after some time (it was     missing 1 sec per day).

  - added MySQLService for quickly adding plugins using     mysql queries.

  - URLService now supports self-signed certificates and     supports custom client certificates.

  - all python.d.plugin modules that require sudo to collect     metrics, are now disabled by default, to avoid security     alarms on installations that do not need them. Improved     data collection modules :

  - apps.plugin now detects changes in process file     descriptors, also fixed a couple of memory leaks. Its     default configuration has been enriched significantly,     especially for IoT.

  - freeipmi.plugin now supports option ignore-status to     ignore the status reported by given sensors.

  - statsd.plugin (for collecting custom APM metrics)

  + The charting thread has been optimized for lowering its     CPU consumption when several millions of metrics are     collected.

  + sets now report zeros instead of gaps when no data are     collected

  + histograms and timers have been optimized for lowering     their CPU consumption to support several thousands of     such metrics are collected.

  + histograms had wrong sampling rate calculations.

  + gauges now ignore sampling rate when no sign is included     in the value.

  + the minimum sampling rate supported is now 0.001.

  + netdata statsd is now drop-in replacement for datadog     statsd (although statsd tags are currently ignored by     netdata).

  - proc.plugin (Linux, system monitoring)

  + Unused interrupts and softirqs are not used in charts     (this saves quite some processing power and memory on     systems with dozens of CPU cores).

  + fixed /proc/net/snmp parsing of IcmpMsg lines that     failed on a few systems.

  + Veritas Volume Manager disks are now recognized and     named accordingly.

  + Now netdata collects TcpExtTCPReqQFullDrop and     re-organizes metrics in charts to properly monitor the     TCP SYN queue and the TCP Accept queue of the kernel.

  + Many charts that were previously reported as IPv4, were     actually reflecting metrics for both IPv4 and IPv6. They     have been renamed to ip.*.

  + netdata now monitors SCTP.

  + Fixed BTRFS over BCACHE sector size detection.

  + BCACHE data collection is now faster.

  + /proc/interrupts and /proc/softirqs parsing fixes.

  - diskspace.plugin (Linux, disk space usage monitoring)

  + It does not stat() excluded mount points any more (it     was interfering with kerberos authenticated mount     points).

  + several filesystems are now by default excluded from     disk-space monitoring, to avoid breaking suspend on     workstations.

  - python.d.plugin PYTHON modules (applications monitoring)

  + web_log module now supports virtual hosts, reports     http/https metrics, support squid logs

  + nginx_plus module now handles non-continuous peer IDs

  + ipfs module is optimized, the use of its Pin API is now     disabled by default and can enabled with a netdata     module option (using the IPFS Pin API increases the load     on the IPFS server).

  + fail2ban module now supports IPv6 too.

  + ceph module now checks permissions and properly reports     issues

  + elasticsearch module got better error handling

  + nginx_plus module now uses upstream ip:port instead of     transient id to identify dimensions.

  + redis, now it supports Pika, collects evited keys, fixes     authentication issues reported and improves exception     handling.

  + beanstalk, bug fix for yaml config loading.

  + mysql, the % of active connections is now monitored,     query types are also charted.

  + varnish, now it supports versions above 5.0.0

  + couchdb

  + phpfpm, now supports IPv6 too.

  + apache, now supports IPv6 too.

  + icecast

  + mongodb, added support for connect URIs

  + postgress

  + elasticsearch, now it supports versions above 6.3.0,     fixed JSON parse errors

  + mdstat , now collects mismatch_cnt

  + openvpn_log

  - node.d.plugin NODE.JS modules

  + snmp was incorrectly parsing a new OID names as float.

  - charts.d.plugin BASH modules

  + nut now supports naming UPSes. Health monitoring :

  - Added variable $system.cpu.processors.

  - Added alarms for detecting abnormally high load average.

  - TCP SYN and TCP accept queue alarms, replacing the old     softnet dropped alarm that was too generic and reported     many false positives.

  - system alarms are now enabled on FreeBSD.

  - netdata now reads NIC speed and sets alarms on each     interface to detect congestion.

  - Network alarms are now relaxed to avoid false positives.

  - New bcache alarms.

  - New mdstat alarms.

  - New apcupsd alarms.

  - New mysql alarms.

  - New notification methods :

  + rocket.chat

  + Microsoft Teams

  + syslog

  + fleep.io

  + Amazon SNS Backends :

  - Host tags are now sent to Graphite

  - Host variables are now sent to Prometheus Streaming :

  - Each netdata slave and proxy now filter the charts that     are streamed. This allows exposing netdata masters to     third parties by limiting the number of charts available     at the master.

  - Fixed a bug in streaming slaves that randomly prevented     them to resume streaming after network errors.

  - Fixed a bug that on slaves that sent duplicated chart     names under certain conditions.

  - Fixed a bug that caused slaves to consume 100% CPU (due     to a misplaced lock) when multiple threads were adding     dimensions on the same chart.

  - The receiving nodes of streaming (netdata masters and     proxies) can now rate-limit the rate of inbound     streaming requests received.

  - Re-worked time synchronization between netdata slaves     and masters. API :

  - Badges that report time, now show 'undefined' instead of     'never'. Dashboard :

  - Added UTC timezone to the list of available time-zones.

  - The dashboard was sending some non-HTTP compliant     characters at the URLs that made netdata dashboards     break when used under certain proxies.");
  script_set_attribute(attribute:"see_also", value:"http://kube-dns.kube-system.svc.cluster.local:9153/metrics");
  script_set_attribute(attribute:"see_also", value:"http://pi.hole");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1139094");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1139095");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1139098");
  script_set_attribute(attribute:"see_also", value:"https://docs.netdata.cloud/docs/anonymous-statistics/");
  script_set_attribute(attribute:"see_also", value:"https://docs.netdata.cloud/web/api/health/#health-management-api");
  script_set_attribute(attribute:"see_also", value:"https://github.com/netdata/go-orchestrator");
  script_set_attribute(attribute:"see_also", value:"https://github.com/netdata/go-orchestrator#go-orchestrator-wip");
  script_set_attribute(attribute:"see_also", value:"https://github.com/netdata/netdata/releases/tag/v1.24.0");
  script_set_attribute(attribute:"see_also", value:"https://localhost:10250/metrics");
  script_set_attribute(attribute:"solution", value:
"Update the affected netdata packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-18837");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-18838");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:netdata");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:netdata-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:netdata-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"netdata-1.29.3-lp152.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"netdata-debuginfo-1.29.3-lp152.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"netdata-debugsource-1.29.3-lp152.4.3.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "netdata / netdata-debuginfo / netdata-debugsource");
}
