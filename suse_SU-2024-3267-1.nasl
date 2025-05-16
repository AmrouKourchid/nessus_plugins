#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:3267-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(207375);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/18");

  script_cve_id("CVE-2023-45142", "CVE-2024-6104");
  script_xref(name:"SuSE", value:"SUSE-SU-2024:3267-1");

  script_name(english:"openSUSE 15 Security Update : SUSE Manager Client Tools (SUSE-SU-2024:3267-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote openSUSE 15 host has a package installed that is affected by multiple vulnerabilities as referenced in the
SUSE-SU-2024:3267-1 advisory.

    golang-github-prometheus-prometheus:

    - Security issues fixed:

      * CVE-2024-6104: Update go-retryablehttp to version 0.7.7 (bsc#1227038)
      * CVE-2023-45142: Updated otelhttp to version 0.46.1 (bsc#1228556)

    - Require Go > 1.20 for building
    - Migrate from `disabled` to `manual` service mode
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
      * [BUGFIX] TSDB: Remove double memory snapshot on shutdown.
    - Update to 2.45.2:
      * [BUGFIX] TSDB: Fix PostingsForMatchers race with creating new
        series.
    - Update to 2.45.1:
      * [ENHANCEMENT] Hetzner SD: Support larger ID's that will be used
        by Hetzner in September.
      * [BUGFIX] Linode SD: Cast InstanceSpec values to int64 to avoid
        overflows on 386 architecture.
      * [BUGFIX] TSDB: Handle TOC parsing failures.

    rhnlib:

    - Version 5.0.4-0
      * Add the old TLS code for very old traditional clients still on
        python 2.7 (bsc#1228198)

    spacecmd:

    - Version 5.0.9-0
      * Update translation strings

    uyuni-tools:

    - Version 0.1.21-0
      * mgrpxy: Fix typo on Systemd template
    - Version 0.1.20-0
      * Update the push tag to 5.0.1
      * mgrpxy: expose port on IPv6 network (bsc#1227951)
    - Version 0.1.19-0
      * Skip updating Tomcat remote debug if conf file is not present
    - Version 0.1.18-0
      * Setup Confidential Computing container during migration
        (bsc#1227588)
      * Add the /etc/uyuni/uyuni-tools.yaml path to the config help
      * Split systemd config files to not loose configuration at upgrade
        (bsc#1227718)
      * Use the same logic for image computation in mgradm and mgrpxy
        (bsc#1228026)
      * Allow building with different Helm and container default
        registry paths (bsc#1226191)
      * Fix recursion in mgradm upgrade podman list --help
      * Setup hub xmlrpc API service in migration to Podman (bsc#1227588)
      * Setup disabled hub xmlrpc API service in all cases (bsc#1227584)
      * Clean the inspection code to make it faster
      * Properly detect IPv6 enabled on Podman network (bsc#1224349)
      * Fix the log file path generation
      * Write scripts output to uyuni-tools.log file
      * Add uyuni-hubxml-rpc to the list of values in
        mgradm scale --help
      * Use path in mgradm support sql file input (bsc#1227505)
      * On Ubuntu build with go1.21 instead of go1.20
      * Enforce Cobbler setup (bsc#1226847)
      * Expose port on IPv6 network (bsc#1227951)
      * show output of podman image search --list-tags command
      * Implement mgrpxy support config command
      * During migration, ignore /etc/sysconfig/tomcat and
        /etc/tomcat/tomcat.conf (bsc#1228183)
      * During migration, remove java.annotation,com.sun.xml.bind and
        UseConcMarkSweepGC settings
      * Disable node exporter port for Kubernetes
      * Fix start, stop and restart in Kubernetes
      * Increase start timeout in Kubernetes
      * Fix traefik query
      * Fix password entry usability (bsc#1226437)
      * Add --prepare option to migrate command
      * Fix random error during installation of CA certificate
        (bsc#1227245)
      * Clarify and fix distro name guessing when not provided
        (bsc#1226284)
      * Replace not working Fatal error by plain error return
        (bsc#1220136)
      * Allow server installation with preexisting storage volumes
      * Do not report error when purging mounted volume (bsc#1225349)
      * Preserve PAGER settings from the host for interactive sql
        usage (bsc#1226914)
      * Add mgrpxy command to clear the Squid cache
      * Use local images for Confidential Computing and
        Hub containers (bsc#1227586)
    - Version 0.1.17-0
      * Allow GPG files to be loaded from the local file (bsc#1227195)
    - Version 0.1.16-0
      * Prefer local images in all migration steps (bsc#1227244)
    - Version 0.1.15-0
      * Define --registry flag behaviour (bsc#1226793)
    - Version 0.1.14-0
      * Do not rely on hardcoded registry, remove any FQDN
    - Version 0.1.13-0
      * Fix mgradm support config tarball creation (bsc#1226759)
    - Version 0.1.12-0
      * Detection of k8s on Proxy was wrongly influenced by Server
        setting

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220136");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224349");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225349");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226191");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226284");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226437");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226759");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226793");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226847");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226914");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227038");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227195");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227244");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227245");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227505");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227584");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227586");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227588");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227718");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227951");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228026");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228183");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228198");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228556");
  # https://lists.suse.com/pipermail/sle-updates/2024-September/036925.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3f41ff3c");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-45142");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-6104");
  script_set_attribute(attribute:"solution", value:
"Update the affected spacecmd package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-6104");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
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
if (isnull(os_release) || os_release !~ "^SUSE") audit(AUDIT_OS_NOT, "openSUSE");
var os_ver = pregmatch(pattern: "^(SUSE[\d.]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SUSE15\.5|SUSE15\.6)$", string:os_ver)) audit(AUDIT_OS_NOT, 'openSUSE 15', 'openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE (' + os_ver + ')', cpu);

var pkgs = [
    {'reference':'spacecmd-5.0.9-150000.3.124.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'spacecmd-5.0.9-150000.3.124.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'spacecmd');
}
