#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:2636-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(204895);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/30");

  script_cve_id(
    "CVE-2024-0760",
    "CVE-2024-1737",
    "CVE-2024-1975",
    "CVE-2024-4076"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2024:2636-1");
  script_xref(name:"IAVA", value:"2024-A-0442-S");

  script_name(english:"SUSE SLED15 / SLES15 / openSUSE 15 Security Update : bind (SUSE-SU-2024:2636-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED15 / SLED_SAP15 / SLES15 / SLES_SAP15 / openSUSE 15 host has packages installed that are
affected by multiple vulnerabilities as referenced in the SUSE-SU-2024:2636-1 advisory.

    Update to release 9.18.28

    Security fixes:

    - CVE-2024-0760: Fixed a flood of DNS messages over TCP may make the server unstable (bsc#1228255)
    - CVE-2024-1737: Fixed BIND's database will be slow if a very large number of RRs exist at the same name
    (bsc#1228256)
    - CVE-2024-1975: Fixed SIG(0) can be used to exhaust CPU resources (bsc#1228257)
    - CVE-2024-4076: Fixed assertion failure when serving both stale cache data and authoritative zone content
    (bsc#1228258)

    Changelog:

      * Command-line options for IPv4-only (named -4) and IPv6-only
        (named -6) modes are now respected for zone primaries,
        also-notify, and parental-agents.
      * An RPZ responses SOA record TTL was set to 1 instead of the
        SOA TTL, if add-soa was used. This has been fixed.
      * When a query related to zone maintenance (NOTIFY, SOA) timed
        out close to a view shutdown (triggered e.g. by rndc reload),
        named could crash with an assertion failure. This has been
        fixed.
      * The statistics channel counters that indicated the number of
        currently connected TCP IPv4/IPv6 clients were not properly
        adjusted in certain failure scenarios. This has been fixed.
      * Some servers that could not be reached due to EHOSTDOWN or
        ENETDOWN conditions were incorrectly prioritized during server
        selection. These are now properly handled as unreachable.
      * On some systems the libuv call may return an error code when
        sending a TCP reset for a connection, which triggers an
        assertion failure in named. This error condition is now dealt
        with in a more graceful manner, by logging the incident and
        shutting down the connection.
      * Changes to listen-on statements were ignored on reconfiguration
        unless the port or interface address was changed, making it
        impossible to change a related listener transport type. That
        issue has been fixed.
      * A bug in the keymgr code unintentionally slowed down some
        DNSSEC key rollovers. This has been fixed.
      * Some ISO 8601 durations were accepted erroneously, leading to
        shorter durations than expected. This has been fixed
      * A regression in cache-cleaning code enabled memory use to grow
        significantly more quickly than before, until the configured
        max-cache-size limit was reached. This has been fixed.
      * Using rndc flush inadvertently caused cache cleaning to become
        less effective. This could ultimately lead to the configured
        max-cache-size limit being exceeded and has now been fixed.
      * The logic for cleaning up expired cached DNS records was
        tweaked to be more aggressive. This change helps with enforcing
        max-cache-ttl and max-ncache-ttl in a timely manner.
      * It was possible to trigger a use-after-free assertion when the
        overmem cache cleaning was initiated. This has been fixed.
      New Features:
      * A new option signatures-jitter has been added to dnssec-policy
        to allow signature expirations to be spread out over a period
        of time.
      * The statistics channel now includes counters that indicate the
        number of currently connected TCP IPv4/IPv6 clients.
      * Added RESOLVER.ARPA to the built in empty zones.
      Feature Changes:
      * DNSSEC signatures that are not valid because the current time
        falls outside the signature inception and expiration dates are
        skipped instead of causing an immediate validation failure.
      Security Fixes:
      * A malicious DNS client that sent many queries over TCP but
        never read the responses could cause a server to respond slowly
        or not at all for other clients. This has been fixed.
        (CVE-2024-0760)
      * It is possible to craft excessively large resource records
        sets, which have the effect of slowing down database
        processing. This has been addressed by adding a configurable
        limit to the number of records that can be stored per name and
        type in a cache or zone database. The default is 100, which can
        be tuned with the new max-records-per-type option.
      * It is possible to craft excessively large numbers of resource
        record types for a given owner name, which has the effect of
        slowing down database processing. This has been addressed by
        adding a configurable limit to the number of records that can
        be stored per name and type in a cache or zone database. The
        default is 100, which can be tuned with the new
        max-types-per-name option. (CVE-2024-1737)
      * Validating DNS messages signed using the SIG(0) protocol (RFC
        2931) could cause excessive CPU load, leading to a
        denial-of-service condition. Support for SIG(0) message
        validation was removed from this version of named.
        (CVE-2024-1975)
      * Due to a logic error, lookups that triggered serving stale data
        and required lookups in local authoritative zone data could
        have resulted in an assertion failure. This has been fixed.
      * Potential data races were found in our DoH implementation,
        related to HTTP/2 session object management and endpoints set
        object management after reconfiguration. These issues have been
        fixed.
      * When looking up the NS records of parent zones as part of
        looking up DS records, it was possible for named to trigger an
        assertion failure if serve-stale was enabled. This has been
        fixed. (CVE-2024-4076)

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228255");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228256");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228257");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228258");
  script_set_attribute(attribute:"see_also", value:"https://lists.suse.com/pipermail/sle-updates/2024-July/036147.html");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-0760");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-1737");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-1975");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-4076");
  script_set_attribute(attribute:"solution", value:
"Update the affected bind, bind-doc and / or bind-utils packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-1975");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:bind-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:bind-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES|SUSE)") audit(AUDIT_OS_NOT, "SUSE / openSUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)(?:_SAP)?\d+|SUSE([\d.]+))", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE / openSUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED15|SLED_SAP15|SLES15|SLES_SAP15|SUSE15\.6)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED15 / SLED_SAP15 / SLES15 / SLES_SAP15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLED15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED15 SP6", os_ver + " SP" + service_pack);
if (os_ver == "SLED_SAP15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED_SAP15 SP6", os_ver + " SP" + service_pack);
if (os_ver == "SLES15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP6", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP6", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'bind-9.18.28-150600.3.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'bind-doc-9.18.28-150600.3.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'bind-utils-9.18.28-150600.3.3.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'bind-utils-9.18.28-150600.3.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'bind-9.18.28-150600.3.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-server-applications-release-15.6', 'sles-release-15.6']},
    {'reference':'bind-doc-9.18.28-150600.3.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-server-applications-release-15.6', 'sles-release-15.6']},
    {'reference':'bind-utils-9.18.28-150600.3.3.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'bind-utils-9.18.28-150600.3.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'bind-9.18.28-150600.3.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'bind-doc-9.18.28-150600.3.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'bind-utils-9.18.28-150600.3.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']}
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
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bind / bind-doc / bind-utils');
}
