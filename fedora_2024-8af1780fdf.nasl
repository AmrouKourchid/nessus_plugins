#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2024-8af1780fdf
#

include('compat.inc');

if (description)
{
  script_id(204983);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/30");

  script_cve_id(
    "CVE-2024-0760",
    "CVE-2024-1737",
    "CVE-2024-1975",
    "CVE-2024-4076"
  );
  script_xref(name:"FEDORA", value:"2024-8af1780fdf");
  script_xref(name:"IAVA", value:"2024-A-0442-S");

  script_name(english:"Fedora 40 : bind / bind-dyndb-ldap (2024-8af1780fdf)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 40 host has packages installed that are affected by multiple vulnerabilities as referenced in the
FEDORA-2024-8af1780fdf advisory.

    # Update to BIND 9.18.28


    ## Security Fixes

    -    A malicious DNS client that sent many queries over TCP but never read the responses could cause a
    server to respond slowly or not at all for other clients. This has been fixed. (CVE-2024-0760) [GL #4481]

    -    It is possible to craft excessively large resource records sets, which have the effect of slowing
    down database processing. This has been addressed by adding a configurable limit to the number of records
    that can be stored per name and type in a cache or zone database. The default is 100, which can be tuned
    with the new max-records-per-type option. [GL #497] [GL #3405]

        It is possible to craft excessively large numbers of resource record types for a given owner name,
    which has the effect of slowing down database processing. This has been addressed by adding a configurable
    limit to the number of records that can be stored per name and type in a cache or zone database. The
    default is 100, which can be tuned with the new max-types-per-name option. (CVE-2024-1737) [GL #3403]

        ISC would like to thank Toshifumi Sakaguchi who independently discovered and responsibly reported the
    issue to ISC. [GL #4548]

    -    Validating DNS messages signed using the SIG(0) protocol (RFC 2931) could cause excessive CPU load,
    leading to a denial-of-service condition. Support for SIG(0) message validation was removed from this
    version of named. (CVE-2024-1975) [GL #4480]

    -    Due to a logic error, lookups that triggered serving stale data and required lookups in local
    authoritative zone data could have resulted in an assertion failure. This has been fixed. (CVE-2024-4076)
    [GL #4507]

    Potential data races were found in our DoH implementation, related to HTTP/2 session object management and
    endpoints set object management after reconfiguration. These issues have been fixed. [GL #4473]

    ISC would like to thank Dzintars and Ivo from nic.lv for bringing this to our attention.

    - When looking up the NS records of parent zones as part of looking up DS records, it was possible for
    named to trigger an assertion failure if serve-stale was enabled. This has been fixed. [GL #4661]

    - Source: https://downloads.isc.org/isc/bind9/9.18.28/doc/arm/html/notes.html


Tenable has extracted the preceding description block directly from the Fedora security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-8af1780fdf");
  script_set_attribute(attribute:"solution", value:
"Update the affected 32:bind and / or bind-dyndb-ldap packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-1975");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:40");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:bind-dyndb-ldap");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Fedora' >!< os_release) audit(AUDIT_OS_NOT, 'Fedora');
var os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Fedora');
os_ver = os_ver[1];
if (! preg(pattern:"^40([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 40', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

var pkgs = [
    {'reference':'bind-9.18.28-2.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind-dyndb-ldap-11.10-29.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bind / bind-dyndb-ldap');
}
