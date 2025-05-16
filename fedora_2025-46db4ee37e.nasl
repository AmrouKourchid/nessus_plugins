#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2025-46db4ee37e
#

include('compat.inc');

if (description)
{
  script_id(215162);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/09");

  script_cve_id("CVE-2025-0638");
  script_xref(name:"FEDORA", value:"2025-46db4ee37e");

  script_name(english:"Fedora 40 : rust-routinator (2025-46db4ee37e)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 40 host has a package installed that is affected by a vulnerability as referenced in the
FEDORA-2025-46db4ee37e advisory.

    ## New

    * ASPA support is now always compiled in and available if `enable-aspa` is set. The `aspa` Cargo feature
    has been removed. ([#990])
    * If merging mutliple ASPA objects for a single customer ASN results in more than 16,380 provider ASNs,
    the ASPA is dropped. (Note that ASPA objects with more than 16,380 provider ASNs are already rejected
    during parsing.) ([#996])
    * New `archive-stats` command that shows some statistics of an RRDP archive. ([#982])
    * Re-enabled the use of GZIP compression in HTTP request sent by the RRDP collector. Measures to deal with
    exploding data have been implemented in [rpki-rs#319]. ([#997])

    ## Bug fixes

    * Fixed an issue with checking the file names in manifests that let to a crash when non-ASCII characters
    are used. ([rpki-rs#320], reported by Haya Schulmann and Niklas Vogel of Goethe University
    Frankfurt/ATHENE Center and assigned [CVE-2025-0638])
    * The validation HTTP endpoints now accept prefixes with non-zero host bits. ([#987])
    * Removed duplicate `rtr_client_reset_queries` in HTTP metrics. ([#992] by [@sleinen])
    * Improved disk space consumption of the new RRDP archives by re-using empty space when updating an object
    and padding all objects to a multiple of 256 bytes. ([#982])

    [#980]: https://github.com/NLnetLabs/routinator/pull/980
    [#982]: https://github.com/NLnetLabs/routinator/pull/982
    [#987]: https://github.com/NLnetLabs/routinator/pull/987
    [#990]: https://github.com/NLnetLabs/routinator/pull/990
    [#992]: https://github.com/NLnetLabs/routinator/pull/992
    [#994]: https://github.com/NLnetLabs/routinator/pull/994
    [#996]: https://github.com/NLnetLabs/routinator/pull/996
    [#997]: https://github.com/NLnetLabs/routinator/pull/997
    [#999]: https://github.com/NLnetLabs/routinator/pull/999
    [@sleinen]: https://github.com/sleinen
    [rpki-rs#319]: https://github.com/NLnetLabs/rpki-rs/pull/319
    [rpki-rs#320]: https://github.com/NLnetLabs/rpki-rs/pull/320
    [ui-0.4.3]: https://github.com/NLnetLabs/routinator-ui/releases/tag/v0.4.3
    [CVE-2025-0638]: https://www.nlnetlabs.nl/downloads/routinator/CVE-2025-0638.txt


Tenable has extracted the preceding description block directly from the Fedora security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-46db4ee37e");
  script_set_attribute(attribute:"solution", value:
"Update the affected rust-routinator package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-0638");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/01/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:40");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-routinator");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'rust-routinator-0.14.1-2.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'rust-routinator');
}
