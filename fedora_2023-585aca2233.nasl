#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2023-585aca2233
#

include('compat.inc');

if (description)
{
  script_id(170872);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/14");

  script_cve_id("CVE-2023-21835", "CVE-2023-21843");
  script_xref(name:"FEDORA", value:"2023-585aca2233");

  script_name(english:"Fedora 37 : java-17-openjdk (2023-585aca2233)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 37 host has a package installed that is affected by multiple vulnerabilities as referenced in the
FEDORA-2023-585aca2233 advisory.

    # New in release [OpenJDK 17.0.6](https://bit.ly/openjdk1706) (2023-01-17)

    ## CVEs Fixed

      - CVE-2023-21835
      - CVE-2023-21843

    ## Security Fixes

      - JDK-8286070: Improve UTF8 representation
      - JDK-8286496: Improve Thread labels
      - JDK-8287411: Enhance DTLS performance
      - JDK-8288516: Enhance font creation
      - JDK-8289350: Better media supports
      - JDK-8293554: Enhanced DH Key Exchanges
      - JDK-8293598: Enhance InetAddress address handling
      - JDK-8293717: Objective view of ObjectView
      - JDK-8293734: Improve BMP image handling
      - JDK-8293742: Better Banking of Sounds
      - JDK-8295687: Better BMP bounds

    ## Major Changes

    ### JDK-8295687: Better BMP bounds

    Loading a linked ICC profile within a BMP image is now disabled by default. To re-enable it, set the new
    system property
    `sun.imageio.bmp.enabledLinkedProfiles` to `true`.  This new property replaces the old property,
    `sun.imageio.plugins.bmp.disableLinkedProfiles`.

    ### JDK-8293742: Better Banking of Sounds

    Previously, the SoundbankReader implementation, `com.sun.media.sound.JARSoundbankReader`, would download a
    JAR soundbank from a URL.  This behaviour is now disabled by default. To re-enable it, set the new system
    property `jdk.sound.jarsoundbank` to `true`.

    ### [JDK-8282730](https://bugs.openjdk.org/browse/JDK-8282730): New Implementation Note for LoginModule on
    Removing Null from a Principals or Credentials Set

    Back in OpenJDK 9, [JDK-8015081](https://bugs.openjdk.org/browse/JDK-8015081) changed the `Set`
    implementation used to hold principals and credentials so that it rejected `null` values. Attempts to call
    `add(null)`, `contains(null)` or `remove(null)` were changed to throw a `NullPointerException`.

    However, the `logout()` methods in the `LoginModule` implementations within the JDK were not updated to
    check for `null` values, which may occur in the event of a failed login. As a result, a `logout()` call
    may throw a `NullPointerException`.

    The `LoginModule` implementations have now been updated with such checks and an implementation note added
    to the specification to suggest that the same change is made in third party modules.  Developers of third
    party modules are advised to verify that their `logout()` method does not throw a `NullPointerException`.

    ### JDK-8287411: Enhance DTLS performance

    The JDK now exchanges DTLS cookies for all handshakes, new and resumed. The previous behaviour can be re-
    enabled by setting the new system property `jdk.tls.enableDtlsResumeCookie` to `false`.

    ### FIPS Changes

    Previous releases hardcoded the NSS database password used in FIPS mode to be the empty string, preventing
    the use of databases which had another PIN set. This release now allows both the database location and its
    PIN to be configured using the properties `fips.nssdb.path` and `fips.nssdb.pin` respectively. The
    properties can be set either permanently in the `java.security` file or at runtime using the
    `-Dfips.nssdb.path` or `-Dfips.nssdb.pin` arguments to the JVM. The default values of both remain as
    before.




Tenable has extracted the preceding description block directly from the Fedora security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-585aca2233");
  script_set_attribute(attribute:"solution", value:
"Update the affected 1:java-17-openjdk package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-21843");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:37");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:java-17-openjdk");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^37([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 37', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

var pkgs = [
    {'reference':'java-17-openjdk-17.0.6.0.10-1.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
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
      severity   : SECURITY_NOTE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'java-17-openjdk');
}
