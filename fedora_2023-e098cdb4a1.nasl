#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2023-e098cdb4a1
#

include('compat.inc');

if (description)
{
  script_id(170999);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/14");

  script_cve_id("CVE-2023-21830", "CVE-2023-21843");
  script_xref(name:"FEDORA", value:"2023-e098cdb4a1");

  script_name(english:"Fedora 36 : java-1.8.0-openjdk (2023-e098cdb4a1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 36 host has a package installed that is affected by multiple vulnerabilities as referenced in the
FEDORA-2023-e098cdb4a1 advisory.

    # New in release [OpenJDK 8u362](https://bit.ly/openjdk8u362)  (2023-01-17)

    ## CVEs Fixed

      - CVE-2023-21830
      - CVE-2023-21843

    ## Security Fixes

      - JDK-8285021: Improve CORBA communication
      - JDK-8286496: Improve Thread labels
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

    ### JDK-8285021: Improve CORBA communication

    The JDK's CORBA implementation now refuses by default to deserialize objects, unless they have the
    `IOR:` prefix.  The previous behaviour can be re-enabled by setting the new property
    `com.sun.CORBA.ORBAllowDeserializeObject` to `true`.

    ### [JDK-8269039](https://bugs.openjdk.org/browse/JDK-8269039): Disabled SHA-1 Signed JARs

    JARs signed with SHA-1 algorithms are now restricted by default and created as if they were unsigned. This
    applies to the algorithms used to digest, sign, and optionally timestamp the JAR. It also applies to the
    signature and digest algorithms of the certificates in the
    certificate chain of the code signer and the Timestamp Authority, and any CRLs or OCSP responses that are
    used to verify if those
    certificates have been revoked. These restrictions also apply to signed JCE providers.

    To reduce the compatibility risk for JARs that have been previously timestamped, there is one exception to
    this policy:

    - Any JAR signed with SHA-1 algorithms and timestamped prior to   January 01, 2019 will not be restricted.

    This exception may be removed in a future JDK release. To determine if your signed JARs are affected by
    this change, run:
    ~~~
    $ jarsigner -verify -verbose -certs
    ~~~
    on the signed JAR, and look for instances of SHA1 or SHA-1 and disabled and a warning that the JAR
    will be treated as unsigned in the output.

    For example:
    ~~~
       Signed by CN=Signer
       Digest algorithm: SHA-1 (disabled)
       Signature algorithm: SHA1withRSA (disabled), 2048-bit key

       WARNING: The jar will be treated as unsigned, because it is signed with a weak algorithm that is now
    disabled by the security property:

       jdk.jar.disabledAlgorithms=MD2, MD5, RSA keySize < 1024, DSA keySize < 1024, SHA1 denyAfter 2019-01-01
    ~~~
    JARs affected by these new restrictions should be replaced or re-signed with stronger algorithms.

    Users can, *at their own risk*, remove these restrictions by modifying the `java.security` configuration
    file (or override it by using the `java.security.properties` system property) and removing SHA1 usage
    SignedJAR & denyAfter 2019-01-01 from the
    `jdk.certpath.disabledAlgorithms` security property and SHA1 denyAfter 2019-01-01 from the
    `jdk.jar.disabledAlgorithms` security property.



Tenable has extracted the preceding description block directly from the Fedora security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-e098cdb4a1");
  script_set_attribute(attribute:"solution", value:
"Update the affected 1:java-1.8.0-openjdk package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-21830");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:36");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:java-1.8.0-openjdk");
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
if (! preg(pattern:"^36([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 36', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

var pkgs = [
    {'reference':'java-1.8.0-openjdk-1.8.0.362.b09-1.fc36', 'release':'FC36', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
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
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'java-1.8.0-openjdk');
}
