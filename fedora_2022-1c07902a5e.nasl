#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2022-1c07902a5e
#

include('compat.inc');

if (description)
{
  script_id(169120);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/14");

  script_cve_id(
    "CVE-2022-21618",
    "CVE-2022-21619",
    "CVE-2022-21624",
    "CVE-2022-21626",
    "CVE-2022-21628",
    "CVE-2022-39399"
  );
  script_xref(name:"FEDORA", value:"2022-1c07902a5e");

  script_name(english:"Fedora 35 : java-11-openjdk (2022-1c07902a5e)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 35 host has a package installed that is affected by multiple vulnerabilities as referenced in the
FEDORA-2022-1c07902a5e advisory.

    # New in release OpenJDK 11.0.17 (2022-10-18)

    * [Release announcement](https://bit.ly/openjdk11017)
    * [Full release notes](https://builds.shipilev.net/backports-monitor/release-notes-11.0.7.html)

    ## Security Fixes
      - JDK-8282252: Improve BigInteger/Decimal validation
      - JDK-8285662: Better permission resolution
      - JDK-8286077, CVE-2022-21618: Wider MultiByte conversions
      - JDK-8286511: Improve macro allocation
      - JDK-8286519: Better memory handling
      - JDK-8286526, CVE-2022-21619: Improve NTLM support
      - JDK-8286533, CVE-2022-21626: Key X509 usages
      - JDK-8286910, CVE-2022-21624: Improve JNDI lookups
      - JDK-8286918, CVE-2022-21628: Better HttpServer service
      - JDK-8287446: Enhance icon presentations
      - JDK-8288508: Enhance ECDSA usage
      - JDK-8289366, CVE-2022-39399: Improve HTTP/2 client usage
      - JDK-8289853: Update HarfBuzz to 4.4.1
      - JDK-8290334: Update FreeType to 2.12.1
      - JDK-8293429: [11u] minor update in attribute style

    ## Major Changes

    ### [JDK-8278067](https://bugs.openjdk.org/browse/JDK-8278067): Make HttpURLConnection Default Keep Alive
    Timeout Configurable
    Two system properties have been added which control the keep alive behavior of HttpURLConnection in the
    case where the server does not specify a keep alive time. Two properties are defined for controlling
    connections to servers and proxies separately. They are:

    * `http.keepAlive.time.server`
    * `http.keepAlive.time.proxy`

    respectively. More information about them can be found on the [Networking Properties
    page](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/net/doc-files/net-
    properties.html).

    ### JDK-8286918: Better HttpServer service
    The HttpServer can be optionally configured with a maximum connection limit by setting the
    jdk.httpserver.maxConnections system property. A value of `0` or a negative integer is ignored and
    considered to represent no connection limit. In the case of a positive integer value, any newly accepted
    connections will be first checked against the current count of established connections and, if the
    configured limit has been reached, then the newly accepted connection will be closed immediately.

    ### [JDK-8281181](https://bugs.openjdk.org/browse/JDK-8281181): CPU Shares Ignored When Computing Active
    Processor Count
    Previous JDK releases used an incorrect interpretation of the Linux cgroups parameter cpu.shares. This
    might cause the JVM to use fewer CPUs than available, leading to an under utilization of CPU resources
    when the JVM is used inside a container.

    Starting from this JDK release, by default, the JVM no longer considers cpu.shares when deciding the
    number of threads to be used by the various thread pools. The `-XX:+UseContainerCpuShares` command-line
    option can be used to revert to the previous behaviour. This option is deprecated and may be removed in a
    future JDK release.

    ### [JDK-8269039](https://bugs.openjdk.org/browse/JDK-8269039): Disabled SHA-1 Signed JARs
    JARs signed with SHA-1 algorithms are now restricted by default and treated as if they were unsigned. This
    applies to the algorithms used to digest, sign, and optionally timestamp the JAR. It also applies to the
    signature and digest algorithms of the certificates in the certificate chain of the code signer and the
    Timestamp Authority, and any CRLs or OCSP responses that are used to verify if those certificates have
    been revoked. These restrictions also apply to signed JCE providers.

    To reduce the compatibility risk for JARs that have been previously timestamped, there is one exception to
    this policy:

    - Any JAR signed with SHA-1 algorithms and timestamped prior to January 01, 2019 will not be restricted.

    This exception may be removed in a future JDK release. To determine if your signed JARs are affected by
    this change, run:
    ~~~
    $ jarsigner -verify -verbose -certs`
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

    ### [JDK-8267880](https://bugs.openjdk.org/browse/JDK-8267880): Upgrade the default PKCS12 MAC algorithm
    The default MAC algorithm used in a PKCS #12 keystore has been updated. The new algorithm is based on
    SHA-256 and is stronger than the old one based on SHA-1. See the security properties starting with
    `keystore.pkcs12` in the `java.security` file for detailed information.

    The new SHA-256 based MAC algorithms were introduced in the 11.0.12 release. Keystores created using this
    newer, stronger, MAC algorithm cannot be opened in versions of OpenJDK 11 earlier than 11.0.12. A
    'java.security.NoSuchAlgorithmException' exception will be thrown in such circumstances.

    For compatibility, use the `keystore.pkcs12.legacy` system property, which will revert the algorithms to
    use the older, weaker
    algorithms. There is no value defined for this property.

    ### [JDK-8261160](https://bugs.openjdk.org/browse/JDK-8261160): JDK Flight Recorder Event for
    Deserialization
    It is now possible to monitor deserialization of objects using JDK Flight Recorder (JFR). When JFR is
    enabled and the JFR configuration includes deserialization events, JFR will emit an event whenever the
    running program attempts to deserialize an object. The deserialization event is named
    `jdk.Deserialization`, and it is disabled by default. The deserialization event contains information that
    is used by the serialization filter mechanism; see the ObjectInputFilter API specification for details.

    Additionally, if a filter is enabled, the JFR event indicates whether the filter accepted or rejected
    deserialization of the object. For
    further information about how to use the JFR deserialization event, see the article [Monitoring
    Deserialization to Improve Application Security](https://inside.java/2021/03/02/monitoring-
    deserialization-activity-in-the-jdk/).

    For reference information about using and configuring JFR, see the [JFR Runtime
    Guide](https://docs.oracle.com/javacomponents/jmc-5-5/jfr-runtime-guide/preface_jfrrt.htm#JFRRT165) and
    [JFR Command Reference](https://docs.oracle.com/javacomponents/jmc-5-5/jfr-command-reference/command-
    line-options.htm#JFRCR-GUID-FE61CA60-E1DF-460E-A8E0-F4FF5D58A7A0) sections of the JDK Mission Control
    documentation.

    ### [JDK-8139348](https://bugs.openjdk.org/browse/JDK-8139348): Deprecate 3DES and RC4 in Kerberos
    The `des3-hmac-sha1` and `rc4-hmac` Kerberos encryption types (etypes) are now deprecated and disabled by
    default. Users can set `allow_weak_crypto = true` in the `krb5.conf` configuration file to re-enable them
    (along with other weak etypes including `des-cbc-crc` and `des-cbc-md5`) at their own risk. To disable a
    subset of the weak etypes, users can list preferred etypes explicitly in any of the
    `default_tkt_enctypes`, `default_tgs_enctypes`, or `permitted_enctypes` settings.


Tenable has extracted the preceding description block directly from the Fedora security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2022-1c07902a5e");
  script_set_attribute(attribute:"solution", value:
"Update the affected 1:java-11-openjdk package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-21618");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:35");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:java-11-openjdk");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^35([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 35', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

var pkgs = [
    {'reference':'java-11-openjdk-11.0.17.0.8-2.fc35', 'release':'FC35', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'java-11-openjdk');
}
