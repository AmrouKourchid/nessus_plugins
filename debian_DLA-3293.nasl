#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3293. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(170888);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/22");

  script_cve_id(
    "CVE-2018-16384",
    "CVE-2020-22669",
    "CVE-2021-35368",
    "CVE-2022-29956",
    "CVE-2022-39955",
    "CVE-2022-39956",
    "CVE-2022-39957",
    "CVE-2022-39958"
  );

  script_name(english:"Debian dla-3293 : modsecurity-crs - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has a package installed that is affected by multiple vulnerabilities as referenced in the
dla-3293 advisory.

    -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3293-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                         Tobias Frost
    January 30, 2023                              https://wiki.debian.org/LTS
    -------------------------------------------------------------------------

    Package        : modsecurity-crs
    Version        : 3.2.3-0+deb10u3
    CVE ID         : CVE-2018-16384 CVE-2020-22669 CVE-2021-35368 CVE-2022-39955
                     CVE-2022-39956 CVE-2022-39957 CVE-2022-39958
    Debian Bug     : 924352 992000 1021137

    Multiple issues were found in modsecurity-crs, a set of generic attack
    detection rules for use with ModSecurity or compatible web application
    firewalls, which allows remote attackers to bypass the web applications
    firewall.

    If you are using modsecurity-crs with apache2 / libapache2-modsecurity, please
    make sure to review your modsecurity configuration, usually
    /etc/modsecurity/modsecurity.conf, against the updated recommended
    configration, available in /etc/modsecurity/modsecurity.conf-recommended:
    Some of the changes to the recommended rules are required to avoid WAF bypasses
    in certain circumstances.

    Please note that CVE-2022-39956 requires an updated modsecurity-apache packge,
    which has been previously uploaded to buster-security, see Debian LTS Advisory
    DLA-3283-1 for details.

    If you are using some other solution in connection with the
    modsecurity-ruleset, for example one that it is using libmodsecurity3, your
    solution might error out with an error message like Error creating rule:
    Unknown variable: MULTIPART_PART_HEADERS. In this case you can disable the
    mitigation for CVE-2022-29956 by removing the rule file
    REQUEST-922-MULTIPART-ATTACK.conf.  However, be aware that this will disable
    the protection and could allow attackers to bypass your Web Application
    Firewall.

    There is no package in Debian which depends on libmodsecurity3, so if you are
    only using software which is available from Debian, you are not affected by
    this limitation.

    Kudos to @airween for the support and help while perparing the update.

    CVE-2018-16384

        A SQL injection bypass (aka PL1 bypass) exists in OWASP ModSecurity Core Rule
        Set (owasp-modsecurity-crs) through v3.1.0-rc3 via {`a`b} where a is a special
        function name (such as if) and b is the SQL statement to be executed.

    CVE-2020-22669

        Modsecurity owasp-modsecurity-crs 3.2.0 (Paranoia level at PL1) has a SQL
        injection bypass vulnerability. Attackers can use the comment characters and
        variable assignments in the SQL syntax to bypass Modsecurity WAF protection and
        implement SQL injection attacks on Web applications.

    CVE-2022-39955

        The OWASP ModSecurity Core Rule Set (CRS) is affected by a partial rule set
        bypass by submitting a specially crafted HTTP Content-Type header field that
        indicates multiple character encoding schemes. A vulnerable back-end can
        potentially be exploited by declaring multiple Content-Type charset names and
        therefore bypassing the configurable CRS Content-Type header charset allow
        list. An encoded payload can bypass CRS detection this way and may then be
        decoded by the backend. The legacy CRS versions 3.0.x and 3.1.x are affected,
        as well as the currently supported versions 3.2.1 and 3.3.2. Integrators and
        users are advised to upgrade to 3.2.2 and 3.3.3 respectively.

    CVE-2022-39956

        The OWASP ModSecurity Core Rule Set (CRS) is affected by a partial rule set
        bypass for HTTP multipart requests by submitting a payload that uses a
        character encoding scheme via the Content-Type or the deprecated
        Content-Transfer-Encoding multipart MIME header fields that will not be decoded
        and inspected by the web application firewall engine and the rule set. The
        multipart payload will therefore bypass detection. A vulnerable backend that
        supports these encoding schemes can potentially be exploited. The legacy CRS
        versions 3.0.x and 3.1.x are affected, as well as the currently supported
        versions 3.2.1 and 3.3.2. Integrators and users are advised upgrade to 3.2.2
        and 3.3.3 respectively. The mitigation against these vulnerabilities depends on
        the installation of the latest ModSecurity version (v2.9.6 / v3.0.8).

    CVE-2022-39957

        The OWASP ModSecurity Core Rule Set (CRS) is affected by a response body
        bypass. A client can issue an HTTP Accept header field containing an optional
        charset parameter in order to receive the response in an encoded form.
        Depending on the charset, this response can not be decoded by the web
        application firewall. A restricted resource, access to which would ordinarily
        be detected, may therefore bypass detection. The legacy CRS versions 3.0.x and
        3.1.x are affected, as well as the currently supported versions 3.2.1 and
        3.3.2. Integrators and users are advised to upgrade to 3.2.2 and 3.3.3
        respectively.

    CVE-2022-39958

        The OWASP ModSecurity Core Rule Set (CRS) is affected by a response body bypass
        to sequentially exfiltrate small and undetectable sections of data by
        repeatedly submitting an HTTP Range header field with a small byte range. A
        restricted resource, access to which would ordinarily be detected, may be
        exfiltrated from the backend, despite being protected by a web application
        firewall that uses CRS. Short subsections of a restricted resource may bypass
        pattern matching techniques and allow undetected access. The legacy CRS
        versions 3.0.x and 3.1.x are affected, as well as the currently supported
        versions 3.2.1 and 3.3.2. Integrators and users are advised to upgrade to 3.2.2
        and 3.3.3 respectively and to configure a CRS paranoia level of 3 or higher.

    For Debian 10 buster, these problems have been fixed in version
    3.2.3-0+deb10u3.

    We recommend that you upgrade your modsecurity-crs packages.

    For the detailed security status of modsecurity-crs please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/modsecurity-crs

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS
    Attachment:
    signature.asc
    Description: PGP signature

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security-tracker.debian.org/tracker/source-package/modsecurity-crs
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?77fb0971");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-16384");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-22669");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-35368");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-29956");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-39955");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-39956");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-39957");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-39958");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/modsecurity-crs");
  script_set_attribute(attribute:"solution", value:
"Upgrade the modsecurity-crs packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-35368");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-39956");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:modsecurity-crs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var debian_release = get_kb_item('Host/Debian/release');
if ( isnull(debian_release) ) audit(AUDIT_OS_NOT, 'Debian');
debian_release = chomp(debian_release);
if (! preg(pattern:"^(10)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'modsecurity-crs', 'reference': '3.2.3-0+deb10u3'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var _release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (_release && prefix && reference) {
    if (deb_check(release:_release, prefix:prefix, reference:reference)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'modsecurity-crs');
}
