#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3160. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(166572);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/22");

  script_cve_id(
    "CVE-2020-9484",
    "CVE-2021-43980",
    "CVE-2022-23181",
    "CVE-2022-29885"
  );
  script_xref(name:"IAVA", value:"2020-A-0225-S");
  script_xref(name:"IAVA", value:"2022-A-0222-S");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"Debian dla-3160 : libtomcat9-embed-java - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3160 advisory.

    -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3160-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                      Markus Koschany
    October 26, 2022                              https://wiki.debian.org/LTS
    -------------------------------------------------------------------------

    Package        : tomcat9
    Version        : 9.0.31-1~deb10u7
    CVE ID         : CVE-2021-43980 CVE-2022-23181 CVE-2022-29885

    Several security vulnerabilities have been discovered in the Tomcat
    servlet and JSP engine.

    CVE-2021-43980

        The simplified implementation of blocking reads and writes introduced in
        Tomcat 10 and back-ported to Tomcat 9.0.47 onwards exposed a long standing
        (but extremely hard to trigger) concurrency bug that could cause client
        connections to share an Http11Processor instance resulting in responses, or
        part responses, to be received by the wrong client.

    CVE-2022-23181

        The fix for bug CVE-2020-9484 introduced a time of check, time of use
        vulnerability into Apache Tomcat that allowed a local attacker to perform
        actions with the privileges of the user that the Tomcat process is using.
        This issue is only exploitable when Tomcat is configured to persist
        sessions using the FileStore.

    CVE-2022-29885

        The documentation of Apache Tomcat for the EncryptInterceptor incorrectly
        stated it enabled Tomcat clustering to run over an untrusted network. This
        was not correct. While the EncryptInterceptor does provide confidentiality
        and integrity protection, it does not protect against all risks associated
        with running over any untrusted network, particularly DoS risks.

    For Debian 10 buster, these problems have been fixed in version
    9.0.31-1~deb10u7.

    We recommend that you upgrade your tomcat9 packages.

    For the detailed security status of tomcat9 please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/tomcat9

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS
    Attachment:
    signature.asc
    Description: This is a digitally signed message part

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/tomcat9");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-9484");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-43980");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-23181");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-29885");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/tomcat9");
  script_set_attribute(attribute:"solution", value:
"Upgrade the libtomcat9-embed-java packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-9484");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-23181");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtomcat9-embed-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtomcat9-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat9-admin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat9-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat9-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat9-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat9-user");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'release': '10.0', 'prefix': 'libtomcat9-embed-java', 'reference': '9.0.31-1~deb10u7'},
    {'release': '10.0', 'prefix': 'libtomcat9-java', 'reference': '9.0.31-1~deb10u7'},
    {'release': '10.0', 'prefix': 'tomcat9', 'reference': '9.0.31-1~deb10u7'},
    {'release': '10.0', 'prefix': 'tomcat9-admin', 'reference': '9.0.31-1~deb10u7'},
    {'release': '10.0', 'prefix': 'tomcat9-common', 'reference': '9.0.31-1~deb10u7'},
    {'release': '10.0', 'prefix': 'tomcat9-docs', 'reference': '9.0.31-1~deb10u7'},
    {'release': '10.0', 'prefix': 'tomcat9-examples', 'reference': '9.0.31-1~deb10u7'},
    {'release': '10.0', 'prefix': 'tomcat9-user', 'reference': '9.0.31-1~deb10u7'}
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
    severity   : SECURITY_WARNING,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libtomcat9-embed-java / libtomcat9-java / tomcat9 / tomcat9-admin / etc');
}
