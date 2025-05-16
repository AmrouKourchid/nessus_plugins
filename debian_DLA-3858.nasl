#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3858. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(206420);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/02");

  script_cve_id(
    "CVE-2021-33621",
    "CVE-2022-28739",
    "CVE-2023-28755",
    "CVE-2023-28756",
    "CVE-2023-36617",
    "CVE-2024-27280",
    "CVE-2024-27281",
    "CVE-2024-27282"
  );

  script_name(english:"Debian dla-3858 : libruby2.7 - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3858 advisory.

    - -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3858-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                      Sylvain Beucler
    September 02, 2024                            https://wiki.debian.org/LTS
    - -------------------------------------------------------------------------

    Package        : ruby2.7
    Version        : 2.7.4-1+deb11u2
    CVE ID         : CVE-2021-33621 CVE-2022-28739 CVE-2023-28755 CVE-2023-28756
                     CVE-2023-36617 CVE-2024-27280 CVE-2024-27281 CVE-2024-27282
    Debian Bug     : 1009957 1024799 1038408 1067802 1069966 1069968

    Several vulnerabilities have been discovered in the interpreter for
    the Ruby language, which may result in denial-of-service (DoS),
    information leak, and remote code execution.

    CVE-2021-33621

        The cgi gem allows HTTP response splitting. This is relevant to
        applications that use untrusted user input either to generate an
        HTTP response or to create a CGI::Cookie object.

    CVE-2022-28739

        Buffer over-read occurs in String-to-Float conversion, including
        Kernel#Float and String#to_f.

    CVE-2023-28755

        A ReDoS issue was discovered in the URI component. The URI parser
        mishandles invalid URLs that have specific characters. It causes
        an increase in execution time for parsing strings to URI objects.

    CVE-2023-28756

        A ReDoS issue was discovered in the Time component. The Time
        parser mishandles invalid URLs that have specific characters. It
        causes an increase in execution time for parsing strings to Time
        objects.

    CVE-2023-36617

        Follow-up fix for CVE-2023-28755.

    CVE-2024-27280

        A buffer-overread issue was discovered in StringIO. The ungetbyte
        and ungetc methods on a StringIO can read past the end of a
        string, and a subsequent call to StringIO.gets may return the
        memory value.

    CVE-2024-27281

        When parsing .rdoc_options (used for configuration in RDoc) as a
        YAML file, object injection and resultant remote code execution
        are possible because there are no restrictions on the classes that
        can be restored. (When loading the documentation cache, object
        injection and resultant remote code execution are also possible if
        there were a crafted cache.)

    CVE-2024-27282

        If attacker-supplied data is provided to the Ruby regex compiler,
        it is possible to extract arbitrary heap data relative to the
        start of the text, including pointers and sensitive strings.

    For Debian 11 bullseye, these problems have been fixed in version
    2.7.4-1+deb11u2.

    We recommend that you upgrade your ruby2.7 packages.

    For the detailed security status of ruby2.7 please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/ruby2.7

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/ruby2.7");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-33621");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-28739");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-28755");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-28756");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-36617");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-27280");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-27281");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-27282");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/ruby2.7");
  script_set_attribute(attribute:"solution", value:
"Upgrade the libruby2.7 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-28739");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-33621");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libruby2.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby2.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby2.7-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby2.7-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(11)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 11.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'libruby2.7', 'reference': '2.7.4-1+deb11u2'},
    {'release': '11.0', 'prefix': 'ruby2.7', 'reference': '2.7.4-1+deb11u2'},
    {'release': '11.0', 'prefix': 'ruby2.7-dev', 'reference': '2.7.4-1+deb11u2'},
    {'release': '11.0', 'prefix': 'ruby2.7-doc', 'reference': '2.7.4-1+deb11u2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libruby2.7 / ruby2.7 / ruby2.7-dev / ruby2.7-doc');
}
