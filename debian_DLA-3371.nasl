#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3371. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(214466);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/22");

  script_cve_id(
    "CVE-2020-28935",
    "CVE-2022-3204",
    "CVE-2022-30698",
    "CVE-2022-30699"
  );

  script_name(english:"Debian dla-3371 : libunbound-dev - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3371 advisory.

    -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3371-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                      Markus Koschany
    March 29, 2023                                https://wiki.debian.org/LTS
    -------------------------------------------------------------------------

    Package        : unbound
    Version        : 1.9.0-2+deb10u3
    CVE ID         : CVE-2020-28935 CVE-2022-3204 CVE-2022-30698 CVE-2022-30699
    Debian Bug     : 1016493 977165

    Several security vulnerabilities have been discovered in unbound, a validating,
    recursive, caching DNS resolver.

    CVE-2022-3204

     A vulnerability named 'Non-Responsive Delegation Attack' (NRDelegation
     Attack) has been discovered in various DNS resolving software. The
     NRDelegation Attack works by having a malicious delegation with a
     considerable number of non responsive nameservers. The attack starts by
     querying a resolver for a record that relies on those unresponsive
     nameservers. The attack can cause a resolver to spend a lot of
     time/resources resolving records under a malicious delegation point where a
     considerable number of unresponsive NS records reside. It can trigger high
     CPU usage in some resolver implementations that continually look in the
     cache for resolved NS records in that delegation. This can lead to degraded
     performance and eventually denial of service in orchestrated attacks.
     Unbound does not suffer from high CPU usage, but resources are still needed
     for resolving the malicious delegation. Unbound will keep trying to resolve
     the record until hard limits are reached. Based on the nature of the attack
     and the replies, different limits could be reached. From now on Unbound
     introduces fixes for better performance when under load, by cutting
     opportunistic queries for nameserver discovery and DNSKEY prefetching and
     limiting the number of times a delegation point can issue a cache lookup
     for missing records.

    CVE-2022-30698 and CVE-2022-30699

     Unbound is vulnerable to a novel type of the ghost domain names attack.
     The vulnerability works by targeting an Unbound instance.
     Unbound is queried for a rogue domain name when the cached delegation
     information is about to expire. The rogue nameserver delays the response so
     that the cached delegation information is expired. Upon receiving the
     delayed answer containing the delegation information, Unbound overwrites
     the now expired entries. This action can be repeated when the delegation
     information is about to expire making the rogue delegation information
     ever-updating. From now on Unbound stores the start time for a query and
     uses that to decide if the cached delegation information can be
     overwritten.

    CVE-2020-28935

     Unbound contains a local vulnerability that would allow for a local symlink
     attack.

    For Debian 10 buster, these problems have been fixed in version
    1.9.0-2+deb10u3.

    We recommend that you upgrade your unbound packages.

    For the detailed security status of unbound please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/unbound

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS
    Attachment:
    signature.asc
    Description: This is a digitally signed message part

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/unbound");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-28935");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-30698");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-30699");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3204");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/unbound");
  script_set_attribute(attribute:"solution", value:
"Upgrade the libunbound-dev packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-28935");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-30699");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libunbound-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libunbound8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-unbound");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-unbound");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:unbound");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:unbound-anchor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:unbound-host");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'release': '10.0', 'prefix': 'libunbound-dev', 'reference': '1.9.0-2+deb10u3'},
    {'release': '10.0', 'prefix': 'libunbound8', 'reference': '1.9.0-2+deb10u3'},
    {'release': '10.0', 'prefix': 'python-unbound', 'reference': '1.9.0-2+deb10u3'},
    {'release': '10.0', 'prefix': 'python3-unbound', 'reference': '1.9.0-2+deb10u3'},
    {'release': '10.0', 'prefix': 'unbound', 'reference': '1.9.0-2+deb10u3'},
    {'release': '10.0', 'prefix': 'unbound-anchor', 'reference': '1.9.0-2+deb10u3'},
    {'release': '10.0', 'prefix': 'unbound-host', 'reference': '1.9.0-2+deb10u3'}
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
    severity   : SECURITY_NOTE,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libunbound-dev / libunbound8 / python-unbound / python3-unbound / etc');
}
