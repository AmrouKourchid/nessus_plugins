#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3885. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(206888);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/10");

  script_cve_id(
    "CVE-2022-24834",
    "CVE-2022-36021",
    "CVE-2023-25155",
    "CVE-2023-28856",
    "CVE-2023-45145"
  );

  script_name(english:"Debian dla-3885 : redis - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3885 advisory.

    - -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3885-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                           Chris Lamb
    September 10, 2024                            https://wiki.debian.org/LTS
    - -------------------------------------------------------------------------

    Package        : redis
    Version        : 5:6.0.16-1+deb11u3
    CVE IDs        : CVE-2023-45145 CVE-2023-28856 CVE-2023-25155 CVE-2022-36021 CVE-2022-24834
    Debian Bugs    : 1032279 1034613 1054225

    It was discovered that there were a number of issues in Redis, a popular
    key-value database:

     * CVE-2023-45145: On startup, Redis began listening on a Unix
       socket before adjusting its permissions to the user-provided
       configuration. If a permissive umask(2) was used, this created a
       race condition that enabled, during a short period of time,
       another process to establish an otherwise unauthorized connection.

     * CVE-2023-28856: Authenticated users could have used the
       HINCRBYFLOAT command to create an invalid hash field that would
       have crashed the Redis server on access.

     * CVE-2023-25155: Authenticated users issuing specially crafted
       SRANDMEMBER, ZRANDMEMBER, and HRANDFIELD commands can trigger an
       integer overflow, resulting in a runtime assertion and termination
       of the Redis server process.

     * CVE-2022-36021: Authenticated users can use string matching
       commands (like SCAN or KEYS) with a specially crafted pattern to
       trigger a denial-of-service attack on Redis, causing it to hang
       and consume 100% CPU time.

     * CVE-2022-24834: A specially-crafted Lua script executing in Redis
       could have triggered a heap overflow in the cjson and cmsgpack
       libraries and result in heap corruption and potentially remote
       code execution.


    For Debian 11 bullseye, these problems have been fixed in version
    5:6.0.16-1+deb11u3.

    We recommend that you upgrade your redis packages.

    For the detailed security status of redis please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/redis

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/redis");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-24834");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-36021");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-25155");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-28856");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-45145");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/redis");
  script_set_attribute(attribute:"solution", value:
"Upgrade the redis packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-24834");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:redis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:redis-sentinel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:redis-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:redis-tools");
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
    {'release': '11.0', 'prefix': 'redis', 'reference': '5:6.0.16-1+deb11u3'},
    {'release': '11.0', 'prefix': 'redis-sentinel', 'reference': '5:6.0.16-1+deb11u3'},
    {'release': '11.0', 'prefix': 'redis-server', 'reference': '5:6.0.16-1+deb11u3'},
    {'release': '11.0', 'prefix': 'redis-tools', 'reference': '5:6.0.16-1+deb11u3'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'redis / redis-sentinel / redis-server / redis-tools');
}
