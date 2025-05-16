#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5610. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(189755);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/30");

  script_cve_id(
    "CVE-2022-24834",
    "CVE-2023-36824",
    "CVE-2023-41053",
    "CVE-2023-41056",
    "CVE-2023-45145"
  );

  script_name(english:"Debian dsa-5610 : redis - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 12 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5610 advisory.

  - Redis is an in-memory database that persists on disk. A specially crafted Lua script executing in Redis
    can trigger a heap overflow in the cjson library, and result with heap corruption and potentially remote
    code execution. The problem exists in all versions of Redis with Lua scripting support, starting from 2.6,
    and affects only authenticated and authorized users. The problem is fixed in versions 7.0.12, 6.2.13, and
    6.0.20. (CVE-2022-24834)

  - Redis is an in-memory database that persists on disk. In Redit 7.0 prior to 7.0.12, extracting key names
    from a command and a list of arguments may, in some cases, trigger a heap overflow and result in reading
    random heap memory, heap corruption and potentially remote code execution. Several scenarios that may lead
    to authenticated users executing a specially crafted `COMMAND GETKEYS` or `COMMAND GETKEYSANDFLAGS`and
    authenticated users who were set with ACL rules that match key names, executing a specially crafted
    command that refers to a variadic list of key names. The vulnerability is patched in Redis 7.0.12.
    (CVE-2023-36824)

  - Redis is an in-memory database that persists on disk. Redis does not correctly identify keys accessed by
    `SORT_RO` and as a result may grant users executing this command access to keys that are not explicitly
    authorized by the ACL configuration. The problem exists in Redis 7.0 or newer and has been fixed in Redis
    7.0.13 and 7.2.1. Users are advised to upgrade. There are no known workarounds for this vulnerability.
    (CVE-2023-41053)

  - Redis is an in-memory database that persists on disk. Redis incorrectly handles resizing of memory buffers
    which can result in integer overflow that leads to heap overflow and potential remote code execution. This
    issue has been patched in version 7.0.15 and 7.2.4. (CVE-2023-41056)

  - Redis is an in-memory database that persists on disk. On startup, Redis begins listening on a Unix socket
    before adjusting its permissions to the user-provided configuration. If a permissive umask(2) is used,
    this creates a race condition that enables, during a short period of time, another process to establish an
    otherwise unauthorized connection. This problem has existed since Redis 2.6.0-RC1. This issue has been
    addressed in Redis versions 7.2.2, 7.0.14 and 6.2.14. Users are advised to upgrade. For users unable to
    upgrade, it is possible to work around the problem by disabling Unix sockets, starting Redis with a
    restrictive umask, or storing the Unix socket file in a protected directory. (CVE-2023-45145)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/redis");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-24834");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-36824");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-41053");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-41056");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-45145");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bookworm/redis");
  script_set_attribute(attribute:"solution", value:
"Upgrade the redis packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-36824");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/07/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:redis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:redis-sentinel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:redis-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:redis-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:12.0");
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
if (! preg(pattern:"^(12)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 12.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '12.0', 'prefix': 'redis', 'reference': '5:7.0.15-1~deb12u1'},
    {'release': '12.0', 'prefix': 'redis-sentinel', 'reference': '5:7.0.15-1~deb12u1'},
    {'release': '12.0', 'prefix': 'redis-server', 'reference': '5:7.0.15-1~deb12u1'},
    {'release': '12.0', 'prefix': 'redis-tools', 'reference': '5:7.0.15-1~deb12u1'}
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
