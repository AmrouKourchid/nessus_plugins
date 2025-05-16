#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-7416-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(233954);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/07");

  script_cve_id("CVE-2016-2385", "CVE-2018-14767", "CVE-2020-28361");
  script_xref(name:"USN", value:"7416-1");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS : Kamailio vulnerabilities (USN-7416-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-7416-1 advisory.

    Stelios Tsampas discovered that Kamailio did not correctly handle certain memory operations, which could
    lead to a buffer overflow. A remote attacker could possibly use this issue to cause a denial of service or
    execute arbitrary code. This issue only affected Ubuntu 16.04 LTS. (CVE-2016-2385)

    Henning Westerholt discovered that Kamailio did not correctly handle duplicated headers, which could lead
    to a segmentation fault. A remote attacker could possibly use this issue to cause a denial of service or
    execute arbitrary code. This issue only affected Ubuntu 16.04 LTS and Ubuntu 18.04 LTS. (CVE-2018-14767)

    It was discovered that Kamailio did not correctly handle parsing certain headers containing whitespace
    characters. An authenticated attacker could possibly use this issue to gain access to unauthorized
    resources and expose sensitive information. This issue only affected Ubuntu 18.04 LTS and Ubuntu 20.04
    LTS. (CVE-2020-28361)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-7416-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-2385");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-14767");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kamailio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kamailio-autheph-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kamailio-berkeley-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kamailio-berkeley-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kamailio-carrierroute-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kamailio-cnxcc-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kamailio-cpl-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kamailio-dnssec-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kamailio-erlang-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kamailio-extra-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kamailio-geoip-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kamailio-geoip2-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kamailio-ims-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kamailio-java-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kamailio-json-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kamailio-kazoo-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kamailio-ldap-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kamailio-lua-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kamailio-memcached-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kamailio-mongodb-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kamailio-mono-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kamailio-mysql-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kamailio-outbound-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kamailio-perl-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kamailio-phonenum-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kamailio-postgres-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kamailio-presence-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kamailio-purple-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kamailio-python-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kamailio-python3-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kamailio-rabbitmq-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kamailio-radius-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kamailio-redis-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kamailio-ruby-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kamailio-sctp-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kamailio-snmpstats-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kamailio-sqlite-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kamailio-systemd-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kamailio-tls-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kamailio-unixodbc-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kamailio-utils-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kamailio-websocket-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kamailio-xml-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kamailio-xmpp-modules");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2025 Canonical, Inc. / NASL script (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "ubuntu_pro_sub_detect.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('16.04' >< os_release || '18.04' >< os_release || '20.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);
var ubuntu_pro_detected = get_kb_item('Host/Ubuntu/Pro/Services/esm-apps');
ubuntu_pro_detected = !empty_or_null(ubuntu_pro_detected);

var pro_caveat_needed = FALSE;

var pkgs = [
    {'osver': '16.04', 'pkgname': 'kamailio', 'pkgver': '4.3.4-1.1ubuntu2.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'kamailio-autheph-modules', 'pkgver': '4.3.4-1.1ubuntu2.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'kamailio-berkeley-bin', 'pkgver': '4.3.4-1.1ubuntu2.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'kamailio-berkeley-modules', 'pkgver': '4.3.4-1.1ubuntu2.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'kamailio-carrierroute-modules', 'pkgver': '4.3.4-1.1ubuntu2.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'kamailio-cnxcc-modules', 'pkgver': '4.3.4-1.1ubuntu2.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'kamailio-cpl-modules', 'pkgver': '4.3.4-1.1ubuntu2.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'kamailio-dnssec-modules', 'pkgver': '4.3.4-1.1ubuntu2.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'kamailio-erlang-modules', 'pkgver': '4.3.4-1.1ubuntu2.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'kamailio-extra-modules', 'pkgver': '4.3.4-1.1ubuntu2.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'kamailio-geoip-modules', 'pkgver': '4.3.4-1.1ubuntu2.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'kamailio-ims-modules', 'pkgver': '4.3.4-1.1ubuntu2.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'kamailio-java-modules', 'pkgver': '4.3.4-1.1ubuntu2.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'kamailio-json-modules', 'pkgver': '4.3.4-1.1ubuntu2.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'kamailio-kazoo-modules', 'pkgver': '4.3.4-1.1ubuntu2.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'kamailio-ldap-modules', 'pkgver': '4.3.4-1.1ubuntu2.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'kamailio-lua-modules', 'pkgver': '4.3.4-1.1ubuntu2.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'kamailio-memcached-modules', 'pkgver': '4.3.4-1.1ubuntu2.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'kamailio-mono-modules', 'pkgver': '4.3.4-1.1ubuntu2.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'kamailio-mysql-modules', 'pkgver': '4.3.4-1.1ubuntu2.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'kamailio-outbound-modules', 'pkgver': '4.3.4-1.1ubuntu2.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'kamailio-perl-modules', 'pkgver': '4.3.4-1.1ubuntu2.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'kamailio-postgres-modules', 'pkgver': '4.3.4-1.1ubuntu2.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'kamailio-presence-modules', 'pkgver': '4.3.4-1.1ubuntu2.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'kamailio-purple-modules', 'pkgver': '4.3.4-1.1ubuntu2.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'kamailio-python-modules', 'pkgver': '4.3.4-1.1ubuntu2.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'kamailio-radius-modules', 'pkgver': '4.3.4-1.1ubuntu2.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'kamailio-redis-modules', 'pkgver': '4.3.4-1.1ubuntu2.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'kamailio-sctp-modules', 'pkgver': '4.3.4-1.1ubuntu2.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'kamailio-snmpstats-modules', 'pkgver': '4.3.4-1.1ubuntu2.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'kamailio-sqlite-modules', 'pkgver': '4.3.4-1.1ubuntu2.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'kamailio-tls-modules', 'pkgver': '4.3.4-1.1ubuntu2.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'kamailio-unixodbc-modules', 'pkgver': '4.3.4-1.1ubuntu2.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'kamailio-utils-modules', 'pkgver': '4.3.4-1.1ubuntu2.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'kamailio-websocket-modules', 'pkgver': '4.3.4-1.1ubuntu2.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'kamailio-xml-modules', 'pkgver': '4.3.4-1.1ubuntu2.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'kamailio-xmpp-modules', 'pkgver': '4.3.4-1.1ubuntu2.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'kamailio', 'pkgver': '5.1.2-1ubuntu2+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'kamailio-autheph-modules', 'pkgver': '5.1.2-1ubuntu2+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'kamailio-berkeley-bin', 'pkgver': '5.1.2-1ubuntu2+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'kamailio-berkeley-modules', 'pkgver': '5.1.2-1ubuntu2+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'kamailio-carrierroute-modules', 'pkgver': '5.1.2-1ubuntu2+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'kamailio-cnxcc-modules', 'pkgver': '5.1.2-1ubuntu2+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'kamailio-cpl-modules', 'pkgver': '5.1.2-1ubuntu2+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'kamailio-erlang-modules', 'pkgver': '5.1.2-1ubuntu2+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'kamailio-extra-modules', 'pkgver': '5.1.2-1ubuntu2+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'kamailio-geoip-modules', 'pkgver': '5.1.2-1ubuntu2+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'kamailio-geoip2-modules', 'pkgver': '5.1.2-1ubuntu2+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'kamailio-ims-modules', 'pkgver': '5.1.2-1ubuntu2+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'kamailio-json-modules', 'pkgver': '5.1.2-1ubuntu2+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'kamailio-kazoo-modules', 'pkgver': '5.1.2-1ubuntu2+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'kamailio-ldap-modules', 'pkgver': '5.1.2-1ubuntu2+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'kamailio-lua-modules', 'pkgver': '5.1.2-1ubuntu2+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'kamailio-memcached-modules', 'pkgver': '5.1.2-1ubuntu2+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'kamailio-mongodb-modules', 'pkgver': '5.1.2-1ubuntu2+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'kamailio-mono-modules', 'pkgver': '5.1.2-1ubuntu2+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'kamailio-mysql-modules', 'pkgver': '5.1.2-1ubuntu2+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'kamailio-outbound-modules', 'pkgver': '5.1.2-1ubuntu2+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'kamailio-perl-modules', 'pkgver': '5.1.2-1ubuntu2+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'kamailio-phonenum-modules', 'pkgver': '5.1.2-1ubuntu2+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'kamailio-postgres-modules', 'pkgver': '5.1.2-1ubuntu2+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'kamailio-presence-modules', 'pkgver': '5.1.2-1ubuntu2+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'kamailio-python-modules', 'pkgver': '5.1.2-1ubuntu2+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'kamailio-rabbitmq-modules', 'pkgver': '5.1.2-1ubuntu2+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'kamailio-radius-modules', 'pkgver': '5.1.2-1ubuntu2+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'kamailio-redis-modules', 'pkgver': '5.1.2-1ubuntu2+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'kamailio-sctp-modules', 'pkgver': '5.1.2-1ubuntu2+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'kamailio-snmpstats-modules', 'pkgver': '5.1.2-1ubuntu2+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'kamailio-sqlite-modules', 'pkgver': '5.1.2-1ubuntu2+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'kamailio-systemd-modules', 'pkgver': '5.1.2-1ubuntu2+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'kamailio-tls-modules', 'pkgver': '5.1.2-1ubuntu2+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'kamailio-unixodbc-modules', 'pkgver': '5.1.2-1ubuntu2+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'kamailio-utils-modules', 'pkgver': '5.1.2-1ubuntu2+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'kamailio-websocket-modules', 'pkgver': '5.1.2-1ubuntu2+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'kamailio-xml-modules', 'pkgver': '5.1.2-1ubuntu2+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'kamailio-xmpp-modules', 'pkgver': '5.1.2-1ubuntu2+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'kamailio', 'pkgver': '5.3.2-1ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'kamailio-autheph-modules', 'pkgver': '5.3.2-1ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'kamailio-berkeley-bin', 'pkgver': '5.3.2-1ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'kamailio-berkeley-modules', 'pkgver': '5.3.2-1ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'kamailio-cnxcc-modules', 'pkgver': '5.3.2-1ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'kamailio-cpl-modules', 'pkgver': '5.3.2-1ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'kamailio-erlang-modules', 'pkgver': '5.3.2-1ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'kamailio-extra-modules', 'pkgver': '5.3.2-1ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'kamailio-geoip-modules', 'pkgver': '5.3.2-1ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'kamailio-geoip2-modules', 'pkgver': '5.3.2-1ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'kamailio-ims-modules', 'pkgver': '5.3.2-1ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'kamailio-json-modules', 'pkgver': '5.3.2-1ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'kamailio-kazoo-modules', 'pkgver': '5.3.2-1ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'kamailio-ldap-modules', 'pkgver': '5.3.2-1ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'kamailio-lua-modules', 'pkgver': '5.3.2-1ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'kamailio-memcached-modules', 'pkgver': '5.3.2-1ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'kamailio-mongodb-modules', 'pkgver': '5.3.2-1ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'kamailio-mono-modules', 'pkgver': '5.3.2-1ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'kamailio-mysql-modules', 'pkgver': '5.3.2-1ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'kamailio-outbound-modules', 'pkgver': '5.3.2-1ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'kamailio-perl-modules', 'pkgver': '5.3.2-1ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'kamailio-phonenum-modules', 'pkgver': '5.3.2-1ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'kamailio-postgres-modules', 'pkgver': '5.3.2-1ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'kamailio-presence-modules', 'pkgver': '5.3.2-1ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'kamailio-python3-modules', 'pkgver': '5.3.2-1ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'kamailio-rabbitmq-modules', 'pkgver': '5.3.2-1ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'kamailio-radius-modules', 'pkgver': '5.3.2-1ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'kamailio-redis-modules', 'pkgver': '5.3.2-1ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'kamailio-ruby-modules', 'pkgver': '5.3.2-1ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'kamailio-sctp-modules', 'pkgver': '5.3.2-1ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'kamailio-snmpstats-modules', 'pkgver': '5.3.2-1ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'kamailio-sqlite-modules', 'pkgver': '5.3.2-1ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'kamailio-systemd-modules', 'pkgver': '5.3.2-1ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'kamailio-tls-modules', 'pkgver': '5.3.2-1ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'kamailio-unixodbc-modules', 'pkgver': '5.3.2-1ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'kamailio-utils-modules', 'pkgver': '5.3.2-1ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'kamailio-websocket-modules', 'pkgver': '5.3.2-1ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'kamailio-xml-modules', 'pkgver': '5.3.2-1ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'kamailio-xmpp-modules', 'pkgver': '5.3.2-1ubuntu0.1~esm2', 'ubuntu_pro': TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var osver = NULL;
  var pkgname = NULL;
  var pkgver = NULL;
  if (!empty_or_null(package_array['osver'])) osver = package_array['osver'];
  if (!empty_or_null(package_array['pkgname'])) pkgname = package_array['pkgname'];
  if (!empty_or_null(package_array['pkgver'])) pkgver = package_array['pkgver'];
  var pro_required = NULL;
  if (!empty_or_null(package_array['ubuntu_pro'])) pro_required = package_array['ubuntu_pro'];
  if (osver && pkgname && pkgver) {
    if (ubuntu_check(osver:osver, pkgname:pkgname, pkgver:pkgver)) {
        flag++;
        if (!ubuntu_pro_detected && !pro_caveat_needed) pro_caveat_needed = pro_required;
    }
  }
}

if (flag)
{
  var extra = '';
  if (pro_caveat_needed) {
    extra += 'NOTE: This vulnerability check contains fixes that apply to packages only \n';
    extra += 'available in Ubuntu ESM repositories. Access to these package security updates \n';
    extra += 'require an Ubuntu Pro subscription.\n\n';
  }
  extra += ubuntu_report_get();
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : extra
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kamailio / kamailio-autheph-modules / kamailio-berkeley-bin / etc');
}
