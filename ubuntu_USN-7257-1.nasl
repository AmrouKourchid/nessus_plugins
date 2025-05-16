#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-7257-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(214997);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/05");

  script_cve_id("CVE-2024-3596");
  script_xref(name:"USN", value:"7257-1");

  script_name(english:"Ubuntu 14.04 LTS / 16.04 LTS / 18.04 LTS / 20.04 LTS / 22.04 LTS / 24.04 LTS / 24.10 : Kerberos vulnerability (USN-7257-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS / 16.04 LTS / 18.04 LTS / 20.04 LTS / 22.04 LTS / 24.04 LTS / 24.10 host has packages
installed that are affected by a vulnerability as referenced in the USN-7257-1 advisory.

    Goldberg, Miro Haller, Nadia Heninger, Mike Milano, Dan Shumow, Marc Stevens, and Adam Suhl discovered
    that Kerberos incorrectly authenticated certain responses. An attacker able to intercept communications
    between a RADIUS client and server could possibly use this issue to forge responses, bypass
    authentication, and access network devices and services.

    This update introduces support for the Message-Authenticator attribute in non-EAP authentication methods
    for communications between Kerberos and a RADIUS server.

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-7257-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_supplemental", value:"CVSS:4.0/R:A");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:U");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-3596");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:24.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:24.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-admin-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-gss-samples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-k5tls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-kdc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-kdc-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-kpropd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-locales");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-multidev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-otp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-pkinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-user");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgssapi-krb5-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgssrpc4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgssrpc4t64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libk5crypto3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkadm5clnt-mit11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkadm5clnt-mit12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkadm5clnt-mit9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkadm5srv-mit11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkadm5srv-mit12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkadm5srv-mit8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkadm5srv-mit9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkdb5-10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkdb5-10t64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkdb5-7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkdb5-8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkdb5-9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkrad-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkrad0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkrb5-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkrb5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkrb5support0");
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
if (! ('14.04' >< os_release || '16.04' >< os_release || '18.04' >< os_release || '20.04' >< os_release || '22.04' >< os_release || '24.04' >< os_release || '24.10' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 14.04 / 16.04 / 18.04 / 20.04 / 22.04 / 24.04 / 24.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);
var ubuntu_pro_detected = get_kb_item('Host/Ubuntu/Pro/Services/esm-apps');
ubuntu_pro_detected = !empty_or_null(ubuntu_pro_detected);

var pro_caveat_needed = FALSE;

var pkgs = [
    {'osver': '14.04', 'pkgname': 'krb5-admin-server', 'pkgver': '1.12+dfsg-2ubuntu5.4+esm6', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'krb5-gss-samples', 'pkgver': '1.12+dfsg-2ubuntu5.4+esm6', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'krb5-kdc', 'pkgver': '1.12+dfsg-2ubuntu5.4+esm6', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'krb5-kdc-ldap', 'pkgver': '1.12+dfsg-2ubuntu5.4+esm6', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'krb5-locales', 'pkgver': '1.12+dfsg-2ubuntu5.4+esm6', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'krb5-multidev', 'pkgver': '1.12+dfsg-2ubuntu5.4+esm6', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'krb5-otp', 'pkgver': '1.12+dfsg-2ubuntu5.4+esm6', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'krb5-pkinit', 'pkgver': '1.12+dfsg-2ubuntu5.4+esm6', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'krb5-user', 'pkgver': '1.12+dfsg-2ubuntu5.4+esm6', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'libgssapi-krb5-2', 'pkgver': '1.12+dfsg-2ubuntu5.4+esm6', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'libgssrpc4', 'pkgver': '1.12+dfsg-2ubuntu5.4+esm6', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'libk5crypto3', 'pkgver': '1.12+dfsg-2ubuntu5.4+esm6', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'libkadm5clnt-mit9', 'pkgver': '1.12+dfsg-2ubuntu5.4+esm6', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'libkadm5srv-mit8', 'pkgver': '1.12+dfsg-2ubuntu5.4+esm6', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'libkadm5srv-mit9', 'pkgver': '1.12+dfsg-2ubuntu5.4+esm6', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'libkdb5-7', 'pkgver': '1.12+dfsg-2ubuntu5.4+esm6', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'libkrad-dev', 'pkgver': '1.12+dfsg-2ubuntu5.4+esm6', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'libkrad0', 'pkgver': '1.12+dfsg-2ubuntu5.4+esm6', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'libkrb5-3', 'pkgver': '1.12+dfsg-2ubuntu5.4+esm6', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'libkrb5-dev', 'pkgver': '1.12+dfsg-2ubuntu5.4+esm6', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'libkrb5support0', 'pkgver': '1.12+dfsg-2ubuntu5.4+esm6', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'krb5-admin-server', 'pkgver': '1.13.2+dfsg-5ubuntu2.2+esm6', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'krb5-gss-samples', 'pkgver': '1.13.2+dfsg-5ubuntu2.2+esm6', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'krb5-k5tls', 'pkgver': '1.13.2+dfsg-5ubuntu2.2+esm6', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'krb5-kdc', 'pkgver': '1.13.2+dfsg-5ubuntu2.2+esm6', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'krb5-kdc-ldap', 'pkgver': '1.13.2+dfsg-5ubuntu2.2+esm6', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'krb5-locales', 'pkgver': '1.13.2+dfsg-5ubuntu2.2+esm6', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'krb5-multidev', 'pkgver': '1.13.2+dfsg-5ubuntu2.2+esm6', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'krb5-otp', 'pkgver': '1.13.2+dfsg-5ubuntu2.2+esm6', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'krb5-pkinit', 'pkgver': '1.13.2+dfsg-5ubuntu2.2+esm6', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'krb5-user', 'pkgver': '1.13.2+dfsg-5ubuntu2.2+esm6', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libgssapi-krb5-2', 'pkgver': '1.13.2+dfsg-5ubuntu2.2+esm6', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libgssrpc4', 'pkgver': '1.13.2+dfsg-5ubuntu2.2+esm6', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libk5crypto3', 'pkgver': '1.13.2+dfsg-5ubuntu2.2+esm6', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libkadm5clnt-mit9', 'pkgver': '1.13.2+dfsg-5ubuntu2.2+esm6', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libkadm5srv-mit9', 'pkgver': '1.13.2+dfsg-5ubuntu2.2+esm6', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libkdb5-8', 'pkgver': '1.13.2+dfsg-5ubuntu2.2+esm6', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libkrad-dev', 'pkgver': '1.13.2+dfsg-5ubuntu2.2+esm6', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libkrad0', 'pkgver': '1.13.2+dfsg-5ubuntu2.2+esm6', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libkrb5-3', 'pkgver': '1.13.2+dfsg-5ubuntu2.2+esm6', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libkrb5-dev', 'pkgver': '1.13.2+dfsg-5ubuntu2.2+esm6', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libkrb5support0', 'pkgver': '1.13.2+dfsg-5ubuntu2.2+esm6', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'krb5-admin-server', 'pkgver': '1.16-2ubuntu0.4+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'krb5-gss-samples', 'pkgver': '1.16-2ubuntu0.4+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'krb5-k5tls', 'pkgver': '1.16-2ubuntu0.4+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'krb5-kdc', 'pkgver': '1.16-2ubuntu0.4+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'krb5-kdc-ldap', 'pkgver': '1.16-2ubuntu0.4+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'krb5-kpropd', 'pkgver': '1.16-2ubuntu0.4+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'krb5-locales', 'pkgver': '1.16-2ubuntu0.4+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'krb5-multidev', 'pkgver': '1.16-2ubuntu0.4+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'krb5-otp', 'pkgver': '1.16-2ubuntu0.4+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'krb5-pkinit', 'pkgver': '1.16-2ubuntu0.4+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'krb5-user', 'pkgver': '1.16-2ubuntu0.4+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libgssapi-krb5-2', 'pkgver': '1.16-2ubuntu0.4+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libgssrpc4', 'pkgver': '1.16-2ubuntu0.4+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libk5crypto3', 'pkgver': '1.16-2ubuntu0.4+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libkadm5clnt-mit11', 'pkgver': '1.16-2ubuntu0.4+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libkadm5srv-mit11', 'pkgver': '1.16-2ubuntu0.4+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libkdb5-9', 'pkgver': '1.16-2ubuntu0.4+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libkrad-dev', 'pkgver': '1.16-2ubuntu0.4+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libkrad0', 'pkgver': '1.16-2ubuntu0.4+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libkrb5-3', 'pkgver': '1.16-2ubuntu0.4+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libkrb5-dev', 'pkgver': '1.16-2ubuntu0.4+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libkrb5support0', 'pkgver': '1.16-2ubuntu0.4+esm3', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'krb5-admin-server', 'pkgver': '1.17-6ubuntu4.8', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'krb5-gss-samples', 'pkgver': '1.17-6ubuntu4.8', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'krb5-k5tls', 'pkgver': '1.17-6ubuntu4.8', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'krb5-kdc', 'pkgver': '1.17-6ubuntu4.8', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'krb5-kdc-ldap', 'pkgver': '1.17-6ubuntu4.8', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'krb5-kpropd', 'pkgver': '1.17-6ubuntu4.8', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'krb5-locales', 'pkgver': '1.17-6ubuntu4.8', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'krb5-multidev', 'pkgver': '1.17-6ubuntu4.8', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'krb5-otp', 'pkgver': '1.17-6ubuntu4.8', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'krb5-pkinit', 'pkgver': '1.17-6ubuntu4.8', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'krb5-user', 'pkgver': '1.17-6ubuntu4.8', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libgssapi-krb5-2', 'pkgver': '1.17-6ubuntu4.8', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libgssrpc4', 'pkgver': '1.17-6ubuntu4.8', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libk5crypto3', 'pkgver': '1.17-6ubuntu4.8', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libkadm5clnt-mit11', 'pkgver': '1.17-6ubuntu4.8', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libkadm5srv-mit11', 'pkgver': '1.17-6ubuntu4.8', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libkdb5-9', 'pkgver': '1.17-6ubuntu4.8', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libkrad-dev', 'pkgver': '1.17-6ubuntu4.8', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libkrad0', 'pkgver': '1.17-6ubuntu4.8', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libkrb5-3', 'pkgver': '1.17-6ubuntu4.8', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libkrb5-dev', 'pkgver': '1.17-6ubuntu4.8', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libkrb5support0', 'pkgver': '1.17-6ubuntu4.8', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'krb5-admin-server', 'pkgver': '1.19.2-2ubuntu0.5', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'krb5-gss-samples', 'pkgver': '1.19.2-2ubuntu0.5', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'krb5-k5tls', 'pkgver': '1.19.2-2ubuntu0.5', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'krb5-kdc', 'pkgver': '1.19.2-2ubuntu0.5', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'krb5-kdc-ldap', 'pkgver': '1.19.2-2ubuntu0.5', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'krb5-kpropd', 'pkgver': '1.19.2-2ubuntu0.5', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'krb5-locales', 'pkgver': '1.19.2-2ubuntu0.5', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'krb5-multidev', 'pkgver': '1.19.2-2ubuntu0.5', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'krb5-otp', 'pkgver': '1.19.2-2ubuntu0.5', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'krb5-pkinit', 'pkgver': '1.19.2-2ubuntu0.5', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'krb5-user', 'pkgver': '1.19.2-2ubuntu0.5', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'libgssapi-krb5-2', 'pkgver': '1.19.2-2ubuntu0.5', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'libgssrpc4', 'pkgver': '1.19.2-2ubuntu0.5', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'libk5crypto3', 'pkgver': '1.19.2-2ubuntu0.5', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'libkadm5clnt-mit12', 'pkgver': '1.19.2-2ubuntu0.5', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'libkadm5srv-mit12', 'pkgver': '1.19.2-2ubuntu0.5', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'libkdb5-10', 'pkgver': '1.19.2-2ubuntu0.5', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'libkrad-dev', 'pkgver': '1.19.2-2ubuntu0.5', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'libkrad0', 'pkgver': '1.19.2-2ubuntu0.5', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'libkrb5-3', 'pkgver': '1.19.2-2ubuntu0.5', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'libkrb5-dev', 'pkgver': '1.19.2-2ubuntu0.5', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'libkrb5support0', 'pkgver': '1.19.2-2ubuntu0.5', 'ubuntu_pro': FALSE},
    {'osver': '24.04', 'pkgname': 'krb5-admin-server', 'pkgver': '1.20.1-6ubuntu2.3', 'ubuntu_pro': FALSE},
    {'osver': '24.04', 'pkgname': 'krb5-gss-samples', 'pkgver': '1.20.1-6ubuntu2.3', 'ubuntu_pro': FALSE},
    {'osver': '24.04', 'pkgname': 'krb5-k5tls', 'pkgver': '1.20.1-6ubuntu2.3', 'ubuntu_pro': FALSE},
    {'osver': '24.04', 'pkgname': 'krb5-kdc', 'pkgver': '1.20.1-6ubuntu2.3', 'ubuntu_pro': FALSE},
    {'osver': '24.04', 'pkgname': 'krb5-kdc-ldap', 'pkgver': '1.20.1-6ubuntu2.3', 'ubuntu_pro': FALSE},
    {'osver': '24.04', 'pkgname': 'krb5-kpropd', 'pkgver': '1.20.1-6ubuntu2.3', 'ubuntu_pro': FALSE},
    {'osver': '24.04', 'pkgname': 'krb5-locales', 'pkgver': '1.20.1-6ubuntu2.3', 'ubuntu_pro': FALSE},
    {'osver': '24.04', 'pkgname': 'krb5-multidev', 'pkgver': '1.20.1-6ubuntu2.3', 'ubuntu_pro': FALSE},
    {'osver': '24.04', 'pkgname': 'krb5-otp', 'pkgver': '1.20.1-6ubuntu2.3', 'ubuntu_pro': FALSE},
    {'osver': '24.04', 'pkgname': 'krb5-pkinit', 'pkgver': '1.20.1-6ubuntu2.3', 'ubuntu_pro': FALSE},
    {'osver': '24.04', 'pkgname': 'krb5-user', 'pkgver': '1.20.1-6ubuntu2.3', 'ubuntu_pro': FALSE},
    {'osver': '24.04', 'pkgname': 'libgssapi-krb5-2', 'pkgver': '1.20.1-6ubuntu2.3', 'ubuntu_pro': FALSE},
    {'osver': '24.04', 'pkgname': 'libgssrpc4t64', 'pkgver': '1.20.1-6ubuntu2.3', 'ubuntu_pro': FALSE},
    {'osver': '24.04', 'pkgname': 'libk5crypto3', 'pkgver': '1.20.1-6ubuntu2.3', 'ubuntu_pro': FALSE},
    {'osver': '24.04', 'pkgname': 'libkadm5clnt-mit12', 'pkgver': '1.20.1-6ubuntu2.3', 'ubuntu_pro': FALSE},
    {'osver': '24.04', 'pkgname': 'libkadm5srv-mit12', 'pkgver': '1.20.1-6ubuntu2.3', 'ubuntu_pro': FALSE},
    {'osver': '24.04', 'pkgname': 'libkdb5-10t64', 'pkgver': '1.20.1-6ubuntu2.3', 'ubuntu_pro': FALSE},
    {'osver': '24.04', 'pkgname': 'libkrad-dev', 'pkgver': '1.20.1-6ubuntu2.3', 'ubuntu_pro': FALSE},
    {'osver': '24.04', 'pkgname': 'libkrad0', 'pkgver': '1.20.1-6ubuntu2.3', 'ubuntu_pro': FALSE},
    {'osver': '24.04', 'pkgname': 'libkrb5-3', 'pkgver': '1.20.1-6ubuntu2.3', 'ubuntu_pro': FALSE},
    {'osver': '24.04', 'pkgname': 'libkrb5-dev', 'pkgver': '1.20.1-6ubuntu2.3', 'ubuntu_pro': FALSE},
    {'osver': '24.04', 'pkgname': 'libkrb5support0', 'pkgver': '1.20.1-6ubuntu2.3', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'krb5-admin-server', 'pkgver': '1.21.3-3ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'krb5-gss-samples', 'pkgver': '1.21.3-3ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'krb5-k5tls', 'pkgver': '1.21.3-3ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'krb5-kdc', 'pkgver': '1.21.3-3ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'krb5-kdc-ldap', 'pkgver': '1.21.3-3ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'krb5-kpropd', 'pkgver': '1.21.3-3ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'krb5-locales', 'pkgver': '1.21.3-3ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'krb5-multidev', 'pkgver': '1.21.3-3ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'krb5-otp', 'pkgver': '1.21.3-3ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'krb5-pkinit', 'pkgver': '1.21.3-3ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'krb5-user', 'pkgver': '1.21.3-3ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'libgssapi-krb5-2', 'pkgver': '1.21.3-3ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'libgssrpc4t64', 'pkgver': '1.21.3-3ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'libk5crypto3', 'pkgver': '1.21.3-3ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'libkadm5clnt-mit12', 'pkgver': '1.21.3-3ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'libkadm5srv-mit12', 'pkgver': '1.21.3-3ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'libkdb5-10t64', 'pkgver': '1.21.3-3ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'libkrad-dev', 'pkgver': '1.21.3-3ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'libkrad0', 'pkgver': '1.21.3-3ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'libkrb5-3', 'pkgver': '1.21.3-3ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'libkrb5-dev', 'pkgver': '1.21.3-3ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'libkrb5support0', 'pkgver': '1.21.3-3ubuntu0.1', 'ubuntu_pro': FALSE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'krb5-admin-server / krb5-gss-samples / krb5-k5tls / krb5-kdc / etc');
}
