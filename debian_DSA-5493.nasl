#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5493. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(181211);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/11");

  script_cve_id("CVE-2023-20867", "CVE-2023-20900");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/07/14");

  script_name(english:"Debian DSA-5493-1 : open-vm-tools - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 / 12 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5493 advisory.

  - A fully compromised ESXi host can force VMware Tools to fail to authenticate host-to-guest operations,
    impacting the confidentiality and integrity of the guest virtual machine. (CVE-2023-20867)

  - A malicious actor that has been granted Guest Operation Privileges https://docs.vmware.com/en/VMware-
    vSphere/8.0/vsphere-security/GUID-6A952214-0E5E-4CCF-9D2A-90948FF643EC.html in a target virtual machine
    may be able to elevate their privileges if that target virtual machine has been assigned a more privileged
    Guest Alias https://vdc-download.vmware.com/vmwb-repository/dcr-
    public/d1902b0e-d479-46bf-8ac9-cee0e31e8ec0/07ce8dbd-
    db48-4261-9b8f-c6d3ad8ba472/vim.vm.guest.AliasManager.html . (CVE-2023-20900)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1050970");
  # https://security-tracker.debian.org/tracker/source-package/open-vm-tools
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a254e898");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2023/dsa-5493");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-20867");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-20900");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/open-vm-tools");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bookworm/open-vm-tools");
  script_set_attribute(attribute:"solution", value:
"Upgrade the open-vm-tools packages.

For the stable distribution (bookworm), these problems have been fixed in version 2");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20900");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:open-vm-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:open-vm-tools-containerinfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:open-vm-tools-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:open-vm-tools-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:open-vm-tools-salt-minion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:open-vm-tools-sdmp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:12.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(11)\.[0-9]+|^(12)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 11.0 / 12.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'open-vm-tools', 'reference': '2:11.2.5-2+deb11u2'},
    {'release': '11.0', 'prefix': 'open-vm-tools-desktop', 'reference': '2:11.2.5-2+deb11u2'},
    {'release': '11.0', 'prefix': 'open-vm-tools-dev', 'reference': '2:11.2.5-2+deb11u2'},
    {'release': '11.0', 'prefix': 'open-vm-tools-sdmp', 'reference': '2:11.2.5-2+deb11u2'},
    {'release': '12.0', 'prefix': 'open-vm-tools', 'reference': '2:12.2.0-1+deb12u1'},
    {'release': '12.0', 'prefix': 'open-vm-tools-containerinfo', 'reference': '2:12.2.0-1+deb12u1'},
    {'release': '12.0', 'prefix': 'open-vm-tools-desktop', 'reference': '2:12.2.0-1+deb12u1'},
    {'release': '12.0', 'prefix': 'open-vm-tools-dev', 'reference': '2:12.2.0-1+deb12u1'},
    {'release': '12.0', 'prefix': 'open-vm-tools-salt-minion', 'reference': '2:12.2.0-1+deb12u1'},
    {'release': '12.0', 'prefix': 'open-vm-tools-sdmp', 'reference': '2:12.2.0-1+deb12u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'open-vm-tools / open-vm-tools-containerinfo / open-vm-tools-desktop / etc');
}
