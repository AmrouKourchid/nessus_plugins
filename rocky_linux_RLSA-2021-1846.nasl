#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Rocky Linux Security Advisory RLSA-2021:1846.
##

include('compat.inc');

if (description)
{
  script_id(184746);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/24");

  script_cve_id("CVE-2020-11023");
  script_xref(name:"RLSA", value:"2021:1846");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/02/13");

  script_name(english:"Rocky Linux 8 : idm:DL1 and idm:client (RLSA-2021:1846)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Rocky Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Rocky Linux 8 host has packages installed that are affected by a vulnerability as referenced in the
RLSA-2021:1846 advisory.

  - In jQuery versions greater than or equal to 1.0.3 and before 3.5.0, passing HTML containing <option>
    elements from untrusted sources - even after sanitizing it - to one of jQuery's DOM manipulation methods
    (i.e. .html(), .append(), and others) may execute untrusted code. This problem is patched in jQuery 3.5.0.
    (CVE-2020-11023)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.rockylinux.org/RLSA-2021:1846");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1340463");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1357495");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1484088");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1542737");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1544379");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1660877");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1779981");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1780328");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1780510");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1780782");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1784657");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1809215");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1810148");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1812871");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1824193");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1850004");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1851835");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1857272");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1860129");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1866558");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1872603");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1875001");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1882340");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1891056");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1891505");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1891735");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1891741");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1891832");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1891850");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1894800");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1901068");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1902173");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1902727");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1903025");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1904484");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1904612");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1905919");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1909876");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1912845");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1922955");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1923900");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1924026");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1924501");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1924812");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1925410");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1926699");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1926910");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1928900");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1930426");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1932289");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1939371");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=871208");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-11023");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:bind-dyndb-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:bind-dyndb-ldap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:bind-dyndb-ldap-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:custodia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:ipa-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:ipa-client-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:ipa-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:ipa-client-epn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:ipa-client-samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:ipa-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:ipa-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:ipa-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:ipa-healthcheck");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:ipa-healthcheck-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:ipa-python-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:ipa-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:ipa-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:ipa-server-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:ipa-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:ipa-server-dns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:ipa-server-trust-ad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:ipa-server-trust-ad-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:opendnssec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:opendnssec-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:opendnssec-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-custodia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-ipaclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-ipalib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-ipaserver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-ipatests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-jwcrypto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-kdcproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-pyusb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-qrcode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-qrcode-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-yubico");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:softhsm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:softhsm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:softhsm-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:softhsm-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rocky:linux:8");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Rocky Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RockyLinux/release", "Host/RockyLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RockyLinux/release');
if (isnull(os_release) || 'Rocky Linux' >!< os_release) audit(AUDIT_OS_NOT, 'Rocky Linux');
var os_ver = pregmatch(pattern: "Rocky(?: Linux)? release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Rocky Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Rocky Linux 8.x', 'Rocky Linux ' + os_ver);

if (!get_kb_item('Host/RockyLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Rocky Linux', cpu);

var pkgs = [
    {'reference':'bind-dyndb-ldap-11.6-2.module+el8.4.0+429+6bd33fea', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bind-dyndb-ldap-11.6-2.module+el8.4.0+429+6bd33fea', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bind-dyndb-ldap-debuginfo-11.6-2.module+el8.4.0+429+6bd33fea', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bind-dyndb-ldap-debuginfo-11.6-2.module+el8.4.0+429+6bd33fea', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bind-dyndb-ldap-debugsource-11.6-2.module+el8.4.0+429+6bd33fea', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bind-dyndb-ldap-debugsource-11.6-2.module+el8.4.0+429+6bd33fea', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'custodia-0.6.0-3.module+el8.4.0+429+6bd33fea', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-client-4.9.2-3.module+el8.4.0+429+6bd33fea', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-client-4.9.2-3.module+el8.4.0+429+6bd33fea', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-client-common-4.9.2-3.module+el8.4.0+429+6bd33fea', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-client-debuginfo-4.9.2-3.module+el8.4.0+429+6bd33fea', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-client-debuginfo-4.9.2-3.module+el8.4.0+429+6bd33fea', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-client-epn-4.9.2-3.module+el8.4.0+429+6bd33fea', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-client-epn-4.9.2-3.module+el8.4.0+429+6bd33fea', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-client-samba-4.9.2-3.module+el8.4.0+429+6bd33fea', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-client-samba-4.9.2-3.module+el8.4.0+429+6bd33fea', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-common-4.9.2-3.module+el8.4.0+429+6bd33fea', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-debuginfo-4.9.2-3.module+el8.4.0+429+6bd33fea', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-debuginfo-4.9.2-3.module+el8.4.0+429+6bd33fea', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-debugsource-4.9.2-3.module+el8.4.0+429+6bd33fea', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-debugsource-4.9.2-3.module+el8.4.0+429+6bd33fea', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-healthcheck-0.7-3.module+el8.4.0+429+6bd33fea', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-healthcheck-core-0.7-3.module+el8.4.0+429+6bd33fea', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-python-compat-4.9.2-3.module+el8.4.0+429+6bd33fea', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-selinux-4.9.2-3.module+el8.4.0+429+6bd33fea', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-server-4.9.2-3.module+el8.4.0+429+6bd33fea', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-server-4.9.2-3.module+el8.4.0+429+6bd33fea', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-server-common-4.9.2-3.module+el8.4.0+429+6bd33fea', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-server-debuginfo-4.9.2-3.module+el8.4.0+429+6bd33fea', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-server-debuginfo-4.9.2-3.module+el8.4.0+429+6bd33fea', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-server-dns-4.9.2-3.module+el8.4.0+429+6bd33fea', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-server-trust-ad-4.9.2-3.module+el8.4.0+429+6bd33fea', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-server-trust-ad-4.9.2-3.module+el8.4.0+429+6bd33fea', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-server-trust-ad-debuginfo-4.9.2-3.module+el8.4.0+429+6bd33fea', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-server-trust-ad-debuginfo-4.9.2-3.module+el8.4.0+429+6bd33fea', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'opendnssec-2.1.7-1.module+el8.4.0+429+6bd33fea', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'opendnssec-2.1.7-1.module+el8.4.0+429+6bd33fea', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'opendnssec-debuginfo-2.1.7-1.module+el8.4.0+429+6bd33fea', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'opendnssec-debuginfo-2.1.7-1.module+el8.4.0+429+6bd33fea', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'opendnssec-debugsource-2.1.7-1.module+el8.4.0+429+6bd33fea', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'opendnssec-debugsource-2.1.7-1.module+el8.4.0+429+6bd33fea', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-custodia-0.6.0-3.module+el8.4.0+429+6bd33fea', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-ipaclient-4.9.2-3.module+el8.4.0+429+6bd33fea', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-ipalib-4.9.2-3.module+el8.4.0+429+6bd33fea', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-ipaserver-4.9.2-3.module+el8.4.0+429+6bd33fea', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-ipatests-4.9.2-3.module+el8.4.0+429+6bd33fea', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-jwcrypto-0.5.0-1.1.module+el8.7.0+1074+aae18f3a', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-jwcrypto-0.5.0-1.module+el8.4.0+429+6bd33fea', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-kdcproxy-0.4-5.module+el8.3.0+244+0b2ae752', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-pyusb-1.0.0-9.1.module+el8.7.0+1074+aae18f3a', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-pyusb-1.0.0-9.module+el8.4.0+429+6bd33fea', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-qrcode-5.1-12.module+el8.4.0+429+6bd33fea', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-qrcode-core-5.1-12.module+el8.4.0+429+6bd33fea', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-yubico-1.3.2-9.1.module+el8.7.0+1074+aae18f3a', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-yubico-1.3.2-9.module+el8.4.0+429+6bd33fea', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'softhsm-2.6.0-5.module+el8.4.0+429+6bd33fea', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'softhsm-2.6.0-5.module+el8.4.0+429+6bd33fea', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'softhsm-debuginfo-2.6.0-5.module+el8.4.0+429+6bd33fea', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'softhsm-debuginfo-2.6.0-5.module+el8.4.0+429+6bd33fea', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'softhsm-debugsource-2.6.0-5.module+el8.4.0+429+6bd33fea', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'softhsm-debugsource-2.6.0-5.module+el8.4.0+429+6bd33fea', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'softhsm-devel-2.6.0-5.module+el8.4.0+429+6bd33fea', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'softhsm-devel-2.6.0-5.module+el8.4.0+429+6bd33fea', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = 'Rocky-' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bind-dyndb-ldap / bind-dyndb-ldap-debuginfo / etc');
}
