##
# (C) Tenable Network Security, Inc.
##
# The descriptive text is (C) Scientific Linux.
#

include('compat.inc');

if (description)
{
  script_id(144296);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/29");

  script_cve_id("CVE-2020-1472", "CVE-2020-14318", "CVE-2020-14323");
  script_xref(name:"RHSA", value:"RHSA-2020:5439");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2020/09/21");
  script_xref(name:"CISA-NCAS", value:"AA22-011A");
  script_xref(name:"CEA-ID", value:"CEA-2020-0129");
  script_xref(name:"CEA-ID", value:"CEA-2020-0101");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");
  script_xref(name:"CEA-ID", value:"CEA-2021-0008");
  script_xref(name:"CEA-ID", value:"CEA-2020-0121");
  script_xref(name:"CEA-ID", value:"CEA-2023-0016");

  script_name(english:"Scientific Linux Security Update : samba on SL7.x i686/x86_64 (2020:5439)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Scientific Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Scientific Linux 7 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SLSA-2020:5439-1 advisory.

  - samba: Netlogon elevation of privilege vulnerability (Zerologon) (CVE-2020-1472)

  - samba: Missing handle permissions check in SMB1/2/3 ChangeNotify (CVE-2020-14318)

  - samba: Unprivileged user can crash winbind (CVE-2020-14323)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.scientificlinux.org/category/sl-errata/slsa-20205439-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1472");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-14318");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fermilab:scientific_linux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libsmbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libwbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libwbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-client-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-common-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-common-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-dc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-dc-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-krb5-printing");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-pidl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-python-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-test-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-vfs-glusterfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-winbind-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-winbind-krb5-locator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-winbind-modules");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Scientific Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item('Host/RedHat/release');
if (isnull(release) || 'Scientific Linux' >!< release) audit(AUDIT_OS_NOT, 'Scientific Linux');
os_ver = pregmatch(pattern: "Scientific Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Scientific Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Scientific Linux 7.x', 'Scientific Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Scientific Linux', cpu);

pkgs = [
    {'reference':'libsmbclient-4.10.16-9.el7_9', 'cpu':'i686', 'release':'SL7'},
    {'reference':'libsmbclient-4.10.16-9.el7_9', 'cpu':'x86_64', 'release':'SL7'},
    {'reference':'libsmbclient-devel-4.10.16-9.el7_9', 'cpu':'i686', 'release':'SL7'},
    {'reference':'libsmbclient-devel-4.10.16-9.el7_9', 'cpu':'x86_64', 'release':'SL7'},
    {'reference':'libwbclient-4.10.16-9.el7_9', 'cpu':'i686', 'release':'SL7'},
    {'reference':'libwbclient-4.10.16-9.el7_9', 'cpu':'x86_64', 'release':'SL7'},
    {'reference':'libwbclient-devel-4.10.16-9.el7_9', 'cpu':'i686', 'release':'SL7'},
    {'reference':'libwbclient-devel-4.10.16-9.el7_9', 'cpu':'x86_64', 'release':'SL7'},
    {'reference':'samba-4.10.16-9.el7_9', 'cpu':'x86_64', 'release':'SL7'},
    {'reference':'samba-client-4.10.16-9.el7_9', 'cpu':'x86_64', 'release':'SL7'},
    {'reference':'samba-client-libs-4.10.16-9.el7_9', 'cpu':'i686', 'release':'SL7'},
    {'reference':'samba-client-libs-4.10.16-9.el7_9', 'cpu':'x86_64', 'release':'SL7'},
    {'reference':'samba-common-4.10.16-9.el7_9', 'release':'SL7'},
    {'reference':'samba-common-libs-4.10.16-9.el7_9', 'cpu':'i686', 'release':'SL7'},
    {'reference':'samba-common-libs-4.10.16-9.el7_9', 'cpu':'x86_64', 'release':'SL7'},
    {'reference':'samba-common-tools-4.10.16-9.el7_9', 'cpu':'x86_64', 'release':'SL7'},
    {'reference':'samba-dc-4.10.16-9.el7_9', 'cpu':'x86_64', 'release':'SL7'},
    {'reference':'samba-dc-libs-4.10.16-9.el7_9', 'cpu':'x86_64', 'release':'SL7'},
    {'reference':'samba-debuginfo-4.10.16-9.el7_9', 'cpu':'i686', 'release':'SL7'},
    {'reference':'samba-debuginfo-4.10.16-9.el7_9', 'cpu':'x86_64', 'release':'SL7'},
    {'reference':'samba-devel-4.10.16-9.el7_9', 'cpu':'i686', 'release':'SL7'},
    {'reference':'samba-devel-4.10.16-9.el7_9', 'cpu':'x86_64', 'release':'SL7'},
    {'reference':'samba-krb5-printing-4.10.16-9.el7_9', 'cpu':'x86_64', 'release':'SL7'},
    {'reference':'samba-libs-4.10.16-9.el7_9', 'cpu':'i686', 'release':'SL7'},
    {'reference':'samba-libs-4.10.16-9.el7_9', 'cpu':'x86_64', 'release':'SL7'},
    {'reference':'samba-pidl-4.10.16-9.el7_9', 'release':'SL7'},
    {'reference':'samba-python-4.10.16-9.el7_9', 'cpu':'i686', 'release':'SL7'},
    {'reference':'samba-python-4.10.16-9.el7_9', 'cpu':'x86_64', 'release':'SL7'},
    {'reference':'samba-python-test-4.10.16-9.el7_9', 'cpu':'x86_64', 'release':'SL7'},
    {'reference':'samba-test-4.10.16-9.el7_9', 'cpu':'x86_64', 'release':'SL7'},
    {'reference':'samba-test-libs-4.10.16-9.el7_9', 'cpu':'i686', 'release':'SL7'},
    {'reference':'samba-test-libs-4.10.16-9.el7_9', 'cpu':'x86_64', 'release':'SL7'},
    {'reference':'samba-vfs-glusterfs-4.10.16-9.el7_9', 'cpu':'x86_64', 'release':'SL7'},
    {'reference':'samba-winbind-4.10.16-9.el7_9', 'cpu':'x86_64', 'release':'SL7'},
    {'reference':'samba-winbind-clients-4.10.16-9.el7_9', 'cpu':'x86_64', 'release':'SL7'},
    {'reference':'samba-winbind-krb5-locator-4.10.16-9.el7_9', 'cpu':'x86_64', 'release':'SL7'},
    {'reference':'samba-winbind-modules-4.10.16-9.el7_9', 'cpu':'i686', 'release':'SL7'},
    {'reference':'samba-winbind-modules-4.10.16-9.el7_9', 'cpu':'x86_64', 'release':'SL7'}
];

flag = 0;
foreach package_array ( pkgs ) {
  reference = NULL;
  release = NULL;
  sp = NULL;
  cpu = NULL;
  el_string = NULL;
  rpm_spec_vers_cmp = NULL;
  epoch = NULL;
  allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && release) {
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libsmbclient / libsmbclient-devel / libwbclient / etc');
}
