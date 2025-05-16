#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Rocky Linux Security Advisory RLSA-2020:2774.
##

include('compat.inc');

if (description)
{
  script_id(184607);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/06");

  script_cve_id("CVE-2019-20382", "CVE-2020-8608");
  script_xref(name:"RLSA", value:"2020:2774");

  script_name(english:"Rocky Linux 8 : virt:rhel (RLSA-2020:2774)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Rocky Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Rocky Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
RLSA-2020:2774 advisory.

  - QEMU 4.1.0 has a memory leak in zrle_compress_data in ui/vnc-enc-zrle.c during a VNC disconnect operation
    because libz is misused, resulting in a situation where memory allocated in deflateInit2 is not freed in
    deflateEnd. (CVE-2019-20382)

  - In libslirp 4.1.0, as used in QEMU 4.2.0, tcp_subr.c misuses snprintf return values, leading to a buffer
    overflow in later code. (CVE-2020-8608)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.rockylinux.org/RLSA-2020:2774");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1798453");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1810390");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8608");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libiscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libiscsi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libiscsi-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libiscsi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libiscsi-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libiscsi-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:netcf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:netcf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:netcf-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:netcf-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:netcf-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:netcf-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:sgabios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:sgabios-bin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rocky:linux:8");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Rocky Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'libiscsi-1.18.0-8.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-1.18.0-8.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-1.18.0-8.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-1.18.0-8.module+el8.6.0+847+b490afdd', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-1.18.0-8.module+el8.6.0+847+b490afdd', 'cpu':'i686', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-1.18.0-8.module+el8.6.0+847+b490afdd', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-1.18.0-8.module+el8.7.0+1084+97b81f61', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-1.18.0-8.module+el8.7.0+1084+97b81f61', 'cpu':'i686', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-1.18.0-8.module+el8.7.0+1084+97b81f61', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-debuginfo-1.18.0-8.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-debuginfo-1.18.0-8.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-debuginfo-1.18.0-8.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-debuginfo-1.18.0-8.module+el8.6.0+847+b490afdd', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-debuginfo-1.18.0-8.module+el8.6.0+847+b490afdd', 'cpu':'i686', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-debuginfo-1.18.0-8.module+el8.6.0+847+b490afdd', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-debuginfo-1.18.0-8.module+el8.7.0+1084+97b81f61', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-debuginfo-1.18.0-8.module+el8.7.0+1084+97b81f61', 'cpu':'i686', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-debuginfo-1.18.0-8.module+el8.7.0+1084+97b81f61', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-debugsource-1.18.0-8.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-debugsource-1.18.0-8.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-debugsource-1.18.0-8.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-debugsource-1.18.0-8.module+el8.6.0+847+b490afdd', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-debugsource-1.18.0-8.module+el8.6.0+847+b490afdd', 'cpu':'i686', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-debugsource-1.18.0-8.module+el8.6.0+847+b490afdd', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-debugsource-1.18.0-8.module+el8.7.0+1084+97b81f61', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-debugsource-1.18.0-8.module+el8.7.0+1084+97b81f61', 'cpu':'i686', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-debugsource-1.18.0-8.module+el8.7.0+1084+97b81f61', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-devel-1.18.0-8.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-devel-1.18.0-8.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-devel-1.18.0-8.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-devel-1.18.0-8.module+el8.6.0+847+b490afdd', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-devel-1.18.0-8.module+el8.6.0+847+b490afdd', 'cpu':'i686', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-devel-1.18.0-8.module+el8.6.0+847+b490afdd', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-devel-1.18.0-8.module+el8.7.0+1084+97b81f61', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-devel-1.18.0-8.module+el8.7.0+1084+97b81f61', 'cpu':'i686', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-devel-1.18.0-8.module+el8.7.0+1084+97b81f61', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-utils-1.18.0-8.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-utils-1.18.0-8.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-utils-1.18.0-8.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-utils-1.18.0-8.module+el8.6.0+847+b490afdd', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-utils-1.18.0-8.module+el8.6.0+847+b490afdd', 'cpu':'i686', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-utils-1.18.0-8.module+el8.6.0+847+b490afdd', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-utils-1.18.0-8.module+el8.7.0+1084+97b81f61', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-utils-1.18.0-8.module+el8.7.0+1084+97b81f61', 'cpu':'i686', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-utils-1.18.0-8.module+el8.7.0+1084+97b81f61', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-utils-debuginfo-1.18.0-8.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-utils-debuginfo-1.18.0-8.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-utils-debuginfo-1.18.0-8.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-utils-debuginfo-1.18.0-8.module+el8.6.0+847+b490afdd', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-utils-debuginfo-1.18.0-8.module+el8.6.0+847+b490afdd', 'cpu':'i686', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-utils-debuginfo-1.18.0-8.module+el8.6.0+847+b490afdd', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-utils-debuginfo-1.18.0-8.module+el8.7.0+1084+97b81f61', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-utils-debuginfo-1.18.0-8.module+el8.7.0+1084+97b81f61', 'cpu':'i686', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-utils-debuginfo-1.18.0-8.module+el8.7.0+1084+97b81f61', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-0.2.8-12.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-0.2.8-12.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-0.2.8-12.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-0.2.8-12.module+el8.6.0+847+b490afdd', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-0.2.8-12.module+el8.6.0+847+b490afdd', 'cpu':'i686', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-0.2.8-12.module+el8.6.0+847+b490afdd', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-0.2.8-12.module+el8.7.0+1084+97b81f61', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-0.2.8-12.module+el8.7.0+1084+97b81f61', 'cpu':'i686', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-0.2.8-12.module+el8.7.0+1084+97b81f61', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-debuginfo-0.2.8-12.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-debuginfo-0.2.8-12.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-debuginfo-0.2.8-12.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-debuginfo-0.2.8-12.module+el8.6.0+847+b490afdd', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-debuginfo-0.2.8-12.module+el8.6.0+847+b490afdd', 'cpu':'i686', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-debuginfo-0.2.8-12.module+el8.6.0+847+b490afdd', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-debuginfo-0.2.8-12.module+el8.7.0+1084+97b81f61', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-debuginfo-0.2.8-12.module+el8.7.0+1084+97b81f61', 'cpu':'i686', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-debuginfo-0.2.8-12.module+el8.7.0+1084+97b81f61', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-debugsource-0.2.8-12.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-debugsource-0.2.8-12.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-debugsource-0.2.8-12.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-debugsource-0.2.8-12.module+el8.6.0+847+b490afdd', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-debugsource-0.2.8-12.module+el8.6.0+847+b490afdd', 'cpu':'i686', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-debugsource-0.2.8-12.module+el8.6.0+847+b490afdd', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-debugsource-0.2.8-12.module+el8.7.0+1084+97b81f61', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-debugsource-0.2.8-12.module+el8.7.0+1084+97b81f61', 'cpu':'i686', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-debugsource-0.2.8-12.module+el8.7.0+1084+97b81f61', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-devel-0.2.8-12.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-devel-0.2.8-12.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-devel-0.2.8-12.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-devel-0.2.8-12.module+el8.6.0+847+b490afdd', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-devel-0.2.8-12.module+el8.6.0+847+b490afdd', 'cpu':'i686', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-devel-0.2.8-12.module+el8.6.0+847+b490afdd', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-devel-0.2.8-12.module+el8.7.0+1084+97b81f61', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-devel-0.2.8-12.module+el8.7.0+1084+97b81f61', 'cpu':'i686', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-devel-0.2.8-12.module+el8.7.0+1084+97b81f61', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-libs-0.2.8-12.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-libs-0.2.8-12.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-libs-0.2.8-12.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-libs-0.2.8-12.module+el8.6.0+847+b490afdd', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-libs-0.2.8-12.module+el8.6.0+847+b490afdd', 'cpu':'i686', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-libs-0.2.8-12.module+el8.6.0+847+b490afdd', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-libs-0.2.8-12.module+el8.7.0+1084+97b81f61', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-libs-0.2.8-12.module+el8.7.0+1084+97b81f61', 'cpu':'i686', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-libs-0.2.8-12.module+el8.7.0+1084+97b81f61', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-libs-debuginfo-0.2.8-12.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-libs-debuginfo-0.2.8-12.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-libs-debuginfo-0.2.8-12.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-libs-debuginfo-0.2.8-12.module+el8.6.0+847+b490afdd', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-libs-debuginfo-0.2.8-12.module+el8.6.0+847+b490afdd', 'cpu':'i686', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-libs-debuginfo-0.2.8-12.module+el8.6.0+847+b490afdd', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-libs-debuginfo-0.2.8-12.module+el8.7.0+1084+97b81f61', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-libs-debuginfo-0.2.8-12.module+el8.7.0+1084+97b81f61', 'cpu':'i686', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-libs-debuginfo-0.2.8-12.module+el8.7.0+1084+97b81f61', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sgabios-0.20170427git-3.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'sgabios-0.20170427git-3.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'sgabios-0.20170427git-3.module+el8.6.0+847+b490afdd', 'cpu':'i686', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'sgabios-0.20170427git-3.module+el8.6.0+847+b490afdd', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'sgabios-0.20170427git-3.module+el8.7.0+1084+97b81f61', 'cpu':'i686', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'sgabios-0.20170427git-3.module+el8.7.0+1084+97b81f61', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'sgabios-bin-0.20170427git-3.module+el8.4.0+534+4680a14e', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'sgabios-bin-0.20170427git-3.module+el8.6.0+847+b490afdd', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'sgabios-bin-0.20170427git-3.module+el8.7.0+1084+97b81f61', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libiscsi / libiscsi-debuginfo / libiscsi-debugsource / etc');
}
