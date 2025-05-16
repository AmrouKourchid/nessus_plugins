#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Rocky Linux Security Advisory RLSA-2020:1650.
##

include('compat.inc');

if (description)
{
  script_id(185067);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/07");

  script_cve_id("CVE-2019-19921", "CVE-2020-1702", "CVE-2020-1726");
  script_xref(name:"RLSA", value:"2020:1650");

  script_name(english:"Rocky Linux 8 : container-tools:rhel8 (RLSA-2020:1650)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Rocky Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Rocky Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
RLSA-2020:1650 advisory.

  - runc through 1.0.0-rc9 has Incorrect Access Control leading to Escalation of Privileges, related to
    libcontainer/rootfs_linux.go. To exploit this, an attacker must be able to spawn two containers with
    custom volume-mount configurations, and be able to run custom images. (This vulnerability does not affect
    Docker due to an implementation detail that happens to block the attack.) (CVE-2019-19921)

  - A malicious container image can consume an unbounded amount of memory when being pulled to a container
    runtime host, such as Red Hat Enterprise Linux using podman, or OpenShift Container Platform. An attacker
    can use this flaw to trick a user, with privileges to pull container images, into crashing the process
    responsible for pulling the image. This flaw affects containers-image versions before 5.2.0.
    (CVE-2020-1702)

  - A flaw was discovered in Podman where it incorrectly allows containers when created to overwrite existing
    files in volumes, even if they are mounted as read-only. When a user runs a malicious container or a
    container based on a malicious image with an attached volume that is used for the first time, it is
    possible to trigger the flaw and overwrite files in the volume.This issue was introduced in version 1.6.0.
    (CVE-2020-1726)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.rockylinux.org/RLSA-2020:1650");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1703245");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1717357");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1731107");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1732704");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1732713");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1748519");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1749999");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1754744");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1754763");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1755119");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1756919");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1757693");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1757845");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1763454");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1766774");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1768930");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1769469");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1771990");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1774755");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1775307");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1776112");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1779834");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1783267");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1783268");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1783270");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1783272");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1783274");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1784267");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1784952");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1788539");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1792796");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1793084");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1793598");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1796107");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1801152");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1802907");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1803496");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1804849");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1805017");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1805212");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1806901");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1808707");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1810053");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1811514");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1813295");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1726");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-19921");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:container-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:crit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:criu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:criu-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:criu-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python-podman-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-criu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:runc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:runc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:runc-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:slirp4netns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:slirp4netns-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:slirp4netns-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:toolbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:udica");
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
    {'reference':'container-selinux-2.124.0-1.gitf958d0c.module+el8.5.0+681+c9a1951f', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'crit-3.12-9.module+el8.4.0+557+48ba8b2f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'crit-3.12-9.module+el8.4.0+557+48ba8b2f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'crit-3.12-9.module+el8.5.0+681+c9a1951f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'crit-3.12-9.module+el8.5.0+681+c9a1951f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'criu-3.12-9.module+el8.4.0+557+48ba8b2f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'criu-3.12-9.module+el8.4.0+557+48ba8b2f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'criu-3.12-9.module+el8.5.0+681+c9a1951f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'criu-3.12-9.module+el8.5.0+681+c9a1951f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'criu-debuginfo-3.12-9.module+el8.4.0+557+48ba8b2f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'criu-debuginfo-3.12-9.module+el8.4.0+557+48ba8b2f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'criu-debuginfo-3.12-9.module+el8.5.0+681+c9a1951f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'criu-debuginfo-3.12-9.module+el8.5.0+681+c9a1951f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'criu-debugsource-3.12-9.module+el8.4.0+557+48ba8b2f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'criu-debugsource-3.12-9.module+el8.4.0+557+48ba8b2f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'criu-debugsource-3.12-9.module+el8.5.0+681+c9a1951f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'criu-debugsource-3.12-9.module+el8.5.0+681+c9a1951f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-podman-api-1.2.0-0.2.gitd0a45fe.module+el8.4.0+559+c02fa3b2', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-podman-api-1.2.0-0.2.gitd0a45fe.module+el8.5.0+708+6758137d', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-podman-api-1.2.0-0.2.gitd0a45fe.module+el8.5.0+770+e2f49861', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-criu-3.12-9.module+el8.4.0+557+48ba8b2f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-criu-3.12-9.module+el8.4.0+557+48ba8b2f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-criu-3.12-9.module+el8.5.0+681+c9a1951f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-criu-3.12-9.module+el8.5.0+681+c9a1951f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'runc-1.0.0-65.rc10.module+el8.4.0+559+c02fa3b2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'runc-1.0.0-65.rc10.module+el8.4.0+559+c02fa3b2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'runc-debuginfo-1.0.0-65.rc10.module+el8.4.0+559+c02fa3b2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'runc-debuginfo-1.0.0-65.rc10.module+el8.4.0+559+c02fa3b2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'runc-debugsource-1.0.0-65.rc10.module+el8.4.0+559+c02fa3b2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'runc-debugsource-1.0.0-65.rc10.module+el8.4.0+559+c02fa3b2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'slirp4netns-0.4.2-3.git21fdece.module+el8.4.0+536+994a2182', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'slirp4netns-0.4.2-3.git21fdece.module+el8.4.0+536+994a2182', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'slirp4netns-0.4.2-3.git21fdece.module+el8.5.0+708+6758137d', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'slirp4netns-0.4.2-3.git21fdece.module+el8.5.0+708+6758137d', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'slirp4netns-0.4.2-3.git21fdece.module+el8.5.0+770+e2f49861', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'slirp4netns-0.4.2-3.git21fdece.module+el8.5.0+770+e2f49861', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'slirp4netns-debuginfo-0.4.2-3.git21fdece.module+el8.4.0+536+994a2182', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'slirp4netns-debuginfo-0.4.2-3.git21fdece.module+el8.4.0+536+994a2182', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'slirp4netns-debuginfo-0.4.2-3.git21fdece.module+el8.5.0+708+6758137d', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'slirp4netns-debuginfo-0.4.2-3.git21fdece.module+el8.5.0+708+6758137d', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'slirp4netns-debuginfo-0.4.2-3.git21fdece.module+el8.5.0+770+e2f49861', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'slirp4netns-debuginfo-0.4.2-3.git21fdece.module+el8.5.0+770+e2f49861', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'slirp4netns-debugsource-0.4.2-3.git21fdece.module+el8.4.0+536+994a2182', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'slirp4netns-debugsource-0.4.2-3.git21fdece.module+el8.4.0+536+994a2182', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'slirp4netns-debugsource-0.4.2-3.git21fdece.module+el8.5.0+708+6758137d', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'slirp4netns-debugsource-0.4.2-3.git21fdece.module+el8.5.0+708+6758137d', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'slirp4netns-debugsource-0.4.2-3.git21fdece.module+el8.5.0+770+e2f49861', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'slirp4netns-debugsource-0.4.2-3.git21fdece.module+el8.5.0+770+e2f49861', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'toolbox-0.0.7-1.module+el8.4.0+559+c02fa3b2', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'toolbox-0.0.7-1.module+el8.5.0+708+6758137d', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'toolbox-0.0.7-1.module+el8.5.0+770+e2f49861', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'udica-0.2.1-2.module+el8.4.0+559+c02fa3b2', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'udica-0.2.1-2.module+el8.5.0+708+6758137d', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'udica-0.2.1-2.module+el8.5.0+770+e2f49861', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'container-selinux / crit / criu / criu-debuginfo / criu-debugsource / etc');
}
