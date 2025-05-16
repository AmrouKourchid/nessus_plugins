##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2021:0153 and
# CentOS Errata and Security Advisory 2021:0153 respectively.
##

include('compat.inc');

if (description)
{
  script_id(145439);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/09");

  script_cve_id("CVE-2020-25684", "CVE-2020-25685", "CVE-2020-25686");
  script_xref(name:"RHSA", value:"2021:0153");
  script_xref(name:"CEA-ID", value:"CEA-2021-0003");

  script_name(english:"CentOS 7 : dnsmasq (RHSA-2021:0153)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 7 host has packages installed that are affected by multiple vulnerabilities as referenced in the
RHSA-2021:0153 advisory.

  - A flaw was found in dnsmasq before version 2.83. When getting a reply from a forwarded query, dnsmasq
    checks in the forward.c:reply_query() if the reply destination address/port is used by the pending
    forwarded queries. However, it does not use the address/port to retrieve the exact forwarded query,
    substantially reducing the number of attempts an attacker on the network would have to perform to forge a
    reply and get it accepted by dnsmasq. This issue contrasts with RFC5452, which specifies a query's
    attributes that all must be used to match a reply. This flaw allows an attacker to perform a DNS Cache
    Poisoning attack. If chained with CVE-2020-25685 or CVE-2020-25686, the attack complexity of a successful
    attack is reduced. The highest threat from this vulnerability is to data integrity. (CVE-2020-25684)

  - A flaw was found in dnsmasq before version 2.83. When getting a reply from a forwarded query, dnsmasq
    checks in forward.c:reply_query(), which is the forwarded query that matches the reply, by only using a
    weak hash of the query name. Due to the weak hash (CRC32 when dnsmasq is compiled without DNSSEC, SHA-1
    when it is) this flaw allows an off-path attacker to find several different domains all having the same
    hash, substantially reducing the number of attempts they would have to perform to forge a reply and get it
    accepted by dnsmasq. This is in contrast with RFC5452, which specifies that the query name is one of the
    attributes of a query that must be used to match a reply. This flaw could be abused to perform a DNS Cache
    Poisoning attack. If chained with CVE-2020-25684 the attack complexity of a successful attack is reduced.
    The highest threat from this vulnerability is to data integrity. (CVE-2020-25685)

  - A flaw was found in dnsmasq before version 2.83. When receiving a query, dnsmasq does not check for an
    existing pending request for the same name and forwards a new request. By default, a maximum of 150
    pending queries can be sent to upstream servers, so there can be at most 150 queries for the same name.
    This flaw allows an off-path attacker on the network to substantially reduce the number of attempts that
    it would have to perform to forge a reply and have it accepted by dnsmasq. This issue is mentioned in the
    Birthday Attacks section of RFC5452. If chained with CVE-2020-25684, the attack complexity of a
    successful attack is reduced. The highest threat from this vulnerability is to data integrity.
    (CVE-2020-25686)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2021:0153");
  script_set_attribute(attribute:"solution", value:
"Update the affected dnsmasq and / or dnsmasq-utils packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25686");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:dnsmasq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:dnsmasq-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/CentOS/release');
if (isnull(os_release) || 'CentOS' >!< os_release) audit(AUDIT_OS_NOT, 'CentOS');
var os_ver = pregmatch(pattern: "CentOS(?: Linux)? release ([0-9]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'CentOS');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '7')) audit(AUDIT_OS_NOT, 'CentOS 7.x', 'CentOS ' + os_ver);

if (!get_kb_item('Host/CentOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'CentOS', cpu);

var pkgs = [
    {'reference':'dnsmasq-2.76-16.el7_9.1', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dnsmasq-2.76-16.el7_9.1', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dnsmasq-utils-2.76-16.el7_9.1', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dnsmasq-utils-2.76-16.el7_9.1', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE}
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
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && _release) {
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'dnsmasq / dnsmasq-utils');
}
