#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Red Hat Security Advisory RHSA-2024:2968. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(197695);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/22");

  script_cve_id("CVE-2023-45803", "CVE-2023-52323", "CVE-2024-22195");
  script_xref(name:"RHSA", value:"2024:2968");

  script_name(english:"CentOS 8 : fence-agents (CESA-2024:2968)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
CESA-2024:2968 advisory.

  - urllib3 is a user-friendly HTTP client library for Python. urllib3 previously wouldn't remove the HTTP
    request body when an HTTP redirect response using status 301, 302, or 303 after the request had its method
    changed from one that could accept a request body (like `POST`) to `GET` as is required by HTTP RFCs.
    Although this behavior is not specified in the section for redirects, it can be inferred by piecing
    together information from different sections and we have observed the behavior in other major HTTP client
    implementations like curl and web browsers. Because the vulnerability requires a previously trusted
    service to become compromised in order to have an impact on confidentiality we believe the exploitability
    of this vulnerability is low. Additionally, many users aren't putting sensitive data in HTTP request
    bodies, if this is the case then this vulnerability isn't exploitable. Both of the following conditions
    must be true to be affected by this vulnerability: 1. Using urllib3 and submitting sensitive information
    in the HTTP request body (such as form data or JSON) and 2. The origin service is compromised and starts
    redirecting using 301, 302, or 303 to a malicious peer or the redirected-to service becomes compromised.
    This issue has been addressed in versions 1.26.18 and 2.0.7 and users are advised to update to resolve
    this issue. Users unable to update should disable redirects for services that aren't expecting to respond
    with redirects with `redirects=False` and disable automatic redirects with `redirects=False` and handle
    301, 302, and 303 redirects manually by stripping the HTTP request body. (CVE-2023-45803)

  - PyCryptodome and pycryptodomex before 3.19.1 allow side-channel leakage for OAEP decryption, exploitable
    for a Manger attack. (CVE-2023-52323)

  - Jinja is an extensible templating engine. Special placeholders in the template allow writing code similar
    to Python syntax. It is possible to inject arbitrary HTML attributes into the rendered HTML template,
    potentially leading to Cross-Site Scripting (XSS). The Jinja `xmlattr` filter can be abused to inject
    arbitrary HTML attribute keys and values, bypassing the auto escaping mechanism and potentially leading to
    XSS. It may also be possible to bypass attribute validation checks if they are blacklist-based.
    (CVE-2024-22195)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2024:2968");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-22195");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:8-stream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-aliyun");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-amt-ws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-apc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-apc-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-azure-arm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-bladecenter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-brocade");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-cisco-mds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-cisco-ucs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-compute");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-drac5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-eaton-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-emerson");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-eps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-gce");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-heuristics-ping");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-hpblade");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-ibm-powervs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-ibm-vpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-ibmblade");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-ifmib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-ilo-moonshot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-ilo-mp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-ilo-ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-ilo2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-intelmodular");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-ipdu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-ipmilan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-kubevirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-lpar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-mpath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-openstack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-redfish");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-rhevm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-rsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-rsb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-sbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-scsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-virsh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-vmware-rest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-vmware-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-wti");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/CentOS/release');
if (isnull(os_release) || 'CentOS' >!< os_release) audit(AUDIT_OS_NOT, 'CentOS');
var os_ver = pregmatch(pattern: "CentOS(?: Stream)?(?: Linux)? release ([0-9]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'CentOS');
os_ver = os_ver[1];
if ('CentOS Stream' >!< os_release) audit(AUDIT_OS_NOT, 'CentOS 8-Stream');
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '8')) audit(AUDIT_OS_NOT, 'CentOS 8.x', 'CentOS ' + os_ver);

if (!get_kb_item('Host/CentOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'CentOS', cpu);

var pkgs = [
    {'reference':'fence-agents-aliyun-4.2.1-129.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-aliyun-4.2.1-129.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-all-4.2.1-129.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-all-4.2.1-129.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-amt-ws-4.2.1-129.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-amt-ws-4.2.1-129.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-apc-4.2.1-129.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-apc-4.2.1-129.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-apc-snmp-4.2.1-129.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-apc-snmp-4.2.1-129.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-aws-4.2.1-129.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-aws-4.2.1-129.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-azure-arm-4.2.1-129.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-azure-arm-4.2.1-129.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-bladecenter-4.2.1-129.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-bladecenter-4.2.1-129.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-brocade-4.2.1-129.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-brocade-4.2.1-129.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-cisco-mds-4.2.1-129.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-cisco-mds-4.2.1-129.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-cisco-ucs-4.2.1-129.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-cisco-ucs-4.2.1-129.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-common-4.2.1-129.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-common-4.2.1-129.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-compute-4.2.1-129.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-compute-4.2.1-129.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-drac5-4.2.1-129.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-drac5-4.2.1-129.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-eaton-snmp-4.2.1-129.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-eaton-snmp-4.2.1-129.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-emerson-4.2.1-129.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-emerson-4.2.1-129.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-eps-4.2.1-129.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-eps-4.2.1-129.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-gce-4.2.1-129.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-gce-4.2.1-129.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-heuristics-ping-4.2.1-129.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-heuristics-ping-4.2.1-129.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-hpblade-4.2.1-129.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-hpblade-4.2.1-129.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-ibm-powervs-4.2.1-129.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-ibm-powervs-4.2.1-129.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-ibm-vpc-4.2.1-129.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-ibm-vpc-4.2.1-129.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-ibmblade-4.2.1-129.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-ibmblade-4.2.1-129.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-ifmib-4.2.1-129.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-ifmib-4.2.1-129.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-ilo-moonshot-4.2.1-129.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-ilo-moonshot-4.2.1-129.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-ilo-mp-4.2.1-129.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-ilo-mp-4.2.1-129.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-ilo-ssh-4.2.1-129.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-ilo-ssh-4.2.1-129.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-ilo2-4.2.1-129.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-ilo2-4.2.1-129.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-intelmodular-4.2.1-129.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-intelmodular-4.2.1-129.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-ipdu-4.2.1-129.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-ipdu-4.2.1-129.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-ipmilan-4.2.1-129.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-ipmilan-4.2.1-129.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-kdump-4.2.1-129.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-kdump-4.2.1-129.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-kubevirt-4.2.1-129.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-kubevirt-4.2.1-129.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-lpar-4.2.1-129.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-lpar-4.2.1-129.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-mpath-4.2.1-129.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-mpath-4.2.1-129.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-openstack-4.2.1-129.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-openstack-4.2.1-129.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-redfish-4.2.1-129.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-redfish-4.2.1-129.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-rhevm-4.2.1-129.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-rhevm-4.2.1-129.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-rsa-4.2.1-129.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-rsa-4.2.1-129.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-rsb-4.2.1-129.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-rsb-4.2.1-129.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-sbd-4.2.1-129.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-sbd-4.2.1-129.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-scsi-4.2.1-129.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-scsi-4.2.1-129.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-virsh-4.2.1-129.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-virsh-4.2.1-129.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-vmware-rest-4.2.1-129.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-vmware-rest-4.2.1-129.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-vmware-soap-4.2.1-129.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-vmware-soap-4.2.1-129.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-wti-4.2.1-129.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-wti-4.2.1-129.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
  if (!empty_or_null(package_array['release'])) _release = 'CentOS-' + package_array['release'];
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'fence-agents-aliyun / fence-agents-all / fence-agents-amt-ws / etc');
}
