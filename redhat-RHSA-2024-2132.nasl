#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2024:2132. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(194780);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/06");

  script_cve_id("CVE-2023-45803", "CVE-2023-52323", "CVE-2024-22195");
  script_xref(name:"RHSA", value:"2024:2132");

  script_name(english:"RHEL 9 : fence-agents (RHSA-2024:2132)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for fence-agents.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 9 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2024:2132 advisory.

    The fence-agents packages provide a collection of scripts for handling remote power management for cluster
    devices. They allow failed or unreachable nodes to be forcibly restarted and removed from the cluster.

    Security Fix(es):

    * urllib3: Request body not stripped after redirect from 303 status changes request method to GET
    (CVE-2023-45803)

    * pycryptodome: side-channel leakage for OAEP decryption in PyCryptodome and pycryptodomex
    (CVE-2023-52323)

    * jinja2: HTML attribute injection when passing user input as keys to xmlattr filter (CVE-2024-22195)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

    Additional Changes:

    For detailed information on changes in this release, see the Red Hat Enterprise Linux 9.4 Release Notes
    linked from the References section.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2024/rhsa-2024_2132.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ae4186b5");
  # https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/html/9.4_release_notes/index
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d922e0bf");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2024:2132");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2246840");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2257028");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2257854");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/RHEL-14030");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/RHEL-5396");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL fence-agents package based on the guidance in RHSA-2024:2132.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-22195");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(79, 200, 203);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-aliyun");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-amt-ws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-apc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-apc-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-azure-arm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-bladecenter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-brocade");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-cisco-mds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-cisco-ucs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-compute");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-drac5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-eaton-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-emerson");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-eps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-gce");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-heuristics-ping");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-hpblade");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-ibm-powervs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-ibm-vpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-ibmblade");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-ifmib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-ilo-moonshot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-ilo-mp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-ilo-ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-ilo2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-intelmodular");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-ipdu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-ipmilan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-kubevirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-lpar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-mpath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-openstack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-redfish");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-rhevm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-rsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-rsb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-sbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-scsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-virsh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-vmware-rest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-vmware-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-wti");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-zvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-virt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-virtd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-virtd-cpg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-virtd-libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-virtd-multicast");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-virtd-serial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-virtd-tcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ha-cloud-support");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "redhat_repos.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Red Hat' >!< os_release) audit(AUDIT_OS_NOT, 'Red Hat');
var os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Red Hat');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '9')) audit(AUDIT_OS_NOT, 'Red Hat 9.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel9/9.1/ppc64le/appstream/debug',
      'content/dist/rhel9/9.1/ppc64le/appstream/os',
      'content/dist/rhel9/9.1/ppc64le/appstream/source/SRPMS',
      'content/dist/rhel9/9.1/ppc64le/highavailability/debug',
      'content/dist/rhel9/9.1/ppc64le/highavailability/os',
      'content/dist/rhel9/9.1/ppc64le/highavailability/source/SRPMS',
      'content/dist/rhel9/9.1/ppc64le/resilientstorage/debug',
      'content/dist/rhel9/9.1/ppc64le/resilientstorage/os',
      'content/dist/rhel9/9.1/ppc64le/resilientstorage/source/SRPMS',
      'content/dist/rhel9/9.1/s390x/appstream/debug',
      'content/dist/rhel9/9.1/s390x/appstream/os',
      'content/dist/rhel9/9.1/s390x/appstream/source/SRPMS',
      'content/dist/rhel9/9.1/s390x/highavailability/debug',
      'content/dist/rhel9/9.1/s390x/highavailability/os',
      'content/dist/rhel9/9.1/s390x/highavailability/source/SRPMS',
      'content/dist/rhel9/9.1/s390x/resilientstorage/debug',
      'content/dist/rhel9/9.1/s390x/resilientstorage/os',
      'content/dist/rhel9/9.1/s390x/resilientstorage/source/SRPMS',
      'content/dist/rhel9/9.1/x86_64/appstream/debug',
      'content/dist/rhel9/9.1/x86_64/appstream/os',
      'content/dist/rhel9/9.1/x86_64/appstream/source/SRPMS',
      'content/dist/rhel9/9.1/x86_64/highavailability/debug',
      'content/dist/rhel9/9.1/x86_64/highavailability/os',
      'content/dist/rhel9/9.1/x86_64/highavailability/source/SRPMS',
      'content/dist/rhel9/9.1/x86_64/resilientstorage/debug',
      'content/dist/rhel9/9.1/x86_64/resilientstorage/os',
      'content/dist/rhel9/9.1/x86_64/resilientstorage/source/SRPMS',
      'content/dist/rhel9/9.2/ppc64le/appstream/debug',
      'content/dist/rhel9/9.2/ppc64le/appstream/os',
      'content/dist/rhel9/9.2/ppc64le/appstream/source/SRPMS',
      'content/dist/rhel9/9.2/ppc64le/highavailability/debug',
      'content/dist/rhel9/9.2/ppc64le/highavailability/os',
      'content/dist/rhel9/9.2/ppc64le/highavailability/source/SRPMS',
      'content/dist/rhel9/9.2/ppc64le/resilientstorage/debug',
      'content/dist/rhel9/9.2/ppc64le/resilientstorage/os',
      'content/dist/rhel9/9.2/ppc64le/resilientstorage/source/SRPMS',
      'content/dist/rhel9/9.2/s390x/appstream/debug',
      'content/dist/rhel9/9.2/s390x/appstream/os',
      'content/dist/rhel9/9.2/s390x/appstream/source/SRPMS',
      'content/dist/rhel9/9.2/s390x/highavailability/debug',
      'content/dist/rhel9/9.2/s390x/highavailability/os',
      'content/dist/rhel9/9.2/s390x/highavailability/source/SRPMS',
      'content/dist/rhel9/9.2/s390x/resilientstorage/debug',
      'content/dist/rhel9/9.2/s390x/resilientstorage/os',
      'content/dist/rhel9/9.2/s390x/resilientstorage/source/SRPMS',
      'content/dist/rhel9/9.2/x86_64/appstream/debug',
      'content/dist/rhel9/9.2/x86_64/appstream/os',
      'content/dist/rhel9/9.2/x86_64/appstream/source/SRPMS',
      'content/dist/rhel9/9.2/x86_64/highavailability/debug',
      'content/dist/rhel9/9.2/x86_64/highavailability/os',
      'content/dist/rhel9/9.2/x86_64/highavailability/source/SRPMS',
      'content/dist/rhel9/9.2/x86_64/resilientstorage/debug',
      'content/dist/rhel9/9.2/x86_64/resilientstorage/os',
      'content/dist/rhel9/9.2/x86_64/resilientstorage/source/SRPMS',
      'content/dist/rhel9/9.3/ppc64le/appstream/debug',
      'content/dist/rhel9/9.3/ppc64le/appstream/os',
      'content/dist/rhel9/9.3/ppc64le/appstream/source/SRPMS',
      'content/dist/rhel9/9.3/ppc64le/highavailability/debug',
      'content/dist/rhel9/9.3/ppc64le/highavailability/os',
      'content/dist/rhel9/9.3/ppc64le/highavailability/source/SRPMS',
      'content/dist/rhel9/9.3/ppc64le/resilientstorage/debug',
      'content/dist/rhel9/9.3/ppc64le/resilientstorage/os',
      'content/dist/rhel9/9.3/ppc64le/resilientstorage/source/SRPMS',
      'content/dist/rhel9/9.3/s390x/appstream/debug',
      'content/dist/rhel9/9.3/s390x/appstream/os',
      'content/dist/rhel9/9.3/s390x/appstream/source/SRPMS',
      'content/dist/rhel9/9.3/s390x/highavailability/debug',
      'content/dist/rhel9/9.3/s390x/highavailability/os',
      'content/dist/rhel9/9.3/s390x/highavailability/source/SRPMS',
      'content/dist/rhel9/9.3/s390x/resilientstorage/debug',
      'content/dist/rhel9/9.3/s390x/resilientstorage/os',
      'content/dist/rhel9/9.3/s390x/resilientstorage/source/SRPMS',
      'content/dist/rhel9/9.3/x86_64/appstream/debug',
      'content/dist/rhel9/9.3/x86_64/appstream/os',
      'content/dist/rhel9/9.3/x86_64/appstream/source/SRPMS',
      'content/dist/rhel9/9.3/x86_64/highavailability/debug',
      'content/dist/rhel9/9.3/x86_64/highavailability/os',
      'content/dist/rhel9/9.3/x86_64/highavailability/source/SRPMS',
      'content/dist/rhel9/9.3/x86_64/resilientstorage/debug',
      'content/dist/rhel9/9.3/x86_64/resilientstorage/os',
      'content/dist/rhel9/9.3/x86_64/resilientstorage/source/SRPMS',
      'content/dist/rhel9/9.4/ppc64le/appstream/debug',
      'content/dist/rhel9/9.4/ppc64le/appstream/os',
      'content/dist/rhel9/9.4/ppc64le/appstream/source/SRPMS',
      'content/dist/rhel9/9.4/ppc64le/highavailability/debug',
      'content/dist/rhel9/9.4/ppc64le/highavailability/os',
      'content/dist/rhel9/9.4/ppc64le/highavailability/source/SRPMS',
      'content/dist/rhel9/9.4/ppc64le/resilientstorage/debug',
      'content/dist/rhel9/9.4/ppc64le/resilientstorage/os',
      'content/dist/rhel9/9.4/ppc64le/resilientstorage/source/SRPMS',
      'content/dist/rhel9/9.4/s390x/appstream/debug',
      'content/dist/rhel9/9.4/s390x/appstream/os',
      'content/dist/rhel9/9.4/s390x/appstream/source/SRPMS',
      'content/dist/rhel9/9.4/s390x/highavailability/debug',
      'content/dist/rhel9/9.4/s390x/highavailability/os',
      'content/dist/rhel9/9.4/s390x/highavailability/source/SRPMS',
      'content/dist/rhel9/9.4/s390x/resilientstorage/debug',
      'content/dist/rhel9/9.4/s390x/resilientstorage/os',
      'content/dist/rhel9/9.4/s390x/resilientstorage/source/SRPMS',
      'content/dist/rhel9/9.4/x86_64/appstream/debug',
      'content/dist/rhel9/9.4/x86_64/appstream/os',
      'content/dist/rhel9/9.4/x86_64/appstream/source/SRPMS',
      'content/dist/rhel9/9.4/x86_64/highavailability/debug',
      'content/dist/rhel9/9.4/x86_64/highavailability/os',
      'content/dist/rhel9/9.4/x86_64/highavailability/source/SRPMS',
      'content/dist/rhel9/9.4/x86_64/resilientstorage/debug',
      'content/dist/rhel9/9.4/x86_64/resilientstorage/os',
      'content/dist/rhel9/9.4/x86_64/resilientstorage/source/SRPMS',
      'content/dist/rhel9/9.5/ppc64le/appstream/debug',
      'content/dist/rhel9/9.5/ppc64le/appstream/os',
      'content/dist/rhel9/9.5/ppc64le/appstream/source/SRPMS',
      'content/dist/rhel9/9.5/ppc64le/highavailability/debug',
      'content/dist/rhel9/9.5/ppc64le/highavailability/os',
      'content/dist/rhel9/9.5/ppc64le/highavailability/source/SRPMS',
      'content/dist/rhel9/9.5/ppc64le/resilientstorage/debug',
      'content/dist/rhel9/9.5/ppc64le/resilientstorage/os',
      'content/dist/rhel9/9.5/ppc64le/resilientstorage/source/SRPMS',
      'content/dist/rhel9/9.5/s390x/appstream/debug',
      'content/dist/rhel9/9.5/s390x/appstream/os',
      'content/dist/rhel9/9.5/s390x/appstream/source/SRPMS',
      'content/dist/rhel9/9.5/s390x/highavailability/debug',
      'content/dist/rhel9/9.5/s390x/highavailability/os',
      'content/dist/rhel9/9.5/s390x/highavailability/source/SRPMS',
      'content/dist/rhel9/9.5/s390x/resilientstorage/debug',
      'content/dist/rhel9/9.5/s390x/resilientstorage/os',
      'content/dist/rhel9/9.5/s390x/resilientstorage/source/SRPMS',
      'content/dist/rhel9/9.5/x86_64/appstream/debug',
      'content/dist/rhel9/9.5/x86_64/appstream/os',
      'content/dist/rhel9/9.5/x86_64/appstream/source/SRPMS',
      'content/dist/rhel9/9.5/x86_64/highavailability/debug',
      'content/dist/rhel9/9.5/x86_64/highavailability/os',
      'content/dist/rhel9/9.5/x86_64/highavailability/source/SRPMS',
      'content/dist/rhel9/9.5/x86_64/resilientstorage/debug',
      'content/dist/rhel9/9.5/x86_64/resilientstorage/os',
      'content/dist/rhel9/9.5/x86_64/resilientstorage/source/SRPMS',
      'content/dist/rhel9/9.6/ppc64le/appstream/debug',
      'content/dist/rhel9/9.6/ppc64le/appstream/os',
      'content/dist/rhel9/9.6/ppc64le/appstream/source/SRPMS',
      'content/dist/rhel9/9.6/ppc64le/highavailability/debug',
      'content/dist/rhel9/9.6/ppc64le/highavailability/os',
      'content/dist/rhel9/9.6/ppc64le/highavailability/source/SRPMS',
      'content/dist/rhel9/9.6/ppc64le/resilientstorage/debug',
      'content/dist/rhel9/9.6/ppc64le/resilientstorage/os',
      'content/dist/rhel9/9.6/ppc64le/resilientstorage/source/SRPMS',
      'content/dist/rhel9/9.6/s390x/appstream/debug',
      'content/dist/rhel9/9.6/s390x/appstream/os',
      'content/dist/rhel9/9.6/s390x/appstream/source/SRPMS',
      'content/dist/rhel9/9.6/s390x/highavailability/debug',
      'content/dist/rhel9/9.6/s390x/highavailability/os',
      'content/dist/rhel9/9.6/s390x/highavailability/source/SRPMS',
      'content/dist/rhel9/9.6/s390x/resilientstorage/debug',
      'content/dist/rhel9/9.6/s390x/resilientstorage/os',
      'content/dist/rhel9/9.6/s390x/resilientstorage/source/SRPMS',
      'content/dist/rhel9/9.6/x86_64/appstream/debug',
      'content/dist/rhel9/9.6/x86_64/appstream/os',
      'content/dist/rhel9/9.6/x86_64/appstream/source/SRPMS',
      'content/dist/rhel9/9.6/x86_64/highavailability/debug',
      'content/dist/rhel9/9.6/x86_64/highavailability/os',
      'content/dist/rhel9/9.6/x86_64/highavailability/source/SRPMS',
      'content/dist/rhel9/9.6/x86_64/resilientstorage/debug',
      'content/dist/rhel9/9.6/x86_64/resilientstorage/os',
      'content/dist/rhel9/9.6/x86_64/resilientstorage/source/SRPMS',
      'content/dist/rhel9/9.7/ppc64le/appstream/debug',
      'content/dist/rhel9/9.7/ppc64le/appstream/os',
      'content/dist/rhel9/9.7/ppc64le/appstream/source/SRPMS',
      'content/dist/rhel9/9.7/ppc64le/highavailability/debug',
      'content/dist/rhel9/9.7/ppc64le/highavailability/os',
      'content/dist/rhel9/9.7/ppc64le/highavailability/source/SRPMS',
      'content/dist/rhel9/9.7/ppc64le/resilientstorage/debug',
      'content/dist/rhel9/9.7/ppc64le/resilientstorage/os',
      'content/dist/rhel9/9.7/ppc64le/resilientstorage/source/SRPMS',
      'content/dist/rhel9/9.7/s390x/appstream/debug',
      'content/dist/rhel9/9.7/s390x/appstream/os',
      'content/dist/rhel9/9.7/s390x/appstream/source/SRPMS',
      'content/dist/rhel9/9.7/s390x/highavailability/debug',
      'content/dist/rhel9/9.7/s390x/highavailability/os',
      'content/dist/rhel9/9.7/s390x/highavailability/source/SRPMS',
      'content/dist/rhel9/9.7/s390x/resilientstorage/debug',
      'content/dist/rhel9/9.7/s390x/resilientstorage/os',
      'content/dist/rhel9/9.7/s390x/resilientstorage/source/SRPMS',
      'content/dist/rhel9/9.7/x86_64/appstream/debug',
      'content/dist/rhel9/9.7/x86_64/appstream/os',
      'content/dist/rhel9/9.7/x86_64/appstream/source/SRPMS',
      'content/dist/rhel9/9.7/x86_64/highavailability/debug',
      'content/dist/rhel9/9.7/x86_64/highavailability/os',
      'content/dist/rhel9/9.7/x86_64/highavailability/source/SRPMS',
      'content/dist/rhel9/9.7/x86_64/resilientstorage/debug',
      'content/dist/rhel9/9.7/x86_64/resilientstorage/os',
      'content/dist/rhel9/9.7/x86_64/resilientstorage/source/SRPMS',
      'content/dist/rhel9/9/ppc64le/appstream/debug',
      'content/dist/rhel9/9/ppc64le/appstream/os',
      'content/dist/rhel9/9/ppc64le/appstream/source/SRPMS',
      'content/dist/rhel9/9/ppc64le/highavailability/debug',
      'content/dist/rhel9/9/ppc64le/highavailability/os',
      'content/dist/rhel9/9/ppc64le/highavailability/source/SRPMS',
      'content/dist/rhel9/9/ppc64le/resilientstorage/debug',
      'content/dist/rhel9/9/ppc64le/resilientstorage/os',
      'content/dist/rhel9/9/ppc64le/resilientstorage/source/SRPMS',
      'content/dist/rhel9/9/s390x/appstream/debug',
      'content/dist/rhel9/9/s390x/appstream/os',
      'content/dist/rhel9/9/s390x/appstream/source/SRPMS',
      'content/dist/rhel9/9/s390x/highavailability/debug',
      'content/dist/rhel9/9/s390x/highavailability/os',
      'content/dist/rhel9/9/s390x/highavailability/source/SRPMS',
      'content/dist/rhel9/9/s390x/resilientstorage/debug',
      'content/dist/rhel9/9/s390x/resilientstorage/os',
      'content/dist/rhel9/9/s390x/resilientstorage/source/SRPMS',
      'content/dist/rhel9/9/x86_64/appstream/debug',
      'content/dist/rhel9/9/x86_64/appstream/os',
      'content/dist/rhel9/9/x86_64/appstream/source/SRPMS',
      'content/dist/rhel9/9/x86_64/highavailability/debug',
      'content/dist/rhel9/9/x86_64/highavailability/os',
      'content/dist/rhel9/9/x86_64/highavailability/source/SRPMS',
      'content/dist/rhel9/9/x86_64/resilientstorage/debug',
      'content/dist/rhel9/9/x86_64/resilientstorage/os',
      'content/dist/rhel9/9/x86_64/resilientstorage/source/SRPMS',
      'content/public/ubi/dist/ubi9/9/ppc64le/appstream/debug',
      'content/public/ubi/dist/ubi9/9/ppc64le/appstream/os',
      'content/public/ubi/dist/ubi9/9/ppc64le/appstream/source/SRPMS',
      'content/public/ubi/dist/ubi9/9/s390x/appstream/debug',
      'content/public/ubi/dist/ubi9/9/s390x/appstream/os',
      'content/public/ubi/dist/ubi9/9/s390x/appstream/source/SRPMS',
      'content/public/ubi/dist/ubi9/9/x86_64/appstream/debug',
      'content/public/ubi/dist/ubi9/9/x86_64/appstream/os',
      'content/public/ubi/dist/ubi9/9/x86_64/appstream/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'fence-agents-aliyun-4.10.0-62.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fence-agents-all-4.10.0-62.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fence-agents-amt-ws-4.10.0-62.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fence-agents-apc-4.10.0-62.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fence-agents-apc-snmp-4.10.0-62.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fence-agents-aws-4.10.0-62.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fence-agents-azure-arm-4.10.0-62.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fence-agents-bladecenter-4.10.0-62.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fence-agents-brocade-4.10.0-62.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fence-agents-cisco-mds-4.10.0-62.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fence-agents-cisco-ucs-4.10.0-62.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fence-agents-common-4.10.0-62.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fence-agents-compute-4.10.0-62.el9', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fence-agents-compute-4.10.0-62.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fence-agents-drac5-4.10.0-62.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fence-agents-eaton-snmp-4.10.0-62.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fence-agents-emerson-4.10.0-62.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fence-agents-eps-4.10.0-62.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fence-agents-gce-4.10.0-62.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fence-agents-heuristics-ping-4.10.0-62.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fence-agents-hpblade-4.10.0-62.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fence-agents-ibm-powervs-4.10.0-62.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fence-agents-ibm-vpc-4.10.0-62.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fence-agents-ibmblade-4.10.0-62.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fence-agents-ifmib-4.10.0-62.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fence-agents-ilo-moonshot-4.10.0-62.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fence-agents-ilo-mp-4.10.0-62.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fence-agents-ilo-ssh-4.10.0-62.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fence-agents-ilo2-4.10.0-62.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fence-agents-intelmodular-4.10.0-62.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fence-agents-ipdu-4.10.0-62.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fence-agents-ipmilan-4.10.0-62.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fence-agents-kdump-4.10.0-62.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fence-agents-kubevirt-4.10.0-62.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fence-agents-lpar-4.10.0-62.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fence-agents-mpath-4.10.0-62.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fence-agents-openstack-4.10.0-62.el9', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fence-agents-openstack-4.10.0-62.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fence-agents-redfish-4.10.0-62.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fence-agents-rhevm-4.10.0-62.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fence-agents-rsa-4.10.0-62.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fence-agents-rsb-4.10.0-62.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fence-agents-sbd-4.10.0-62.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fence-agents-scsi-4.10.0-62.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fence-agents-virsh-4.10.0-62.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fence-agents-vmware-rest-4.10.0-62.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fence-agents-vmware-soap-4.10.0-62.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fence-agents-wti-4.10.0-62.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fence-agents-zvm-4.10.0-62.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fence-virt-4.10.0-62.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fence-virtd-4.10.0-62.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fence-virtd-cpg-4.10.0-62.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fence-virtd-libvirt-4.10.0-62.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fence-virtd-multicast-4.10.0-62.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fence-virtd-serial-4.10.0-62.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fence-virtd-tcp-4.10.0-62.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ha-cloud-support-4.10.0-62.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE}
    ]
  }
];

var applicable_repo_urls = rhel_determine_applicable_repository_urls(constraints:constraints);
if(applicable_repo_urls == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);

var flag = 0;
foreach var constraint_array ( constraints ) {
  var repo_relative_urls = NULL;
  if (!empty_or_null(constraint_array['repo_relative_urls'])) repo_relative_urls = constraint_array['repo_relative_urls'];
  foreach var pkg ( constraint_array['pkgs'] ) {
    var reference = NULL;
    var _release = NULL;
    var sp = NULL;
    var _cpu = NULL;
    var el_string = NULL;
    var rpm_spec_vers_cmp = NULL;
    var epoch = NULL;
    var allowmaj = NULL;
    var exists_check = NULL;
    var cves = NULL;
    if (!empty_or_null(pkg['reference'])) reference = pkg['reference'];
    if (!empty_or_null(pkg['release'])) _release = 'RHEL' + pkg['release'];
    if (!empty_or_null(pkg['sp'])) sp = pkg['sp'];
    if (!empty_or_null(pkg['cpu'])) _cpu = pkg['cpu'];
    if (!empty_or_null(pkg['el_string'])) el_string = pkg['el_string'];
    if (!empty_or_null(pkg['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = pkg['rpm_spec_vers_cmp'];
    if (!empty_or_null(pkg['epoch'])) epoch = pkg['epoch'];
    if (!empty_or_null(pkg['allowmaj'])) allowmaj = pkg['allowmaj'];
    if (!empty_or_null(pkg['exists_check'])) exists_check = pkg['exists_check'];
    if (!empty_or_null(pkg['cves'])) cves = pkg['cves'];
    if (reference &&
        _release &&
        rhel_decide_repo_relative_url_check(required_repo_url_list:repo_relative_urls) &&
        (applicable_repo_urls || (!exists_check || rpm_exists(release:_release, rpm:exists_check))) &&
        rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj, cves:cves)) flag++;
  }
}

if (flag)
{
  var extra = NULL;
  if (isnull(applicable_repo_urls) || !applicable_repo_urls) extra = rpm_report_get() + redhat_report_repo_caveat();
  else extra = rpm_report_get();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'fence-agents-aliyun / fence-agents-all / fence-agents-amt-ws / etc');
}
