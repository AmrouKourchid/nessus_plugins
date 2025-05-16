#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3778. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(192736);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/22");

  script_cve_id(
    "CVE-2020-10703",
    "CVE-2020-12430",
    "CVE-2020-25637",
    "CVE-2021-3631",
    "CVE-2021-3667",
    "CVE-2021-3975",
    "CVE-2021-4147",
    "CVE-2022-0897",
    "CVE-2024-1441",
    "CVE-2024-2494",
    "CVE-2024-2496"
  );
  script_xref(name:"IAVA", value:"2024-A-0184");

  script_name(english:"Debian dla-3778 : libnss-libvirt - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3778 advisory.

    -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3778-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                       Guilhem Moulin
    April 01, 2024                                https://wiki.debian.org/LTS
    -------------------------------------------------------------------------

    Package        : libvirt
    Version        : 5.0.0-4+deb10u2
    CVE ID         : CVE-2020-10703 CVE-2020-12430 CVE-2020-25637 CVE-2021-3631
                     CVE-2021-3667 CVE-2021-3975 CVE-2021-4147 CVE-2022-0897
                     CVE-2024-1441 CVE-2024-2494 CVE-2024-2496
    Debian Bug     : 959447 971555 990709 991594 1002535 1009075 1066058 1067461

    Multiple vulnerabilities were found in libvirt, a C toolkit to interact
    with the virtualization capabilities of Linux, which could lead to
    denial of service or information disclosure.

    CVE-2020-10703

        A NULL pointer dereference was found in the libvirt API that is responsible for
        fetching a storage pool based on its target path.  In more detail, this flaw affects
        storage pools created without a target path such as network-based pools like gluster
        and RBD.  Unprivileged users with a read-only connection could abuse this flaw to
        crash the libvirt daemon, resulting in a potential denial of service.

    CVE-2020-12430

        A memory leak was found in the virDomainListGetStats libvirt API that is responsible
        for retrieving domain statistics when managing QEMU guests.  This flaw allows
        unprivileged users with a read-only connection to cause a memory leak in the domstats
        command, resulting in a potential denial of service.

    CVE-2020-25637

        A double free memory issue was found in the libvirt API that is responsible for
        requesting information about network interfaces of a running QEMU domain.  This flaw
        affects the polkit access control driver.  Specifically, clients connecting to the
        read-write socket with limited ACL permissions could use this flaw to crash the
        libvirt daemon, resulting in a denial of service, or potentially escalate their
        privileges on the system.  The highest threat from this vulnerability is to data
        confidentiality and integrity as well as system availability.

    CVE-2021-3631

        An issue was found in the generation of SELinux MCS category pairs for VMs' dynamic
        labels.  This flaw allows one exploited guest to access files labeled for another
        guest, resulting in the breaking out of sVirt confinement.

    CVE-2021-3667

        An improper locking issue was found in the virStoragePoolLookupByTargetPath API.  It
        occurs in the storagePoolLookupByTargetPath function where a locked virStoragePoolObj
        object is not properly released on ACL permission failure.  Clients connecting to the
        read-write socket with limited ACL permissions could use this flaw to acquire the lock
        and prevent other users from accessing storage pool/volume APIs, resulting in a denial
        of service condition.

    CVE-2021-3975

        A use-after-free issue was found in libvirt in qemuProcessHandleMonitorEOF(), where
        the qemuMonitorUnregister() function is called using multiple threads without being
        adequately protected by a monitor lock.  This flaw could be triggered by the
        virConnectGetAllDomainStats API when the guest is shutting down.  An unprivileged
        client with a read-only connection could use this flaw to perform a denial of service
        attack by causing the libvirt daemon to crash.

    CVE-2021-4147

        Jim Fehlig discovered that a malicious guest using the libxl driver could cause
        libvirtd on the host to deadlock or crash when continuously rebooting itself.

    CVE-2022-0897

        A flaw was found in the libvirt nwfilter driver.  The virNWFilterObjListNumOfNWFilters
        method failed to acquire the driver->nwfilters mutex before iterating over
        virNWFilterObj instances.  There was no protection to stop another thread from
        concurrently modifying the driver->nwfilters object.  This flaw allows a malicious,
        unprivileged user to exploit this issue via libvirt's API virConnectNumOfNWFilters to
        crash the network filter management daemon (libvirtd/virtnwfilterd).

    CVE-2024-1441

        An off-by-one error flaw was found in the udevListInterfacesByStatus() function in
        libvirt when the number of interfaces exceeds the size of the `names` array.  This
        issue can be reproduced by sending specially crafted data to the libvirt daemon,
        allowing an unprivileged client to perform a denial of service attack by causing the
        libvirt daemon to crash.

    CVE-2024-2494

        The ALT Linux Team discovered that the RPC server deserialization code allocates
        memory for arrays before the non-negative length check is performed by the C API entry
        points.  Passing a negative length therefore results in a crash due to the negative
        length being treated as a huge positive number.  This flaw allows a local,
        unprivileged user to perform a denial of service attack by causing the libvirt daemon
        to crash.

    CVE-2024-2496

        A NULL pointer dereference flaw was found in the udevConnectListAllInterfaces()
        function.  This issue can occur when detaching a host interface while at the same time
        collecting the list of interfaces via virConnectListAllInterfaces API.  This flaw
        could be used to perform a denial of service attack by causing the libvirt daemon to
        crash.

    For Debian 10 buster, these problems have been fixed in version
    5.0.0-4+deb10u2.

    We recommend that you upgrade your libvirt packages.

    For the detailed security status of libvirt please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/libvirt

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS
    Attachment:
    signature.asc
    Description: PGP signature

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/libvirt");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-10703");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-12430");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-25637");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3631");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3667");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3975");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-4147");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0897");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-1441");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-2494");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-2496");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/libvirt");
  script_set_attribute(attribute:"solution", value:
"Upgrade the libnss-libvirt packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25637");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnss-libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libvirt-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libvirt-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libvirt-daemon-driver-storage-gluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libvirt-daemon-driver-storage-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libvirt-daemon-driver-storage-zfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libvirt-daemon-system");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libvirt-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libvirt-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libvirt-sanlock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libvirt-wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libvirt0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(10)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'libnss-libvirt', 'reference': '5.0.0-4+deb10u2'},
    {'release': '10.0', 'prefix': 'libvirt-clients', 'reference': '5.0.0-4+deb10u2'},
    {'release': '10.0', 'prefix': 'libvirt-daemon', 'reference': '5.0.0-4+deb10u2'},
    {'release': '10.0', 'prefix': 'libvirt-daemon-driver-storage-gluster', 'reference': '5.0.0-4+deb10u2'},
    {'release': '10.0', 'prefix': 'libvirt-daemon-driver-storage-rbd', 'reference': '5.0.0-4+deb10u2'},
    {'release': '10.0', 'prefix': 'libvirt-daemon-driver-storage-zfs', 'reference': '5.0.0-4+deb10u2'},
    {'release': '10.0', 'prefix': 'libvirt-daemon-system', 'reference': '5.0.0-4+deb10u2'},
    {'release': '10.0', 'prefix': 'libvirt-dev', 'reference': '5.0.0-4+deb10u2'},
    {'release': '10.0', 'prefix': 'libvirt-doc', 'reference': '5.0.0-4+deb10u2'},
    {'release': '10.0', 'prefix': 'libvirt-sanlock', 'reference': '5.0.0-4+deb10u2'},
    {'release': '10.0', 'prefix': 'libvirt-wireshark', 'reference': '5.0.0-4+deb10u2'},
    {'release': '10.0', 'prefix': 'libvirt0', 'reference': '5.0.0-4+deb10u2'}
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
    severity   : SECURITY_HOLE,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libnss-libvirt / libvirt-clients / libvirt-daemon / etc');
}
