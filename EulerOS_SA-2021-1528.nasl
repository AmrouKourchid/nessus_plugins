#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(147110);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/12");

  script_cve_id(
    "CVE-2020-14374",
    "CVE-2020-14375",
    "CVE-2020-14376",
    "CVE-2020-14377"
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.6.0 : spdk (EulerOS-SA-2021-1528)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the spdk package installed, the EulerOS
Virtualization for ARM 64 installation on the remote host is affected
by the following vulnerabilities :

  - A flaw was found in dpdk in versions before 18.11.10
    and before 19.11.5. A complete lack of validation of
    attacker-controlled parameters can lead to a buffer
    over read. The results of the over read are then
    written back to the guest virtual machine memory. This
    vulnerability can be used by an attacker in a virtual
    machine to read significant amounts of host memory. The
    highest threat from this vulnerability is to data
    confidentiality and system
    availability.(CVE-2020-14377)

  - A flaw was found in dpdk in versions before 18.11.10
    and before 19.11.5. A lack of bounds checking when
    copying iv_data from the VM guest memory into host
    memory can lead to a large buffer overflow. The highest
    threat from this vulnerability is to data
    confidentiality and integrity as well as system
    availability.(CVE-2020-14376)

  - A flaw was found in dpdk in versions before 18.11.10
    and before 19.11.5. A flawed bounds checking in the
    copy_data function leads to a buffer overflow allowing
    an attacker in a virtual machine to write arbitrary
    data to any address in the vhost_crypto application.
    The highest threat from this vulnerability is to data
    confidentiality and integrity as well as system
    availability.(CVE-2020-14374)

  - A flaw was found in dpdk in versions before 18.11.10
    and before 19.11.5. Virtio ring descriptors, and the
    data they describe are in a region of memory accessible
    by from both the virtual machine and the host. An
    attacker in a VM can change the contents of the memory
    after vhost_crypto has validated it. The highest threat
    from this vulnerability is to data confidentiality and
    integrity as well as system
    availability.CVE-2020-14375)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1528
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?47d943e1");
  script_set_attribute(attribute:"solution", value:
"Update the affected spdk packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14374");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:spdk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.6.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "3.0.6.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.6.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["spdk-19.01.1-126"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "spdk");
}
