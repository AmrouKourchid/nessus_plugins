#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(147036);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/16");

  script_cve_id(
    "CVE-2020-16592",
    "CVE-2020-16598",
    "CVE-2020-35493",
    "CVE-2020-35494",
    "CVE-2020-35495",
    "CVE-2020-35496",
    "CVE-2020-35507"
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.6.0 : binutils (EulerOS-SA-2021-1580)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the binutils package installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - A Null Pointer Dereference vulnerability exists in the
    Binary File Descriptor (BFD) library (aka libbfd), as
    distributed in GNU Binutils 2.34, in
    debug_get_real_type, as demonstrated in objdump, that
    can cause a denial of service via a crafted
    file.(CVE-2020-16598)

  - A use after free issue exists in the Binary File
    Descriptor (BFD) library (aka libbfd) in GNU Binutils
    2.34 in bfd_hash_lookup, as demonstrated in nm-new,
    that can cause a denial of service via a crafted
    file.(CVE-2020-16592)

  - A flaw was found in binutils. An attacker who is able
    to submit a crafted input file to be processed by the
    objdump program could cause a null pointer dereference.
    The greatest threat from this flaw is to application
    availability.(CVE-2020-35495)

  - A flaw was found in binutils. An attacker who is able
    to submit a crafted input file to be processed by
    binutils could cause usage of uninitialized memory. The
    highest threat is to application availability with a
    lower threat to data confidentiality.(CVE-2020-35494)

  - A flaw was found in Binutils in bfd/pef.c. This flaw
    allows an attacker who can submit a crafted PEF file to
    be parsed by objdump to cause a heap buffer overflow,
    leading to an out-of-bounds read. The highest threat
    from this vulnerability is to system
    availability.(CVE-2020-35493)

  - A flaw was found in bfd_pef_parse_function_stubs of
    bfd/pef.c in binutils which could allow an attacker who
    is able to submit a crafted file to be processed by
    objdump to cause a NULL pointer dereference. The
    greatest threat of this flaw is to application
    availability.(CVE-2020-35507)

  - A flaw was found in bfd_pef_scan_start_address() of
    bfd/pef.c in binutils which could allow an attacker who
    is able to submit a crafted file to be processed by
    objdump to cause a NULL pointer dereference. The
    greatest threat of this flaw is to application
    availability.(CVE-2020-35496)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1580
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?be19a1ba");
  script_set_attribute(attribute:"solution", value:
"Update the affected binutils packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-35494");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:binutils");
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

pkgs = ["binutils-2.31.1-13.h21.eulerosv2r8"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "binutils");
}
