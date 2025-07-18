#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151392);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/11");

  script_cve_id(
    "CVE-2016-9798",
    "CVE-2016-9800",
    "CVE-2016-9801",
    "CVE-2016-9802",
    "CVE-2016-9804",
    "CVE-2016-9917",
    "CVE-2016-9918"
  );

  script_name(english:"EulerOS Virtualization 3.0.2.2 : bluez (EulerOS-SA-2021-2129)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the bluez package installed, the EulerOS
Virtualization installation on the remote host is affected by the
following vulnerabilities :

  - In BlueZ 5.42, a use-after-free was identified in
    'conf_opt' function in 'tools/parser/l2cap.c' source
    file. This issue can be triggered by processing a
    corrupted dump file and will result in hcidump
    crash.(CVE-2016-9798)

  - In BlueZ 5.42, a buffer overflow was observed in
    'pin_code_reply_dump' function in 'tools/parser/hci.c'
    source file. The issue exists because 'pin' array is
    overflowed by supplied parameter due to lack of
    boundary checks on size of the buffer from frame
    'pin_code_reply_cp *cp' parameter.(CVE-2016-9800)

  - In BlueZ 5.42, a buffer overflow was observed in
    'set_ext_ctrl' function in 'tools/parser/l2cap.c'
    source file when processing corrupted dump
    file.(CVE-2016-9801)

  - In BlueZ 5.42, a buffer over-read was identified in
    'l2cap_packet' function in 'monitor/packet.c' source
    file. This issue can be triggered by processing a
    corrupted dump file and will result in btmon
    crash.(CVE-2016-9802)

  - In BlueZ 5.42, a buffer overflow was observed in
    'commands_dump' function in 'tools/parser/csr.c' source
    file. The issue exists because 'commands' array is
    overflowed by supplied parameter due to lack of
    boundary checks on size of the buffer from frame
    'frm->ptr' parameter. This issue can be triggered by
    processing a corrupted dump file and will result in
    hcidump crash.(CVE-2016-9804)

  - In BlueZ 5.42, a buffer overflow was observed in
    'read_n' function in 'tools/hcidump.c' source file.
    This issue can be triggered by processing a corrupted
    dump file and will result in hcidump
    crash.(CVE-2016-9917)

  - In BlueZ 5.42, an out-of-bounds read was identified in
    'packet_hexdump' function in 'monitor/packet.c' source
    file. This issue can be triggered by processing a
    corrupted dump file and will result in btmon
    crash.(CVE-2016-9918)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2129
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bda265d4");
  script_set_attribute(attribute:"solution", value:
"Update the affected bluez packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-9918");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bluez-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.2.2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (uvp != "3.0.2.2") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.2.2");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["bluez-libs-5.44-4.h2.eulerosv2r7"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bluez");
}
