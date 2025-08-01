#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104703);
  script_version("3.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/09");

  script_cve_id("CVE-2017-1000251", "CVE-2017-1000253", "CVE-2017-12154");
  script_xref(name:"IAVB", value:"2017-B-0135-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/09/30");

  script_name(english:"Virtuozzo 7 : readykernel-patch (VZA-2017-086)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Virtuozzo host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to the version of the vzkernel package and the
readykernel-patch installed, the Virtuozzo installation on the remote
host is affected by the following vulnerabilities :

  - A flaw was found in the way the Linux kernel loaded ELF
    executables. Provided that an application was built as
    Position Independent Executable (PIE), the loader could
    allow part of that application's data segment to map
    over the memory area reserved for its stack,
    potentially resulting in memory corruption. An
    unprivileged local user with access to SUID (or
    otherwise privileged) PIE binary could use this flaw to
    escalate their privileges on the system.

  - A stack buffer overflow flaw was found in the way the
    Bluetooth subsystem of the Linux kernel processed
    pending L2CAP configuration responses from a client. On
    systems with the stack protection feature enabled in
    the kernel an unauthenticated attacker able to initiate
    a connection to a system via Bluetooth could use this
    flaw to crash the system. Due to the nature of the
    stack protection feature, code execution cannot be
    fully ruled out, although we believe it is unlikely.

  - The prepare_vmcs02 function in arch/x86/kvm/vmx.c in
    the Linux kernel through 4.13.3 does not ensure that
    the 'CR8-load exiting' and 'CR8-store exiting' L0
    vmcs02 controls exist in cases where L1 omits the 'use
    TPR shadow' vmcs12 control, which allows KVM L2 guest
    OS users to obtain read and write access to the
    hardware CR8 register.

Note that Tenable Network Security has extracted the preceding
description block directly from the Virtuozzo security advisory.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://help.virtuozzo.com/customer/portal/articles/2881453");
  # https://readykernel.com/patch/Virtuozzo-7/readykernel-patch-15.2-32.1-1.vl7/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?80fa3656");
  # https://readykernel.com/patch/Virtuozzo-7/readykernel-patch-18.7-32.1-1.vl7/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d9bfb930");
  # https://readykernel.com/patch/Virtuozzo-7/readykernel-patch-20.18-32.1-1.vl7/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1666c1ac");
  # https://readykernel.com/patch/Virtuozzo-7/readykernel-patch-30.10-32.1-1.vl7/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?692ae938");
  # https://readykernel.com/patch/Virtuozzo-7/readykernel-patch-30.15-32.1-1.vl7/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?afeeded6");
  # https://readykernel.com/patch/Virtuozzo-7/readykernel-patch-33.22-32.1-1.vl7/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?858ad3c2");
  script_set_attribute(attribute:"solution", value:
"Update the readykernel patch.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-1000251");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:readykernel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:virtuozzo:virtuozzo:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Virtuozzo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Virtuozzo/release", "Host/Virtuozzo/rpm-list", "Host/readykernel-info");

  exit(0);
}

include("global_settings.inc");
include("readykernel.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/Virtuozzo/release");
if (isnull(release) || "Virtuozzo" >!< release) audit(AUDIT_OS_NOT, "Virtuozzo");
os_ver = pregmatch(pattern: "Virtuozzo Linux release ([0-9]+\.[0-9])(\D|$)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Virtuozzo");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Virtuozzo 7.x", "Virtuozzo " + os_ver);

if (!get_kb_item("Host/Virtuozzo/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Virtuozzo", cpu);

rk_info = get_kb_item("Host/readykernel-info");
if (empty_or_null(rk_info)) audit(AUDIT_UNKNOWN_APP_VER, "Virtuozzo");

checks = make_list2(
  make_array(
    "kernel","vzkernel-3.10.0-327.18.2.vz7.15.2",
    "patch","readykernel-patch-15.2-32.1-1.vl7"
  ),
  make_array(
    "kernel","vzkernel-3.10.0-327.36.1.vz7.18.7",
    "patch","readykernel-patch-18.7-32.1-1.vl7"
  ),
  make_array(
    "kernel","vzkernel-3.10.0-327.36.1.vz7.20.18",
    "patch","readykernel-patch-20.18-32.1-1.vl7"
  ),
  make_array(
    "kernel","vzkernel-3.10.0-514.16.1.vz7.30.10",
    "patch","readykernel-patch-30.10-32.1-1.vl7"
  ),
  make_array(
    "kernel","vzkernel-3.10.0-514.16.1.vz7.30.15",
    "patch","readykernel-patch-30.15-32.1-1.vl7"
  ),
  make_array(
    "kernel","vzkernel-3.10.0-514.26.1.vz7.33.22",
    "patch","readykernel-patch-33.22-32.1-1.vl7"
  )
);
readykernel_execute_checks(checks:checks, severity:SECURITY_HOLE, release:"Virtuozzo-7");
