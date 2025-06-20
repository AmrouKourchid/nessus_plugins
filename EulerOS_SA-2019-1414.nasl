#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124917);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/23");

  script_cve_id(
    "CVE-2017-13077",
    "CVE-2017-13078",
    "CVE-2017-13079",
    "CVE-2017-13080",
    "CVE-2017-13081",
    "CVE-2017-13082",
    "CVE-2017-13086",
    "CVE-2017-13087",
    "CVE-2017-13088",
    "CVE-2018-14526"
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.1.0 : wpa_supplicant (EulerOS-SA-2019-1414)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the wpa_supplicant package installed,
the EulerOS Virtualization for ARM 64 installation on the remote host
is affected by the following vulnerabilities :

  - An issue was discovered in rsn_supp/wpa.c in
    wpa_supplicant 2.0 through 2.6. Under certain
    conditions, the integrity of EAPOL-Key messages is not
    checked, leading to a decryption oracle. An attacker
    within range of the Access Point and client can abuse
    the vulnerability to recover sensitive
    information.(CVE-2018-14526)

  - A new exploitation technique called key reinstallation
    attacks (KRACK) affecting WPA2 has been discovered. A
    remote attacker within Wi-Fi range could exploit this
    attack to decrypt Wi-Fi traffic or possibly inject
    forged Wi-Fi packets by reinstalling a previously used
    pairwise key (PTK-TK) by retransmitting Fast BSS
    Transition (FT) Reassociation Requests.(CVE-2017-13082)

  - A new exploitation technique called key reinstallation
    attacks (KRACK) affecting WPA2 has been discovered. A
    remote attacker within Wi-Fi range could exploit this
    attack to decrypt Wi-Fi traffic or possibly inject
    forged Wi-Fi packets by reinstalling a previously used
    group key (GTK) during a group key
    handshake.(CVE-2017-13080)

  - Wi-Fi Protected Access (WPA and WPA2) that supports
    IEEE 802.11w allows reinstallation of the Integrity
    Group Temporal Key (IGTK) during the group key
    handshake, allowing an attacker within radio range to
    spoof frames from access points to
    clients.(CVE-2017-13081)

  - A new exploitation technique called key reinstallation
    attacks (KRACK) affecting WPA2 has been discovered. A
    remote attacker within Wi-Fi range could exploit this
    attack to decrypt Wi-Fi traffic or possibly inject
    forged Wi-Fi packets by reinstalling a previously used
    Tunneled Direct-Link Setup (TDLS) Peerkey (TPK) key
    during a TDLS handshake.(CVE-2017-13086)

  - Wi-Fi Protected Access (WPA and WPA2) that supports
    IEEE 802.11w allows reinstallation of the Integrity
    Group Temporal Key (IGTK) during the four-way
    handshake, allowing an attacker within radio range to
    spoof frames from access points to
    clients.(CVE-2017-13079)

  - A new exploitation technique called key reinstallation
    attacks (KRACK) affecting WPA2 has been discovered. A
    remote attacker within Wi-Fi range could exploit this
    attack to decrypt Wi-Fi traffic or possibly inject
    forged Wi-Fi packets by reinstalling a previously used
    group key (GTK) during a 4-way
    handshake.(CVE-2017-13078)

  - A new exploitation technique called key reinstallation
    attacks (KRACKs) affecting WPA2 has been discovered. A
    remote attacker within Wi-Fi range could exploit this
    attack to decrypt Wi-Fi traffic or possibly inject
    forged Wi-Fi packets by reinstalling a previously used
    pairwise key (PTK-TK) during a 4-way
    handshake.(CVE-2017-13077)

  - A new exploitation technique called key reinstallation
    attacks (KRACK) affecting WPA2 has been discovered. A
    remote attacker within Wi-Fi range could exploit this
    attack to decrypt Wi-Fi traffic or possibly inject
    forged Wi-Fi packets by reinstalling a previously used
    integrity group key (IGTK) during a Wireless Network
    Management (WNM) Sleep Mode handshake.(CVE-2017-13088)

  - A new exploitation technique called key reinstallation
    attacks (KRACK) affecting WPA2 has been discovered. A
    remote attacker within Wi-Fi range could exploit this
    attack to decrypt Wi-Fi traffic or possibly inject
    forged Wi-Fi packets by reinstalling a previously used
    group key (GTK) during a Wireless Network Management
    (WNM) Sleep Mode handshake.(CVE-2017-13087)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1414
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a63927e7");
  script_set_attribute(attribute:"solution", value:
"Update the affected wpa_supplicant packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-13082");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:wpa_supplicant");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.1.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (uvp != "3.0.1.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.1.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["wpa_supplicant-2.6-9.h1"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "wpa_supplicant");
}
