#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(143400);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/07");

  script_cve_id(
    "CVE-2019-17007",
    "CVE-2020-12399",
    "CVE-2020-12400",
    "CVE-2020-12403",
    "CVE-2020-25648"
  );

  script_name(english:"EulerOS 2.0 SP9 : nss (EulerOS-SA-2020-2487)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the nss packages installed, the EulerOS
installation on the remote host is affected by the following
vulnerabilities :

  - NSS has shown timing differences when performing DSA
    signatures, which was exploitable and could eventually
    leak private keys. This vulnerability affects
    Thunderbird < 68.9.0, Firefox < 77, and Firefox ESR <
    68.9.(CVE-2020-12399)

  - When converting coordinates from projective to affine,
    the modular inversion was not performed in constant
    time, resulting in a possible timing-based side channel
    attack. This vulnerability affects Firefox < 80 and
    Firefox for Android < 80.(CVE-2020-12400)

  - A flaw was found in the way CHACHA20-POLY1305 was
    implemented in NSS. When using multi-part Chacha20, it
    could cause out-of-bounds reads. This issue was fixed
    by explicitly disabling multi-part ChaCha20 (which was
    not functioning correctly) and strictly enforcing tag
    length. The highest threat from(CVE-2020-12403)

  - A flaw was found in the way NSS handled CCS
    (ChangeCipherSpec) messages in TLS 1.3. This flaw
    allows a remote attacker to send multiple CCS messages,
    causing a denial of service for servers compiled with
    the NSS library. The highest threat from this
    vulnerability is to system availability. This flaw
    affects NSS versions before 3.58.(CVE-2020-25648)

  - In Network Security Services before 3.44, a malformed
    Netscape Certificate Sequence can cause NSS to crash,
    resulting in a denial of service.(CVE-2019-17007)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-2487
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2b187de8");
  script_set_attribute(attribute:"solution", value:
"Update the affected nss packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-12403");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:nss-softokn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:nss-util");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0");

sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(9)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP9");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP9", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["nss-3.40.1-11.h7.eulerosv2r9",
        "nss-softokn-3.40.1-11.h7.eulerosv2r9",
        "nss-util-3.40.1-11.h7.eulerosv2r9"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"9", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nss");
}
