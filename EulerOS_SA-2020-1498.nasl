#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(135660);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/21");

  script_cve_id(
    "CVE-2014-3591",
    "CVE-2014-5270",
    "CVE-2015-0837",
    "CVE-2017-7526"
  );
  script_bugtraq_id(69164, 73064, 73066);

  script_name(english:"EulerOS Virtualization 3.0.2.2 : libgcrypt (EulerOS-SA-2020-1498)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the libgcrypt package installed, the
EulerOS Virtualization installation on the remote host is affected by
the following vulnerabilities :

  - Libgcrypt before 1.5.4, as used in GnuPG and other
    products, does not properly perform ciphertext
    normalization and ciphertext randomization, which makes
    it easier for physically proximate attackers to conduct
    key-extraction attacks by leveraging the ability to
    collect voltage data from exposed metal, a different
    vector than CVE-2013-4576.(CVE-2014-5270)

  - libgcrypt before version 1.7.8 is vulnerable to a cache
    side-channel attack resulting into a complete break of
    RSA-1024 while using the left-to-right method for
    computing the sliding-window expansion. The same attack
    is believed to work on RSA-2048 with moderately more
    computation. This side-channel requires that attacker
    can run arbitrary software on the hardware where the
    private RSA key is used.(CVE-2017-7526)

  - Libgcrypt before 1.6.3 and GnuPG before 1.4.19 does not
    implement ciphertext blinding for Elgamal decryption,
    which allows physically proximate attackers to obtain
    the server's private key by determining factors using
    crafted ciphertext and the fluctuations in the
    electromagnetic field during
    multiplication.(CVE-2014-3591)

  - The mpi_powm function in Libgcrypt before 1.6.3 and
    GnuPG before 1.4.19 allows attackers to obtain
    sensitive information by leveraging timing differences
    when accessing a pre-computed table during modular
    exponentiation, related to a 'Last-Level Cache
    Side-Channel Attack.'(CVE-2015-0837)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1498
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fcf879ab");
  script_set_attribute(attribute:"solution", value:
"Update the affected libgcrypt packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-7526");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libgcrypt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.2.2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

pkgs = ["libgcrypt-1.5.3-14.h4.eulerosv2r7"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libgcrypt");
}
