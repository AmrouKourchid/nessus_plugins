#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149187);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/02");

  script_cve_id(
    "CVE-2015-3217",
    "CVE-2015-5073",
    "CVE-2021-27218",
    "CVE-2021-27219",
    "CVE-2021-28153"
  );
  script_bugtraq_id(75018, 75430);

  script_name(english:"EulerOS 2.0 SP3 : glib2 (EulerOS-SA-2021-1789)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the glib2 packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - An issue was discovered in GNOME GLib before 2.66.6 and
    2.67.x before 2.67.3. The function g_bytes_new has an
    integer overflow on 64-bit platforms due to an implicit
    cast from 64 bits to 32 bits. The overflow could
    potentially lead to memory corruption.(CVE-2021-27219)

  - An issue was discovered in GNOME GLib before 2.66.7 and
    2.67.x before 2.67.4. If g_byte_array_new_take() was
    called with a buffer of 4GB or more on a 64-bit
    platform, the length would be truncated modulo 2**32,
    causing unintended length truncation.(CVE-2021-27218)

  - An issue was discovered in GNOME GLib before 2.66.8.
    When g_file_replace() is used with
    G_FILE_CREATE_REPLACE_DESTINATION to replace a path
    that is a dangling symlink, it incorrectly also creates
    the target of the symlink as an empty file, which could
    conceivably have security relevance if the symlink is
    attacker-controlled. (If the path is a symlink to a
    file that already exists, then the contents of that
    file correctly remain unchanged.)(CVE-2021-28153)

  - Heap-based buffer overflow in the find_fixedlength
    function in pcre_compile.c in PCRE before 8.38 allows
    remote attackers to cause a denial of service (crash)
    or obtain sensitive information from heap memory and
    possibly bypass the ASLR protection mechanism via a
    crafted regular expression with an excess closing
    parenthesis.(CVE-2015-5073)

  - PCRE 7.8 and 8.32 through 8.37, and PCRE2 10.10
    mishandle group empty matches, which might allow remote
    attackers to cause a denial of service (stack-based
    buffer overflow) via a crafted regular expression, as
    demonstrated by
    /^(?:(?(1)\\.|([^\\\\W_])?)+)+$/.(CVE-2015-3217)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1789
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d1a7f00f");
  script_set_attribute(attribute:"solution", value:
"Update the affected glib2 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-5073");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glib2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glib2-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (isnull(sp) || sp !~ "^(3)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["glib2-2.50.3-3.h7",
        "glib2-devel-2.50.3-3.h7"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"3", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glib2");
}
