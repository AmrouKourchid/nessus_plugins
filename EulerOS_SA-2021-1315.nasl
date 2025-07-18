#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(146696);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/19");

  script_cve_id(
    "CVE-2019-9278",
    "CVE-2020-0093",
    "CVE-2020-0181",
    "CVE-2020-0182",
    "CVE-2020-0198"
  );

  script_name(english:"EulerOS 2.0 SP2 : libexif (EulerOS-SA-2021-1315)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the libexif package installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - In exif_data_save_data_entry of exif-data.c, there is a
    possible out of bounds read due to a missing bounds
    check. This could lead to local information disclosure
    with no additional execution privileges needed. User
    interaction is needed for exploitation.Product:
    AndroidVersions: Android-8.0 Android-8.1 Android-9
    Android-10Android ID: A-148705132(CVE-2020-0093)

  - In exif_entry_get_value of exif-entry.c, there is a
    possible out of bounds read due to a missing bounds
    check. This could lead to local information disclosure
    with no additional execution privileges needed. User
    interaction is not needed for exploitation.Product:
    AndroidVersions: Android-10Android ID:
    A-147140917(CVE-2020-0182)

  - In exif_data_load_data_content of exif-data.c, there is
    a possible UBSAN abort due to an integer overflow. This
    could lead to remote denial of service with no
    additional execution privileges needed. User
    interaction is needed for exploitation.Product:
    AndroidVersions: Android-10Android ID:
    A-146428941(CVE-2020-0198)

  - In libexif, there is a possible out of bounds write due
    to an integer overflow. This could lead to remote
    escalation of privilege in the media content provider
    with no additional execution privileges needed. User
    interaction is needed for exploitation. Product:
    AndroidVersions: Android-10Android ID:
    A-112537774(CVE-2019-9278)

  - In exif_data_load_data_thumbnail of exif-data.c, there
    is a possible denial of service due to an integer
    overflow. This could lead to remote denial of service
    with no additional execution privileges needed. User
    interaction is not needed for exploitation.Product:
    AndroidVersions: Android-10Android ID:
    A-145075076(CVE-2020-0181)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1315
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c2357dbf");
  script_set_attribute(attribute:"solution", value:
"Update the affected libexif packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-9278");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libexif");
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
if (isnull(sp) || sp !~ "^(2)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["libexif-0.6.21-6.h6"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"2", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libexif");
}
