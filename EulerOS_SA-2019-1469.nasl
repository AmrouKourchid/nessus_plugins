#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124793);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/23");

  script_cve_id(
    "CVE-2019-7573",
    "CVE-2019-7576",
    "CVE-2019-7577",
    "CVE-2019-7578",
    "CVE-2019-7635",
    "CVE-2019-7636",
    "CVE-2019-7637",
    "CVE-2019-7638"
  );

  script_name(english:"EulerOS Virtualization 3.0.1.0 : SDL (EulerOS-SA-2019-1469)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the SDL package installed, the EulerOS
Virtualization installation on the remote host is affected by the
following vulnerabilities :

  - SDL (Simple DirectMedia Layer) through 1.2.15 and 2.x
    through 2.0.9 has a heap-based buffer over-read in
    InitMS_ADPCM in audio/SDL_wave.c (inside the wNumCoef
    loop).(CVE-2019-7573)

  - SDL (Simple DirectMedia Layer) through 1.2.15 and 2.x
    through 2.0.9 has a heap-based buffer over-read in
    InitMS_ADPCM in audio/SDL_wave.c (outside the wNumCoef
    loop).(CVE-2019-7576)

  - SDL (Simple DirectMedia Layer) through 1.2.15 and 2.x
    through 2.0.9 has a buffer over-read in SDL_LoadWAV_RW
    in audio/SDL_wave.c.(CVE-2019-7577)

  - SDL (Simple DirectMedia Layer) through 1.2.15 and 2.x
    through 2.0.9 has a heap-based buffer over-read in
    InitIMA_ADPCM in audio/SDL_wave.c.(CVE-2019-7578)

  - SDL (Simple DirectMedia Layer) through 1.2.15 and 2.x
    through 2.0.9 has a heap-based buffer over-read in
    Blit1to4 in video/SDL_blit_1.c.(CVE-2019-7635)

  - SDL (Simple DirectMedia Layer) through 1.2.15 and 2.x
    through 2.0.9 has a heap-based buffer over-read in
    Map1toN in video/SDL_pixels.c.(CVE-2019-7638)

  - SDL (Simple DirectMedia Layer) through 1.2.15 and 2.x
    through 2.0.9 has a heap-based buffer over-read in
    SDL_GetRGB in video/SDL_pixels.c.(CVE-2019-7636)

  - SDL (Simple DirectMedia Layer) through 1.2.15 and 2.x
    through 2.0.9 has a heap-based buffer overflow in
    SDL_FillRect in video/SDL_surface.c.(CVE-2019-7637)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1469
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c0943461");
  script_set_attribute(attribute:"solution", value:
"Update the affected SDL packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-7638");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:SDL");
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
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["SDL-1.2.15-14.h1"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "SDL");
}
