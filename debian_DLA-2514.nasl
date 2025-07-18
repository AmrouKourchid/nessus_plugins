#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2514-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(144723);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/31");

  script_cve_id("CVE-2017-6888", "CVE-2020-0499");

  script_name(english:"Debian DLA-2514-1 : flac security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"Two vulnerabilities were fixed in flac, the library for the Free
Lossless Audio Codec.

CVE-2017-6888

Memory leak via a specially crafted FLAC file

CVE-2020-0499

Out of bounds read due to a heap buffer overflow

For Debian 9 stretch, these problems have been fixed in version
1.3.2-2+deb9u1.

We recommend that you upgrade your flac packages.

For the detailed security status of flac please refer to its security
tracker page at: https://security-tracker.debian.org/tracker/flac

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://lists.debian.org/debian-lts-announce/2021/01/msg00001.html");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/flac");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/flac");
  script_set_attribute(attribute:"solution", value:
"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-0499");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2017-6888");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:flac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libflac++-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libflac++6v5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libflac-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libflac-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libflac8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("debian_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/release")) audit(AUDIT_OS_NOT, "Debian");
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (deb_check(release:"9.0", prefix:"flac", reference:"1.3.2-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libflac++-dev", reference:"1.3.2-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libflac++6v5", reference:"1.3.2-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libflac-dev", reference:"1.3.2-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libflac-doc", reference:"1.3.2-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libflac8", reference:"1.3.2-2+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
