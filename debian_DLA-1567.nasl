#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1567-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(118735);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/26");

  script_cve_id("CVE-2018-18718");

  script_name(english:"Debian DLA-1567-1 : gthumb security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"CVE-2018-18718 - CWE-415: Double Free The product calls free() twice
on the same memory address, potentially leading to modification of
unexpected memory locations.

There is a suspected double-free bug with static void
add_themes_from_dir() dlg-contact-sheet.c. This method involves two
successive calls of g_free(buffer) (line 354 and 373), and is likely
to cause double-free of the buffer. One possible fix could be directly
assigning the buffer to NULL after the first call of g_free(buffer).
Thanks Tianjun Wu https://gitlab.gnome.org/GNOME/gthumb/issues/18

For Debian 8 'Jessie', this problem has been fixed in version
3:3.3.1-2.1+deb8u1

We recommend that you upgrade your gthumb packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://gitlab.gnome.org/GNOME/gthumb/issues/18");
  script_set_attribute(attribute:"see_also", value:"https://lists.debian.org/debian-lts-announce/2018/11/msg00002.html");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/jessie/gthumb");
  script_set_attribute(attribute:"solution", value:
"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-18718");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gthumb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gthumb-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gthumb-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gthumb-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (deb_check(release:"8.0", prefix:"gthumb", reference:"3:3.3.1-2.1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"gthumb-data", reference:"3:3.3.1-2.1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"gthumb-dbg", reference:"3:3.3.1-2.1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"gthumb-dev", reference:"3:3.3.1-2.1+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
