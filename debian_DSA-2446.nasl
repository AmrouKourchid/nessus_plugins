#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2446. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(58598);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/29");

  script_cve_id("CVE-2011-3048");
  script_bugtraq_id(52830);
  script_xref(name:"DSA", value:"2446");

  script_name(english:"Debian DSA-2446-1 : libpng - incorrect memory handling");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that incorrect memory handling in the
png_set_text2() function of the PNG library could lead to the
execution of arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/libpng"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2012/dsa-2446"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libpng packages.

For the stable distribution (squeeze), this problem has been fixed in
version libpng_1.2.44-1+squeeze4."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2011-3048");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpng");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");
  script_set_attribute(attribute:"generated_plugin", value:"former");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Debian Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("debian_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/release")) audit(AUDIT_OS_NOT, "Debian");

var dpkg_l_contents = get_kb_item("Host/Debian/dpkg-l");
if (empty_or_null(dpkg_l_contents))
  audit(AUDIT_PACKAGE_LIST_MISSING);

flag = 0;
var flag2 = 0;
if (deb_check(release:"6.0", prefix:"libpng12-0", reference:"libpng_1.2.44-1+squeeze4")) flag2++;
if (deb_check(release:"6.0", prefix:"libpng12-0-udeb", reference:"libpng_1.2.44-1+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"libpng12-dev", reference:"libpng_1.2.44-1+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"libpng3", reference:"libpng_1.2.44-1+squeeze4")) flag++;

if (flag || flag2)
{
  # avoid FP
  if (!flag && flag2 && dpkg_l_contents =~ "ii\s+libpng12-0\s+1\.2\.44\-1\+squeeze(4|[56789]|[1-9][0-9])($|\s)")
    audit(AUDIT_HOST_NOT, "affected");

  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
