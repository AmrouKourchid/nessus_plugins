##
# (C) Tenable, Inc.
##

include("compat.inc");

if (description)
{
  script_id(95719);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/04");

  script_cve_id("CVE-2016-9559");
  script_bugtraq_id(94489);

  script_name(english:"ImageMagick 6.x < 6.9.6-5 TIFFGetProperties() NULL Pointer Dereference DoS");
  script_summary(english:"Checks the version of ImageMagick.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by a
denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of ImageMagick installed on the remote Windows host is 6.x
prior to 6.9.6-5. It is, therefore, affected by a denial of service
vulnerability due to a NULL pointer dereference flaw in the
TIFFGetProperties() function within file coders/tiff.c.
An unauthenticated, remote attacker can exploit this, via a specially
crafted TIFF image, to crash a process linked against the library.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/ImageMagick/ImageMagick/issues/298");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/oss-sec/2016/q4/472");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ImageMagick version 6.9.6-5 or later. Note that you may
also need to manually uninstall the vulnerable version from the
system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-9559");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:imagemagick:imagemagick");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("imagemagick_installed.nasl");
  script_require_keys("installed_sw/ImageMagick");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:"ImageMagick");

var constraints = [
  {'min_version' : '6.0.0-0', 'fixed_version' : '6.9.6.5', 'fixed_display' : '6.9.6-5'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
