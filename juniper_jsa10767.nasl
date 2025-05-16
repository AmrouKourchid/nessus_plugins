#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 9/5/2023. Deprecated due to target obsolescence.
#

include("compat.inc");

if (description)
{
  script_id(94678);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/05");

  script_cve_id("CVE-2016-4925");
  script_bugtraq_id(93533);
  script_xref(name:"JSA", value:"JSA10767");

  script_name(english:"Juniper JUNOSe IPv6 Packet Handling Line Card Reset Remote DoS (JSA10767) (deprecated)");
  script_summary(english:"Checks the JunosE version.");

  script_set_attribute(attribute:"synopsis", value:"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"According to its version, the remote Juniper E-eries device is
affected by a denial of service vulnerability in the IPv6 support
component due to improper handling IPv6 packets. An unauthenticated,
remote attacker can exploit this, via a specially crafted IPv6 packet,
to cause the line card to reset.

Note that devices with IPv6 disabled are not affected.

This plugin has been deprecated. Juniper ERX devices reached
End of Support Life on October 26, 2018.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10767");
  script_set_attribute(attribute:"see_also", value:"https://support.juniper.net/support/eol/software/junose/");
  script_set_attribute(attribute:"solution", value:"N/A");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-4925");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/10");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junose");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_require_keys("Settings/ParanoidReport", "Host/JunosE/version");

  exit(0);
}

exit(0, 'This plugin has been deprecated. Juniper ERX devices reached End of Support Life on October 26, 2018.');

