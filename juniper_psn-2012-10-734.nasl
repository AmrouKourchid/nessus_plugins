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
  script_id(70102);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/05");

  script_bugtraq_id(57331);

  script_name(english:"Juniper JunosE Malformed IP Option Remote DoS (deprecated)");
  script_summary(english:"Checks to JunosE version.");

  script_set_attribute(attribute:"synopsis", value:"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"According to its version, the remote Juniper E-Series device is
affected by a remote denial of service vulnerability that can be
triggered by sending packets with a malformed IPv4 Option set,
resulting in a device reset. IPv6 is not vulnerable to this issue.

This plugin has been deprecated. Juniper ERX devices reached
End of Support Life on October 26, 2018.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10539");
  script_set_attribute(attribute:"see_also", value:"https://support.juniper.net/support/eol/software/junose/");
  script_set_attribute(attribute:"solution", value:"N/A");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junose");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2023 Tenable Network Security, Inc.");

  script_require_keys("Host/JunosE/version");

  exit(0);
}

exit(0, 'This plugin has been deprecated. Juniper ERX devices reached End of Support Life on October 26, 2018.');

