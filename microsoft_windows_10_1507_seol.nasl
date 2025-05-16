#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @DEPRECATED@
#
# Disabled on 2024/03/28. Deprecated by windows_10_1507_education_seol.nasl, windows_10_1507_enterprise_seol.nasl, windows_10_1507_home_seol.nasl, and windows_10_1507_iot_seol.nasl.

include('compat.inc');

if (description)
{
  script_id(187378);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/28");

  script_xref(name:"IAVA", value:"0001-A-0020");

  script_name(english:"Microsoft Windows 10 1507 SEoL (deprecated)");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"Microsoft Windows 10 version 1507 is running on the remote host.
Microsoft ended support for Windows 10 version 1507 on May 9, 2017.

This plugin has been deprecated by windows_10_1507_education_seol.nasl, windows_10_1507_enterprise_seol.nasl,
windows_10_1507_home_seol.nasl, and windows_10_1507_iot_seol.nasl in favor of individual SEoL plugins per edition.");
  # https://support.microsoft.com/en-us/help/4015562/windows-10-version-1507-will-no-longer-receive-security-updates
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?67b17ad4");
  # https://docs.microsoft.com/en-us/windows/release-health/release-information
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7f33b3fd");
  # https://docs.microsoft.com/en-us/lifecycle/products/windows-10-enterprise-and-education
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?807cb358");
  # https://docs.microsoft.com/en-us/lifecycle/products/windows-10-home-and-pro
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fa29d6e3");

  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Tenable standard unsupported software score.");

  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/28");
  script_set_attribute(attribute:"seol_date", value:"2017/05/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows_10_1507");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023-2024 Tenable Network Security, Inc.");

  script_require_keys("installed_os/local/SMB/product");

  exit(0);
}

exit(0, 'This plugin has been deprecated. Use windows_10_1507_education_seol.nasl, windows_10_1507_enterprise_seol.nasl, windows_10_1507_home_seol.nasl, and windows_10_1507_iot_seol.nasl instead.');
