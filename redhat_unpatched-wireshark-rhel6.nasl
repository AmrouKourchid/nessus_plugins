#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# @DEPRECATED@
#
# Disabled on 2024-05-31.
# This plugin has been deprecated as it does not adhere to established standards for this style of check.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory wireshark. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(196731);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/31");

  script_cve_id(
    "CVE-2016-2523",
    "CVE-2016-2530",
    "CVE-2016-2531",
    "CVE-2016-2532",
    "CVE-2016-4006",
    "CVE-2016-4076",
    "CVE-2016-4077",
    "CVE-2016-4078",
    "CVE-2016-4079",
    "CVE-2016-4080",
    "CVE-2016-4081",
    "CVE-2016-4082",
    "CVE-2016-4083",
    "CVE-2016-4084",
    "CVE-2016-4085",
    "CVE-2016-4417",
    "CVE-2016-4418",
    "CVE-2016-4421",
    "CVE-2016-5350",
    "CVE-2016-5351",
    "CVE-2016-5352",
    "CVE-2016-5353",
    "CVE-2016-5354",
    "CVE-2016-5355",
    "CVE-2016-5356",
    "CVE-2016-5357",
    "CVE-2016-5358",
    "CVE-2016-5359",
    "CVE-2016-6505",
    "CVE-2016-6506",
    "CVE-2016-6507",
    "CVE-2016-6508",
    "CVE-2016-6509",
    "CVE-2016-6510",
    "CVE-2016-6511",
    "CVE-2016-6512",
    "CVE-2016-6513",
    "CVE-2016-7175",
    "CVE-2016-7176",
    "CVE-2016-7177",
    "CVE-2016-7178",
    "CVE-2016-7179",
    "CVE-2016-7180",
    "CVE-2016-7957",
    "CVE-2016-7958",
    "CVE-2016-9372",
    "CVE-2016-9373",
    "CVE-2016-9374",
    "CVE-2016-9375",
    "CVE-2016-9376",
    "CVE-2017-5596",
    "CVE-2017-5597",
    "CVE-2017-6014",
    "CVE-2017-6467",
    "CVE-2017-6468",
    "CVE-2017-6469",
    "CVE-2017-6470",
    "CVE-2017-6471",
    "CVE-2017-6472",
    "CVE-2017-6473",
    "CVE-2017-6474",
    "CVE-2017-7700",
    "CVE-2017-7701",
    "CVE-2017-7702",
    "CVE-2017-7703",
    "CVE-2017-7704",
    "CVE-2017-7705",
    "CVE-2017-7745",
    "CVE-2017-7746",
    "CVE-2017-7747",
    "CVE-2017-7748",
    "CVE-2017-9343",
    "CVE-2017-9344",
    "CVE-2017-9345",
    "CVE-2017-9346",
    "CVE-2017-9347",
    "CVE-2017-9348",
    "CVE-2017-9349",
    "CVE-2017-9350",
    "CVE-2017-9351",
    "CVE-2017-9352",
    "CVE-2017-9353",
    "CVE-2017-9354",
    "CVE-2017-9616",
    "CVE-2017-9617",
    "CVE-2017-9766",
    "CVE-2017-11406",
    "CVE-2017-11407",
    "CVE-2017-11408",
    "CVE-2017-11409",
    "CVE-2017-11410",
    "CVE-2017-11411",
    "CVE-2017-13764",
    "CVE-2017-13765",
    "CVE-2017-13766",
    "CVE-2017-13767",
    "CVE-2017-15189",
    "CVE-2017-15190",
    "CVE-2017-15191",
    "CVE-2017-15192",
    "CVE-2017-15193",
    "CVE-2017-17083",
    "CVE-2017-17084",
    "CVE-2017-17085",
    "CVE-2017-17935",
    "CVE-2017-17997",
    "CVE-2018-5334",
    "CVE-2018-5335",
    "CVE-2018-5336",
    "CVE-2018-6836",
    "CVE-2018-7418",
    "CVE-2018-11358",
    "CVE-2018-11362",
    "CVE-2018-14340",
    "CVE-2018-14341",
    "CVE-2018-14368",
    "CVE-2018-16057",
    "CVE-2018-19622",
    "CVE-2018-19625",
    "CVE-2019-9209",
    "CVE-2019-12295",
    "CVE-2019-16319",
    "CVE-2020-7044",
    "CVE-2020-7045",
    "CVE-2020-9428",
    "CVE-2020-9430",
    "CVE-2020-9431",
    "CVE-2020-13164",
    "CVE-2020-26421",
    "CVE-2021-22207",
    "CVE-2023-0411",
    "CVE-2023-0412",
    "CVE-2023-0413",
    "CVE-2023-0414",
    "CVE-2023-0415",
    "CVE-2023-0416",
    "CVE-2023-0417",
    "CVE-2023-0666",
    "CVE-2023-0667",
    "CVE-2023-0668",
    "CVE-2023-1161",
    "CVE-2023-1992",
    "CVE-2023-1993",
    "CVE-2023-1994",
    "CVE-2023-2854",
    "CVE-2023-2855",
    "CVE-2023-2856",
    "CVE-2023-2857",
    "CVE-2023-2858",
    "CVE-2023-2952",
    "CVE-2023-4511",
    "CVE-2023-4512",
    "CVE-2023-4513",
    "CVE-2023-5371",
    "CVE-2023-6174",
    "CVE-2023-6175",
    "CVE-2024-2955",
    "CVE-2024-24476",
    "CVE-2024-24479"
  );

  script_name(english:"RHEL 6 : wireshark (Unpatched Vulnerability) (deprecated)");

  script_set_attribute(attribute:"synopsis", value: "This plugin has been deprecated as it does not adhere to established standards for this style of check.");
  script_set_attribute(attribute:"description", value:
"This plugin has been deprecated as it does not adhere to established standards for this style of check.");
  script_set_attribute(attribute:"solution", value: "n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-6836");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:wireshark");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}

exit(0, "This plugin has been deprecated as it does not adhere to established standards for this style of check.");
