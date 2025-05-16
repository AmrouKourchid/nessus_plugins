#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Rocky Linux Security Advisory RLSA-2024:7001.
##

include('compat.inc');

if (description)
{
  script_id(207938);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/30");

  script_cve_id(
    "CVE-2021-46984",
    "CVE-2021-47097",
    "CVE-2021-47101",
    "CVE-2021-47287",
    "CVE-2021-47289",
    "CVE-2021-47321",
    "CVE-2021-47338",
    "CVE-2021-47352",
    "CVE-2021-47383",
    "CVE-2021-47384",
    "CVE-2021-47385",
    "CVE-2021-47386",
    "CVE-2021-47393",
    "CVE-2021-47412",
    "CVE-2021-47432",
    "CVE-2021-47441",
    "CVE-2021-47455",
    "CVE-2021-47466",
    "CVE-2021-47497",
    "CVE-2021-47527",
    "CVE-2021-47560",
    "CVE-2021-47582",
    "CVE-2021-47609",
    "CVE-2022-48619",
    "CVE-2022-48754",
    "CVE-2022-48760",
    "CVE-2022-48804",
    "CVE-2022-48836",
    "CVE-2022-48866",
    "CVE-2023-6040",
    "CVE-2023-52470",
    "CVE-2023-52476",
    "CVE-2023-52478",
    "CVE-2023-52522",
    "CVE-2023-52605",
    "CVE-2023-52683",
    "CVE-2023-52817",
    "CVE-2023-52840",
    "CVE-2024-23848",
    "CVE-2024-26595",
    "CVE-2024-26645",
    "CVE-2024-26649",
    "CVE-2024-26665",
    "CVE-2024-26717",
    "CVE-2024-26720",
    "CVE-2024-26769",
    "CVE-2024-26855",
    "CVE-2024-26880",
    "CVE-2024-26894",
    "CVE-2024-26923",
    "CVE-2024-26939",
    "CVE-2024-27013",
    "CVE-2024-27042",
    "CVE-2024-35809",
    "CVE-2024-35877",
    "CVE-2024-35884",
    "CVE-2024-35944",
    "CVE-2024-35989",
    "CVE-2024-36883",
    "CVE-2024-36901",
    "CVE-2024-36902",
    "CVE-2024-36920",
    "CVE-2024-36939",
    "CVE-2024-36953",
    "CVE-2024-37356",
    "CVE-2024-38558",
    "CVE-2024-38559",
    "CVE-2024-38570",
    "CVE-2024-38581",
    "CVE-2024-38619",
    "CVE-2024-39471",
    "CVE-2024-39499",
    "CVE-2024-39501",
    "CVE-2024-39506",
    "CVE-2024-40901",
    "CVE-2024-40904",
    "CVE-2024-40911",
    "CVE-2024-40912",
    "CVE-2024-40929",
    "CVE-2024-40931",
    "CVE-2024-40941",
    "CVE-2024-40954",
    "CVE-2024-40958",
    "CVE-2024-40959",
    "CVE-2024-40960",
    "CVE-2024-40972",
    "CVE-2024-40977",
    "CVE-2024-40978",
    "CVE-2024-40988",
    "CVE-2024-40989",
    "CVE-2024-40995",
    "CVE-2024-40997",
    "CVE-2024-40998",
    "CVE-2024-41005",
    "CVE-2024-41007",
    "CVE-2024-41008",
    "CVE-2024-41012",
    "CVE-2024-41013",
    "CVE-2024-41014",
    "CVE-2024-41035",
    "CVE-2024-41038",
    "CVE-2024-41039",
    "CVE-2024-41040",
    "CVE-2024-41041",
    "CVE-2024-41044",
    "CVE-2024-41055",
    "CVE-2024-41056",
    "CVE-2024-41060",
    "CVE-2024-41071",
    "CVE-2024-41076",
    "CVE-2024-41090",
    "CVE-2024-41091",
    "CVE-2024-41097",
    "CVE-2024-42084",
    "CVE-2024-42090",
    "CVE-2024-42096",
    "CVE-2024-42114",
    "CVE-2024-42124",
    "CVE-2024-42131",
    "CVE-2024-42152",
    "CVE-2024-42154",
    "CVE-2024-42226",
    "CVE-2024-42228",
    "CVE-2024-42237",
    "CVE-2024-42238",
    "CVE-2024-42240",
    "CVE-2024-42246",
    "CVE-2024-42322",
    "CVE-2024-43871"
  );
  script_xref(name:"IAVA", value:"2024-A-0487");
  script_xref(name:"RLSA", value:"2024:7001");

  script_name(english:"Rocky Linux 8 : kernel-rt (RLSA-2024:7001)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Rocky Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Rocky Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
RLSA-2024:7001 advisory.

    CVE-2023-6040  CVE-2024-26595  CVE-2021-46984  CVE-2023-52478  CVE-2023-52476  CVE-2023-52522
    CVE-2021-47101  CVE-2021-47097  CVE-2023-52605  CVE-2024-26645  CVE-2024-26665  CVE-2024-26720
    CVE-2024-26717  CVE-2024-26769  CVE-2024-26894  CVE-2024-26880  CVE-2024-26855  CVE-2024-26923
    CVE-2024-26939  CVE-2024-27013  CVE-2024-27042  CVE-2024-35809  CVE-2023-52683  CVE-2024-35884
    CVE-2024-35877  CVE-2024-35944  CVE-2024-35989  CVE-2021-47412  CVE-2021-47393  CVE-2021-47386
    CVE-2021-47385  CVE-2021-47384  CVE-2021-47383  CVE-2021-47432  CVE-2021-47352  CVE-2021-47338
    CVE-2021-47321  CVE-2021-47289  CVE-2021-47287  CVE-2023-52817  CVE-2023-52840  CVE-2021-47441
    CVE-2021-47466  CVE-2021-47455  CVE-2021-47497  CVE-2021-47560  CVE-2021-47527  CVE-2024-36883
    CVE-2024-36920  CVE-2024-36902  CVE-2024-36953  CVE-2024-36939  CVE-2024-36901  CVE-2021-47582
    CVE-2021-47609  CVE-2024-38619  CVE-2022-48754  CVE-2022-48760  CVE-2024-38581  CVE-2024-38570
    CVE-2024-38559  CVE-2024-38558  CVE-2024-37356  CVE-2024-39471  CVE-2024-39499  CVE-2024-39501
    CVE-2024-39506  CVE-2024-40904  CVE-2024-40911  CVE-2024-40912  CVE-2024-40929  CVE-2024-40931
    CVE-2024-40941  CVE-2024-40954  CVE-2024-40958  CVE-2024-40959  CVE-2024-40960  CVE-2024-40972
    CVE-2024-40977  CVE-2024-40978  CVE-2024-40988  CVE-2024-40989  CVE-2024-40995  CVE-2024-40997
    CVE-2024-40998  CVE-2024-41005  CVE-2024-40901  CVE-2024-41007  CVE-2024-41008  CVE-2022-48804
    CVE-2022-48836  CVE-2022-48866  CVE-2024-41090  CVE-2024-41091  CVE-2024-41012  CVE-2024-41013
    CVE-2024-41014  CVE-2024-41035  CVE-2024-41038  CVE-2024-41039  CVE-2024-41040  CVE-2024-41041
    CVE-2024-41044  CVE-2024-41055  CVE-2024-41056  CVE-2024-41060  CVE-2024-41071  CVE-2024-41076
    CVE-2024-41097  CVE-2024-42084  CVE-2024-42090  CVE-2024-42096  CVE-2024-42114  CVE-2024-42124
    CVE-2024-42131  CVE-2024-42152  CVE-2024-42154  CVE-2024-42226  CVE-2024-42228  CVE-2024-42237
    CVE-2024-42238  CVE-2024-42240  CVE-2024-42246  CVE-2024-42322  CVE-2024-43871

Tenable has extracted the preceding description block directly from the Rocky Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.rockylinux.org/RLSA-2024:7001");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2258012");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2258013");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2260038");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2265799");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2266358");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2266750");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2267036");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2267041");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2267795");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2267916");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2267925");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2268295");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2271648");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2271796");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2272793");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2273141");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2273148");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2273180");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2275661");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2275690");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2275742");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2277171");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2278220");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2278270");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2278447");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2281217");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2281317");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2281704");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2281720");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2281807");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2281847");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2282324");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2282345");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2282354");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2282355");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2282356");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2282357");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2282366");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2282401");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2282422");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2282440");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2282508");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2282511");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2282676");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2282757");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2282851");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2282890");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2282903");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2282918");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2283389");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2283424");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2284271");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2284515");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2284545");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2284596");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2284628");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2284634");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2293247");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2293270");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2293273");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2293304");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2293377");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2293408");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2293423");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2293440");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2293441");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2293658");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2294313");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2297471");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2297473");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2297478");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2297488");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2297495");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2297496");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2297513");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2297515");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2297525");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2297538");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2297542");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2297543");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2297544");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2297556");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2297561");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2297562");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2297572");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2297573");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2297579");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2297581");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2297582");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2297589");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2297706");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2297909");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2298079");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2298140");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2298177");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2298640");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2299240");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2299336");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2299452");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2300296");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2300297");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2300402");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2300407");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2300408");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2300409");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2300410");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2300414");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2300429");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2300430");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2300434");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2300448");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2300453");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2300492");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2300533");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2300552");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2300713");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2301477");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2301489");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2301496");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2301519");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2301522");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2301544");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2303077");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-42154");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:kernel-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:kernel-rt-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:kernel-rt-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:kernel-rt-debug-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:kernel-rt-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:kernel-rt-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:kernel-rt-debug-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:kernel-rt-debug-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:kernel-rt-debug-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:kernel-rt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:kernel-rt-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:kernel-rt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:kernel-rt-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:kernel-rt-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:kernel-rt-modules-extra");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rocky:linux:8");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Rocky Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RockyLinux/release", "Host/RockyLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('ksplice.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RockyLinux/release');
if (isnull(os_release) || 'Rocky Linux' >!< os_release) audit(AUDIT_OS_NOT, 'Rocky Linux');
var os_ver = pregmatch(pattern: "Rocky(?: Linux)? release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Rocky Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Rocky Linux 8.x', 'Rocky Linux ' + os_ver);

if (!get_kb_item('Host/RockyLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Rocky Linux', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  var cve_list = make_list('CVE-2021-46984', 'CVE-2021-47097', 'CVE-2021-47101', 'CVE-2021-47287', 'CVE-2021-47289', 'CVE-2021-47321', 'CVE-2021-47338', 'CVE-2021-47352', 'CVE-2021-47383', 'CVE-2021-47384', 'CVE-2021-47385', 'CVE-2021-47386', 'CVE-2021-47393', 'CVE-2021-47412', 'CVE-2021-47432', 'CVE-2021-47441', 'CVE-2021-47455', 'CVE-2021-47466', 'CVE-2021-47497', 'CVE-2021-47527', 'CVE-2021-47560', 'CVE-2021-47582', 'CVE-2021-47609', 'CVE-2022-48619', 'CVE-2022-48754', 'CVE-2022-48760', 'CVE-2022-48804', 'CVE-2022-48836', 'CVE-2022-48866', 'CVE-2023-6040', 'CVE-2023-52470', 'CVE-2023-52476', 'CVE-2023-52478', 'CVE-2023-52522', 'CVE-2023-52605', 'CVE-2023-52683', 'CVE-2023-52817', 'CVE-2023-52840', 'CVE-2024-23848', 'CVE-2024-26595', 'CVE-2024-26645', 'CVE-2024-26649', 'CVE-2024-26665', 'CVE-2024-26717', 'CVE-2024-26720', 'CVE-2024-26769', 'CVE-2024-26855', 'CVE-2024-26880', 'CVE-2024-26894', 'CVE-2024-26923', 'CVE-2024-26939', 'CVE-2024-27013', 'CVE-2024-27042', 'CVE-2024-35809', 'CVE-2024-35877', 'CVE-2024-35884', 'CVE-2024-35944', 'CVE-2024-35989', 'CVE-2024-36883', 'CVE-2024-36901', 'CVE-2024-36902', 'CVE-2024-36920', 'CVE-2024-36939', 'CVE-2024-36953', 'CVE-2024-37356', 'CVE-2024-38558', 'CVE-2024-38559', 'CVE-2024-38570', 'CVE-2024-38581', 'CVE-2024-38619', 'CVE-2024-39471', 'CVE-2024-39499', 'CVE-2024-39501', 'CVE-2024-39506', 'CVE-2024-40901', 'CVE-2024-40904', 'CVE-2024-40911', 'CVE-2024-40912', 'CVE-2024-40929', 'CVE-2024-40931', 'CVE-2024-40941', 'CVE-2024-40954', 'CVE-2024-40958', 'CVE-2024-40959', 'CVE-2024-40960', 'CVE-2024-40972', 'CVE-2024-40977', 'CVE-2024-40978', 'CVE-2024-40988', 'CVE-2024-40989', 'CVE-2024-40995', 'CVE-2024-40997', 'CVE-2024-40998', 'CVE-2024-41005', 'CVE-2024-41007', 'CVE-2024-41008', 'CVE-2024-41012', 'CVE-2024-41013', 'CVE-2024-41014', 'CVE-2024-41035', 'CVE-2024-41038', 'CVE-2024-41039', 'CVE-2024-41040', 'CVE-2024-41041', 'CVE-2024-41044', 'CVE-2024-41055', 'CVE-2024-41056', 'CVE-2024-41060', 'CVE-2024-41071', 'CVE-2024-41076', 'CVE-2024-41090', 'CVE-2024-41091', 'CVE-2024-41097', 'CVE-2024-42084', 'CVE-2024-42090', 'CVE-2024-42096', 'CVE-2024-42114', 'CVE-2024-42124', 'CVE-2024-42131', 'CVE-2024-42152', 'CVE-2024-42154', 'CVE-2024-42226', 'CVE-2024-42228', 'CVE-2024-42237', 'CVE-2024-42238', 'CVE-2024-42240', 'CVE-2024-42246', 'CVE-2024-42322', 'CVE-2024-43871');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for RLSA-2024:7001');
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

var pkgs = [
    {'reference':'kernel-rt-4.18.0-553.22.1.rt7.363.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-core-4.18.0-553.22.1.rt7.363.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-debug-4.18.0-553.22.1.rt7.363.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-debug-core-4.18.0-553.22.1.rt7.363.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-debug-debuginfo-4.18.0-553.22.1.rt7.363.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-debug-devel-4.18.0-553.22.1.rt7.363.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-debug-kvm-4.18.0-553.22.1.rt7.363.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-debug-modules-4.18.0-553.22.1.rt7.363.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-debug-modules-extra-4.18.0-553.22.1.rt7.363.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-debuginfo-4.18.0-553.22.1.rt7.363.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-debuginfo-common-x86_64-4.18.0-553.22.1.rt7.363.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-devel-4.18.0-553.22.1.rt7.363.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-kvm-4.18.0-553.22.1.rt7.363.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-modules-4.18.0-553.22.1.rt7.363.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-modules-extra-4.18.0-553.22.1.rt7.363.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = 'Rocky-' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel-rt / kernel-rt-core / kernel-rt-debug / kernel-rt-debug-core / etc');
}
