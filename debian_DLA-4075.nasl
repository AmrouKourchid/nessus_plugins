#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-4075. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(216984);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/10");

  script_cve_id(
    "CVE-2021-47469",
    "CVE-2023-52530",
    "CVE-2023-52917",
    "CVE-2024-26921",
    "CVE-2024-27017",
    "CVE-2024-27072",
    "CVE-2024-35965",
    "CVE-2024-35966",
    "CVE-2024-36476",
    "CVE-2024-36899",
    "CVE-2024-38538",
    "CVE-2024-38544",
    "CVE-2024-38588",
    "CVE-2024-38591",
    "CVE-2024-39497",
    "CVE-2024-40953",
    "CVE-2024-41016",
    "CVE-2024-41060",
    "CVE-2024-41080",
    "CVE-2024-42315",
    "CVE-2024-43098",
    "CVE-2024-44931",
    "CVE-2024-44940",
    "CVE-2024-46695",
    "CVE-2024-46809",
    "CVE-2024-46841",
    "CVE-2024-46849",
    "CVE-2024-46853",
    "CVE-2024-46854",
    "CVE-2024-46858",
    "CVE-2024-46865",
    "CVE-2024-47143",
    "CVE-2024-47670",
    "CVE-2024-47671",
    "CVE-2024-47672",
    "CVE-2024-47674",
    "CVE-2024-47679",
    "CVE-2024-47684",
    "CVE-2024-47685",
    "CVE-2024-47692",
    "CVE-2024-47696",
    "CVE-2024-47697",
    "CVE-2024-47698",
    "CVE-2024-47699",
    "CVE-2024-47701",
    "CVE-2024-47705",
    "CVE-2024-47706",
    "CVE-2024-47707",
    "CVE-2024-47709",
    "CVE-2024-47710",
    "CVE-2024-47712",
    "CVE-2024-47713",
    "CVE-2024-47718",
    "CVE-2024-47723",
    "CVE-2024-47735",
    "CVE-2024-47737",
    "CVE-2024-47739",
    "CVE-2024-47740",
    "CVE-2024-47742",
    "CVE-2024-47748",
    "CVE-2024-47749",
    "CVE-2024-47756",
    "CVE-2024-47757",
    "CVE-2024-48881",
    "CVE-2024-49851",
    "CVE-2024-49858",
    "CVE-2024-49860",
    "CVE-2024-49863",
    "CVE-2024-49867",
    "CVE-2024-49868",
    "CVE-2024-49875",
    "CVE-2024-49877",
    "CVE-2024-49878",
    "CVE-2024-49879",
    "CVE-2024-49881",
    "CVE-2024-49882",
    "CVE-2024-49883",
    "CVE-2024-49884",
    "CVE-2024-49889",
    "CVE-2024-49890",
    "CVE-2024-49892",
    "CVE-2024-49894",
    "CVE-2024-49895",
    "CVE-2024-49896",
    "CVE-2024-49900",
    "CVE-2024-49902",
    "CVE-2024-49903",
    "CVE-2024-49907",
    "CVE-2024-49913",
    "CVE-2024-49930",
    "CVE-2024-49933",
    "CVE-2024-49936",
    "CVE-2024-49938",
    "CVE-2024-49944",
    "CVE-2024-49948",
    "CVE-2024-49949",
    "CVE-2024-49952",
    "CVE-2024-49955",
    "CVE-2024-49957",
    "CVE-2024-49958",
    "CVE-2024-49959",
    "CVE-2024-49962",
    "CVE-2024-49963",
    "CVE-2024-49965",
    "CVE-2024-49966",
    "CVE-2024-49969",
    "CVE-2024-49973",
    "CVE-2024-49974",
    "CVE-2024-49975",
    "CVE-2024-49977",
    "CVE-2024-49981",
    "CVE-2024-49982",
    "CVE-2024-49983",
    "CVE-2024-49985",
    "CVE-2024-49995",
    "CVE-2024-49996",
    "CVE-2024-50001",
    "CVE-2024-50006",
    "CVE-2024-50007",
    "CVE-2024-50008",
    "CVE-2024-50010",
    "CVE-2024-50013",
    "CVE-2024-50015",
    "CVE-2024-50024",
    "CVE-2024-50033",
    "CVE-2024-50035",
    "CVE-2024-50036",
    "CVE-2024-50039",
    "CVE-2024-50040",
    "CVE-2024-50044",
    "CVE-2024-50045",
    "CVE-2024-50046",
    "CVE-2024-50049",
    "CVE-2024-50055",
    "CVE-2024-50058",
    "CVE-2024-50059",
    "CVE-2024-50072",
    "CVE-2024-50074",
    "CVE-2024-50082",
    "CVE-2024-50083",
    "CVE-2024-50095",
    "CVE-2024-50096",
    "CVE-2024-50099",
    "CVE-2024-50103",
    "CVE-2024-50115",
    "CVE-2024-50116",
    "CVE-2024-50117",
    "CVE-2024-50121",
    "CVE-2024-50127",
    "CVE-2024-50131",
    "CVE-2024-50134",
    "CVE-2024-50142",
    "CVE-2024-50148",
    "CVE-2024-50150",
    "CVE-2024-50151",
    "CVE-2024-50153",
    "CVE-2024-50167",
    "CVE-2024-50171",
    "CVE-2024-50179",
    "CVE-2024-50180",
    "CVE-2024-50181",
    "CVE-2024-50184",
    "CVE-2024-50185",
    "CVE-2024-50188",
    "CVE-2024-50192",
    "CVE-2024-50193",
    "CVE-2024-50194",
    "CVE-2024-50195",
    "CVE-2024-50198",
    "CVE-2024-50199",
    "CVE-2024-50201",
    "CVE-2024-50202",
    "CVE-2024-50205",
    "CVE-2024-50208",
    "CVE-2024-50209",
    "CVE-2024-50210",
    "CVE-2024-50218",
    "CVE-2024-50229",
    "CVE-2024-50230",
    "CVE-2024-50233",
    "CVE-2024-50234",
    "CVE-2024-50236",
    "CVE-2024-50237",
    "CVE-2024-50251",
    "CVE-2024-50262",
    "CVE-2024-50264",
    "CVE-2024-50265",
    "CVE-2024-50267",
    "CVE-2024-50268",
    "CVE-2024-50269",
    "CVE-2024-50273",
    "CVE-2024-50278",
    "CVE-2024-50279",
    "CVE-2024-50282",
    "CVE-2024-50287",
    "CVE-2024-50290",
    "CVE-2024-50292",
    "CVE-2024-50295",
    "CVE-2024-50296",
    "CVE-2024-50299",
    "CVE-2024-50301",
    "CVE-2024-50302",
    "CVE-2024-50304",
    "CVE-2024-52332",
    "CVE-2024-53042",
    "CVE-2024-53052",
    "CVE-2024-53057",
    "CVE-2024-53059",
    "CVE-2024-53060",
    "CVE-2024-53061",
    "CVE-2024-53063",
    "CVE-2024-53066",
    "CVE-2024-53096",
    "CVE-2024-53097",
    "CVE-2024-53099",
    "CVE-2024-53101",
    "CVE-2024-53103",
    "CVE-2024-53104",
    "CVE-2024-53112",
    "CVE-2024-53119",
    "CVE-2024-53121",
    "CVE-2024-53124",
    "CVE-2024-53125",
    "CVE-2024-53127",
    "CVE-2024-53130",
    "CVE-2024-53131",
    "CVE-2024-53135",
    "CVE-2024-53136",
    "CVE-2024-53138",
    "CVE-2024-53140",
    "CVE-2024-53141",
    "CVE-2024-53142",
    "CVE-2024-53145",
    "CVE-2024-53146",
    "CVE-2024-53148",
    "CVE-2024-53150",
    "CVE-2024-53155",
    "CVE-2024-53156",
    "CVE-2024-53157",
    "CVE-2024-53158",
    "CVE-2024-53161",
    "CVE-2024-53164",
    "CVE-2024-53171",
    "CVE-2024-53172",
    "CVE-2024-53173",
    "CVE-2024-53174",
    "CVE-2024-53181",
    "CVE-2024-53183",
    "CVE-2024-53184",
    "CVE-2024-53194",
    "CVE-2024-53197",
    "CVE-2024-53198",
    "CVE-2024-53214",
    "CVE-2024-53217",
    "CVE-2024-53226",
    "CVE-2024-53227",
    "CVE-2024-53237",
    "CVE-2024-53239",
    "CVE-2024-53240",
    "CVE-2024-53241",
    "CVE-2024-53680",
    "CVE-2024-53685",
    "CVE-2024-53690",
    "CVE-2024-54031",
    "CVE-2024-55916",
    "CVE-2024-56531",
    "CVE-2024-56532",
    "CVE-2024-56533",
    "CVE-2024-56539",
    "CVE-2024-56548",
    "CVE-2024-56558",
    "CVE-2024-56562",
    "CVE-2024-56567",
    "CVE-2024-56568",
    "CVE-2024-56569",
    "CVE-2024-56570",
    "CVE-2024-56574",
    "CVE-2024-56576",
    "CVE-2024-56581",
    "CVE-2024-56586",
    "CVE-2024-56587",
    "CVE-2024-56589",
    "CVE-2024-56593",
    "CVE-2024-56594",
    "CVE-2024-56595",
    "CVE-2024-56596",
    "CVE-2024-56597",
    "CVE-2024-56598",
    "CVE-2024-56600",
    "CVE-2024-56601",
    "CVE-2024-56602",
    "CVE-2024-56603",
    "CVE-2024-56605",
    "CVE-2024-56606",
    "CVE-2024-56610",
    "CVE-2024-56615",
    "CVE-2024-56616",
    "CVE-2024-56619",
    "CVE-2024-56623",
    "CVE-2024-56629",
    "CVE-2024-56630",
    "CVE-2024-56631",
    "CVE-2024-56633",
    "CVE-2024-56634",
    "CVE-2024-56636",
    "CVE-2024-56637",
    "CVE-2024-56642",
    "CVE-2024-56643",
    "CVE-2024-56644",
    "CVE-2024-56645",
    "CVE-2024-56648",
    "CVE-2024-56650",
    "CVE-2024-56659",
    "CVE-2024-56661",
    "CVE-2024-56662",
    "CVE-2024-56670",
    "CVE-2024-56672",
    "CVE-2024-56681",
    "CVE-2024-56688",
    "CVE-2024-56690",
    "CVE-2024-56691",
    "CVE-2024-56694",
    "CVE-2024-56698",
    "CVE-2024-56700",
    "CVE-2024-56704",
    "CVE-2024-56705",
    "CVE-2024-56716",
    "CVE-2024-56720",
    "CVE-2024-56723",
    "CVE-2024-56724",
    "CVE-2024-56728",
    "CVE-2024-56739",
    "CVE-2024-56741",
    "CVE-2024-56747",
    "CVE-2024-56748",
    "CVE-2024-56754",
    "CVE-2024-56756",
    "CVE-2024-56759",
    "CVE-2024-56763",
    "CVE-2024-56766",
    "CVE-2024-56767",
    "CVE-2024-56769",
    "CVE-2024-56770",
    "CVE-2024-56779",
    "CVE-2024-56780",
    "CVE-2024-57791",
    "CVE-2024-57792",
    "CVE-2024-57802",
    "CVE-2024-57807",
    "CVE-2024-57850",
    "CVE-2024-57874",
    "CVE-2024-57884",
    "CVE-2024-57887",
    "CVE-2024-57889",
    "CVE-2024-57890",
    "CVE-2024-57892",
    "CVE-2024-57896",
    "CVE-2024-57900",
    "CVE-2024-57901",
    "CVE-2024-57902",
    "CVE-2024-57904",
    "CVE-2024-57906",
    "CVE-2024-57907",
    "CVE-2024-57908",
    "CVE-2024-57910",
    "CVE-2024-57911",
    "CVE-2024-57912",
    "CVE-2024-57913",
    "CVE-2024-57922",
    "CVE-2024-57929",
    "CVE-2024-57931",
    "CVE-2024-57938",
    "CVE-2024-57940",
    "CVE-2024-57946",
    "CVE-2024-57948",
    "CVE-2024-57951",
    "CVE-2025-21638",
    "CVE-2025-21639",
    "CVE-2025-21640",
    "CVE-2025-21646",
    "CVE-2025-21648",
    "CVE-2025-21653",
    "CVE-2025-21664",
    "CVE-2025-21666",
    "CVE-2025-21669",
    "CVE-2025-21678",
    "CVE-2025-21683",
    "CVE-2025-21687",
    "CVE-2025-21688",
    "CVE-2025-21689",
    "CVE-2025-21692",
    "CVE-2025-21694",
    "CVE-2025-21697",
    "CVE-2025-21699"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/04/30");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/02/26");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/03/25");

  script_name(english:"Debian dla-4075 : ata-modules-5.10.0-29-armmp-di - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-4075 advisory.

    -------------------------------------------------------------------------
    Debian LTS Advisory DLA-4075-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                        Ben Hutchings
    March 01, 2025                                https://wiki.debian.org/LTS
    -------------------------------------------------------------------------

    Package        : linux
    Version        : 5.10.234-1
    CVE ID         : CVE-2021-47469 CVE-2023-52530 CVE-2023-52917 CVE-2024-26921
                     CVE-2024-27017 CVE-2024-27072 CVE-2024-35965 CVE-2024-35966
                     CVE-2024-36476 CVE-2024-36899 CVE-2024-38538 CVE-2024-38544
                     CVE-2024-38588 CVE-2024-38591 CVE-2024-39497 CVE-2024-40953
                     CVE-2024-41016 CVE-2024-41060 CVE-2024-41080 CVE-2024-42315
                     CVE-2024-43098 CVE-2024-44931 CVE-2024-44940 CVE-2024-46695
                     CVE-2024-46809 CVE-2024-46841 CVE-2024-46849 CVE-2024-46853
                     CVE-2024-46854 CVE-2024-46858 CVE-2024-46865 CVE-2024-47143
                     CVE-2024-47670 CVE-2024-47671 CVE-2024-47672 CVE-2024-47674
                     CVE-2024-47679 CVE-2024-47684 CVE-2024-47685 CVE-2024-47692
                     CVE-2024-47696 CVE-2024-47697 CVE-2024-47698 CVE-2024-47699
                     CVE-2024-47701 CVE-2024-47705 CVE-2024-47706 CVE-2024-47707
                     CVE-2024-47709 CVE-2024-47710 CVE-2024-47712 CVE-2024-47713
                     CVE-2024-47718 CVE-2024-47723 CVE-2024-47735 CVE-2024-47737
                     CVE-2024-47739 CVE-2024-47740 CVE-2024-47742 CVE-2024-47748
                     CVE-2024-47749 CVE-2024-47756 CVE-2024-47757 CVE-2024-48881
                     CVE-2024-49851 CVE-2024-49858 CVE-2024-49860 CVE-2024-49863
                     CVE-2024-49867 CVE-2024-49868 CVE-2024-49875 CVE-2024-49877
                     CVE-2024-49878 CVE-2024-49879 CVE-2024-49881 CVE-2024-49882
                     CVE-2024-49883 CVE-2024-49884 CVE-2024-49889 CVE-2024-49890
                     CVE-2024-49892 CVE-2024-49894 CVE-2024-49895 CVE-2024-49896
                     CVE-2024-49900 CVE-2024-49902 CVE-2024-49903 CVE-2024-49907
                     CVE-2024-49913 CVE-2024-49930 CVE-2024-49933 CVE-2024-49936
                     CVE-2024-49938 CVE-2024-49944 CVE-2024-49948 CVE-2024-49949
                     CVE-2024-49952 CVE-2024-49955 CVE-2024-49957 CVE-2024-49958
                     CVE-2024-49959 CVE-2024-49962 CVE-2024-49963 CVE-2024-49965
                     CVE-2024-49966 CVE-2024-49969 CVE-2024-49973 CVE-2024-49974
                     CVE-2024-49975 CVE-2024-49977 CVE-2024-49981 CVE-2024-49982
                     CVE-2024-49983 CVE-2024-49985 CVE-2024-49995 CVE-2024-49996
                     CVE-2024-50001 CVE-2024-50006 CVE-2024-50007 CVE-2024-50008
                     CVE-2024-50010 CVE-2024-50013 CVE-2024-50015 CVE-2024-50024
                     CVE-2024-50033 CVE-2024-50035 CVE-2024-50036 CVE-2024-50039
                     CVE-2024-50040 CVE-2024-50044 CVE-2024-50045 CVE-2024-50046
                     CVE-2024-50049 CVE-2024-50055 CVE-2024-50058 CVE-2024-50059
                     CVE-2024-50072 CVE-2024-50074 CVE-2024-50082 CVE-2024-50083
                     CVE-2024-50095 CVE-2024-50096 CVE-2024-50099 CVE-2024-50103
                     CVE-2024-50115 CVE-2024-50116 CVE-2024-50117 CVE-2024-50121
                     CVE-2024-50127 CVE-2024-50131 CVE-2024-50134 CVE-2024-50142
                     CVE-2024-50148 CVE-2024-50150 CVE-2024-50151 CVE-2024-50153
                     CVE-2024-50167 CVE-2024-50171 CVE-2024-50179 CVE-2024-50180
                     CVE-2024-50181 CVE-2024-50184 CVE-2024-50185 CVE-2024-50188
                     CVE-2024-50192 CVE-2024-50193 CVE-2024-50194 CVE-2024-50195
                     CVE-2024-50198 CVE-2024-50199 CVE-2024-50201 CVE-2024-50202
                     CVE-2024-50205 CVE-2024-50208 CVE-2024-50209 CVE-2024-50210
                     CVE-2024-50218 CVE-2024-50229 CVE-2024-50230 CVE-2024-50233
                     CVE-2024-50234 CVE-2024-50236 CVE-2024-50237 CVE-2024-50251
                     CVE-2024-50262 CVE-2024-50264 CVE-2024-50265 CVE-2024-50267
                     CVE-2024-50268 CVE-2024-50269 CVE-2024-50273 CVE-2024-50278
                     CVE-2024-50279 CVE-2024-50282 CVE-2024-50287 CVE-2024-50290
                     CVE-2024-50292 CVE-2024-50295 CVE-2024-50296 CVE-2024-50299
                     CVE-2024-50301 CVE-2024-50302 CVE-2024-50304 CVE-2024-52332
                     CVE-2024-53042 CVE-2024-53052 CVE-2024-53057 CVE-2024-53059
                     CVE-2024-53060 CVE-2024-53061 CVE-2024-53063 CVE-2024-53066
                     CVE-2024-53096 CVE-2024-53097 CVE-2024-53099 CVE-2024-53101
                     CVE-2024-53103 CVE-2024-53104 CVE-2024-53112 CVE-2024-53119
                     CVE-2024-53121 CVE-2024-53124 CVE-2024-53125 CVE-2024-53127
                     CVE-2024-53130 CVE-2024-53131 CVE-2024-53135 CVE-2024-53136
                     CVE-2024-53138 CVE-2024-53140 CVE-2024-53141 CVE-2024-53142
                     CVE-2024-53145 CVE-2024-53146 CVE-2024-53148 CVE-2024-53150
                     CVE-2024-53155 CVE-2024-53156 CVE-2024-53157 CVE-2024-53158
                     CVE-2024-53161 CVE-2024-53164 CVE-2024-53171 CVE-2024-53172
                     CVE-2024-53173 CVE-2024-53174 CVE-2024-53181 CVE-2024-53183
                     CVE-2024-53184 CVE-2024-53194 CVE-2024-53197 CVE-2024-53198
                     CVE-2024-53214 CVE-2024-53217 CVE-2024-53226 CVE-2024-53227
                     CVE-2024-53237 CVE-2024-53239 CVE-2024-53240 CVE-2024-53241
                     CVE-2024-53680 CVE-2024-53685 CVE-2024-53690 CVE-2024-54031
                     CVE-2024-55916 CVE-2024-56531 CVE-2024-56532 CVE-2024-56533
                     CVE-2024-56539 CVE-2024-56548 CVE-2024-56558 CVE-2024-56562
                     CVE-2024-56567 CVE-2024-56568 CVE-2024-56569 CVE-2024-56570
                     CVE-2024-56574 CVE-2024-56576 CVE-2024-56581 CVE-2024-56586
                     CVE-2024-56587 CVE-2024-56589 CVE-2024-56593 CVE-2024-56594
                     CVE-2024-56595 CVE-2024-56596 CVE-2024-56597 CVE-2024-56598
                     CVE-2024-56600 CVE-2024-56601 CVE-2024-56602 CVE-2024-56603
                     CVE-2024-56605 CVE-2024-56606 CVE-2024-56610 CVE-2024-56615
                     CVE-2024-56616 CVE-2024-56619 CVE-2024-56623 CVE-2024-56629
                     CVE-2024-56630 CVE-2024-56631 CVE-2024-56633 CVE-2024-56634
                     CVE-2024-56636 CVE-2024-56637 CVE-2024-56642 CVE-2024-56643
                     CVE-2024-56644 CVE-2024-56645 CVE-2024-56648 CVE-2024-56650
                     CVE-2024-56659 CVE-2024-56661 CVE-2024-56662 CVE-2024-56670
                     CVE-2024-56672 CVE-2024-56681 CVE-2024-56688 CVE-2024-56690
                     CVE-2024-56691 CVE-2024-56694 CVE-2024-56698 CVE-2024-56700
                     CVE-2024-56704 CVE-2024-56705 CVE-2024-56716 CVE-2024-56720
                     CVE-2024-56723 CVE-2024-56724 CVE-2024-56728 CVE-2024-56739
                     CVE-2024-56741 CVE-2024-56747 CVE-2024-56748 CVE-2024-56754
                     CVE-2024-56756 CVE-2024-56759 CVE-2024-56763 CVE-2024-56766
                     CVE-2024-56767 CVE-2024-56769 CVE-2024-56770 CVE-2024-56779
                     CVE-2024-56780 CVE-2024-57791 CVE-2024-57792 CVE-2024-57802
                     CVE-2024-57807 CVE-2024-57850 CVE-2024-57874 CVE-2024-57884
                     CVE-2024-57887 CVE-2024-57889 CVE-2024-57890 CVE-2024-57892
                     CVE-2024-57896 CVE-2024-57900 CVE-2024-57901 CVE-2024-57902
                     CVE-2024-57904 CVE-2024-57906 CVE-2024-57907 CVE-2024-57908
                     CVE-2024-57910 CVE-2024-57911 CVE-2024-57912 CVE-2024-57913
                     CVE-2024-57922 CVE-2024-57929 CVE-2024-57931 CVE-2024-57938
                     CVE-2024-57940 CVE-2024-57946 CVE-2024-57948 CVE-2024-57951
                     CVE-2025-21638 CVE-2025-21639 CVE-2025-21640 CVE-2025-21646
                     CVE-2025-21648 CVE-2025-21653 CVE-2025-21664 CVE-2025-21666
                     CVE-2025-21669 CVE-2025-21678 CVE-2025-21683 CVE-2025-21687
                     CVE-2025-21688 CVE-2025-21689 CVE-2025-21692 CVE-2025-21694
                     CVE-2025-21697 CVE-2025-21699
    Debian Bug     : 1082001

    Several vulnerabilities have been discovered in the Linux kernel that
    may lead to a privilege escalation, denial of service or information
    leaks.

    For Debian 11 bullseye, these problems have been fixed in version
    5.10.234-1.  This additionally includes many more bug fixes from
    stable updates 5.10.227-5.10.234 inclusive.

    We recommend that you upgrade your linux packages.

    For the detailed security status of linux please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/linux

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS
    Attachment:
    signature.asc
    Description: PGP signature

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/linux");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-47469");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-52530");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-52917");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26921");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-27017");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-27072");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-35965");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-35966");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-36476");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-36899");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-38538");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-38544");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-38588");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-38591");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-39497");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-40953");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-41016");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-41060");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-41080");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-42315");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-43098");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-44931");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-44940");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-46695");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-46809");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-46841");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-46849");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-46853");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-46854");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-46858");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-46865");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-47143");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-47670");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-47671");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-47672");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-47674");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-47679");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-47684");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-47685");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-47692");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-47696");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-47697");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-47698");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-47699");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-47701");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-47705");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-47706");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-47707");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-47709");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-47710");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-47712");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-47713");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-47718");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-47723");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-47735");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-47737");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-47739");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-47740");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-47742");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-47748");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-47749");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-47756");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-47757");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-48881");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-49851");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-49858");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-49860");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-49863");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-49867");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-49868");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-49875");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-49877");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-49878");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-49879");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-49881");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-49882");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-49883");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-49884");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-49889");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-49890");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-49892");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-49894");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-49895");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-49896");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-49900");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-49902");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-49903");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-49907");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-49913");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-49930");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-49933");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-49936");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-49938");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-49944");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-49948");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-49949");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-49952");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-49955");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-49957");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-49958");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-49959");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-49962");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-49963");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-49965");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-49966");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-49969");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-49973");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-49974");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-49975");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-49977");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-49981");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-49982");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-49983");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-49985");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-49995");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-49996");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50001");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50006");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50007");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50008");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50010");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50013");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50015");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50024");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50033");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50035");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50036");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50039");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50040");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50044");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50045");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50046");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50049");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50055");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50058");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50059");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50072");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50074");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50082");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50083");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50095");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50096");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50099");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50103");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50115");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50116");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50117");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50121");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50127");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50131");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50134");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50142");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50148");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50150");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50151");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50153");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50167");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50171");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50179");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50180");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50181");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50184");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50185");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50188");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50192");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50193");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50194");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50195");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50198");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50199");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50201");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50202");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50205");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50208");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50209");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50210");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50218");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50229");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50230");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50233");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50234");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50236");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50237");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50251");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50262");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50264");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50265");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50267");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50268");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50269");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50273");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50278");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50279");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50282");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50287");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50290");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50292");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50295");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50296");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50299");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50301");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50302");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50304");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-52332");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53042");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53052");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53057");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53059");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53060");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53061");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53063");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53066");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53096");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53097");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53099");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53101");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53103");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53104");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53112");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53119");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53121");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53124");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53125");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53127");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53130");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53131");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53135");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53136");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53138");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53140");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53141");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53142");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53145");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53146");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53148");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53150");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53155");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53156");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53157");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53158");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53161");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53164");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53171");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53172");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53173");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53174");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53181");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53183");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53184");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53194");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53197");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53198");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53214");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53217");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53226");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53227");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53237");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53239");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53240");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53241");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53680");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53685");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53690");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-54031");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-55916");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56531");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56532");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56533");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56539");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56548");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56558");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56562");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56567");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56568");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56569");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56570");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56574");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56576");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56581");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56586");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56587");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56589");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56593");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56594");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56595");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56596");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56597");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56598");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56600");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56601");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56602");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56603");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56605");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56606");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56610");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56615");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56616");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56619");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56623");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56629");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56630");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56631");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56633");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56634");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56636");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56637");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56642");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56643");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56644");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56645");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56648");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56650");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56659");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56661");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56662");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56670");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56672");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56681");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56688");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56690");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56691");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56694");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56698");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56700");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56704");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56705");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56716");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56720");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56723");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56724");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56728");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56739");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56741");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56747");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56748");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56754");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56756");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56759");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56763");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56766");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56767");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56769");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56770");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56779");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56780");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57791");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57792");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57802");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57807");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57850");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57874");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57884");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57887");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57889");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57890");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57892");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57896");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57900");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57901");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57902");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57904");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57906");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57907");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57908");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57910");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57911");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57912");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57913");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57922");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57929");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57931");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57938");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57940");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57946");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57948");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57951");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21638");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21639");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21640");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21646");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21648");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21653");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21664");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21666");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21669");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21678");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21683");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21687");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21688");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21689");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21692");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21694");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21697");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21699");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/linux");
  script_set_attribute(attribute:"solution", value:
"Upgrade the ata-modules-5.10.0-29-armmp-di packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-47685");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-33-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-34-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-33-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-34-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-33-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-34-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-33-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-34-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-33-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-34-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-33-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-34-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:efi-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:efi-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:efi-modules-5.10.0-33-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:efi-modules-5.10.0-34-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-33-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-34-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-33-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-34-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-33-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-34-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-33-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-34-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-33-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-34-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-33-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-34-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:hyperv-daemons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-33-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-34-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-33-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-34-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-33-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-34-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-33-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-34-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-33-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-34-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:leds-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:leds-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:leds-modules-5.10.0-33-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:leds-modules-5.10.0-34-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcpupower-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcpupower1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-compiler-gcc-10-arm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-compiler-gcc-10-x86");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-config-5.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-cpupower");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-doc-5.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-29-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-29-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-29-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-29-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-29-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-29-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-29-cloud-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-29-cloud-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-29-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-29-common-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-29-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-29-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-29-rt-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-29-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-29-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-29-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-29-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-29-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-29-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-29-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-29-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-29-armmp-lpae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-29-cloud-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-29-cloud-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-29-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-29-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-29-rt-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-29-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-29-rt-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-amd64-signed-template");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-arm64-signed-template");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-armmp-lpae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-cloud-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-cloud-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-i386-signed-template");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-rt-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-rt-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-kbuild-5.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-libc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-perf-5.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-source-5.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-support-5.10.0-29");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-33-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-34-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-33-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-34-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-33-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-34-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-modules-5.10.0-33-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-modules-5.10.0-34-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-33-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-34-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-33-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-34-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-33-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-34-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-33-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-34-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-33-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-34-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-33-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-34-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-33-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-34-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-33-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-34-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-33-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-34-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-33-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-34-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-33-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-34-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-33-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-34-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-33-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-34-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-33-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-34-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uinput-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uinput-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uinput-modules-5.10.0-33-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uinput-modules-5.10.0-34-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-33-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-34-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-33-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-34-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-33-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-34-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usbip");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var debian_release = get_kb_item('Host/Debian/release');
if ( isnull(debian_release) ) audit(AUDIT_OS_NOT, 'Debian');
debian_release = chomp(debian_release);
if (! preg(pattern:"^(11)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 11.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-29-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-31-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-33-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-34-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'bpftool', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-29-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-31-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-33-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-34-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-29-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-31-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-33-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-34-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-29-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-31-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-33-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-34-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-29-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-31-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-33-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-34-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-29-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-31-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-33-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-34-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'efi-modules-5.10.0-29-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'efi-modules-5.10.0-31-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'efi-modules-5.10.0-33-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'efi-modules-5.10.0-34-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-29-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-31-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-33-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-34-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-29-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-31-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-33-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-34-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-29-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-31-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-33-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-34-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-29-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-31-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-33-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-34-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-29-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-31-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-33-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-34-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-29-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-31-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-33-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-34-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'hyperv-daemons', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-29-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-31-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-33-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-34-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-29-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-31-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-33-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-34-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-29-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-31-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-33-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-34-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-29-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-31-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-33-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-34-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-29-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-31-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-33-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-34-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'leds-modules-5.10.0-29-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'leds-modules-5.10.0-31-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'leds-modules-5.10.0-33-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'leds-modules-5.10.0-34-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'libcpupower-dev', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'libcpupower1', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'linux-compiler-gcc-10-arm', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'linux-compiler-gcc-10-x86', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'linux-config-5.10', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'linux-cpupower', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'linux-doc', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'linux-doc-5.10', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-29-686', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-29-686-pae', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-29-amd64', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-29-arm64', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-29-armmp', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-29-armmp-lpae', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-29-cloud-amd64', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-29-cloud-arm64', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-29-common', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-29-common-rt', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-29-rt-686-pae', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-29-rt-amd64', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-29-rt-arm64', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-29-rt-armmp', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'linux-headers-armmp', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'linux-headers-armmp-lpae', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'linux-headers-rt-armmp', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-29-686-dbg', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-29-686-pae-dbg', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-29-amd64-dbg', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-29-arm64-dbg', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-29-armmp', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-29-armmp-dbg', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-29-armmp-lpae', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-29-armmp-lpae-dbg', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-29-cloud-amd64-dbg', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-29-cloud-arm64-dbg', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-29-rt-686-pae-dbg', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-29-rt-amd64-dbg', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-29-rt-arm64-dbg', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-29-rt-armmp', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-29-rt-armmp-dbg', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'linux-image-686-dbg', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'linux-image-686-pae-dbg', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'linux-image-amd64-dbg', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'linux-image-amd64-signed-template', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'linux-image-arm64-dbg', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'linux-image-arm64-signed-template', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'linux-image-armmp', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'linux-image-armmp-dbg', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'linux-image-armmp-lpae', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'linux-image-armmp-lpae-dbg', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'linux-image-cloud-amd64-dbg', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'linux-image-cloud-arm64-dbg', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'linux-image-i386-signed-template', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'linux-image-rt-686-pae-dbg', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'linux-image-rt-amd64-dbg', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'linux-image-rt-arm64-dbg', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'linux-image-rt-armmp', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'linux-image-rt-armmp-dbg', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'linux-kbuild-5.10', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'linux-libc-dev', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'linux-perf', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'linux-perf-5.10', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'linux-source', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'linux-source-5.10', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'linux-support-5.10.0-29', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-29-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-31-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-33-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-34-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-29-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-31-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-33-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-34-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-29-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-31-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-33-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-34-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'mtd-modules-5.10.0-29-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'mtd-modules-5.10.0-31-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'mtd-modules-5.10.0-33-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'mtd-modules-5.10.0-34-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-29-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-31-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-33-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-34-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-29-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-31-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-33-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-34-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-29-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-31-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-33-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-34-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-29-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-31-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-33-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-34-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-29-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-31-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-33-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-34-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-29-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-31-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-33-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-34-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-29-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-31-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-33-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-34-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-29-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-31-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-33-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-34-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-29-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-31-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-33-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-34-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-29-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-31-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-33-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-34-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-29-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-31-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-33-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-34-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-29-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-31-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-33-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-34-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-29-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-31-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-33-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-34-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-29-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-31-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-33-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-34-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'uinput-modules-5.10.0-29-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'uinput-modules-5.10.0-31-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'uinput-modules-5.10.0-33-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'uinput-modules-5.10.0-34-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-29-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-31-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-33-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-34-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-29-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-31-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-33-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-34-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-29-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-31-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-33-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-34-armmp-di', 'reference': '5.10.234-1'},
    {'release': '11.0', 'prefix': 'usbip', 'reference': '5.10.234-1'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var _release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (_release && prefix && reference) {
    if (deb_check(release:_release, prefix:prefix, reference:reference)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ata-modules-5.10.0-29-armmp-di / ata-modules-5.10.0-31-armmp-di / etc');
}
