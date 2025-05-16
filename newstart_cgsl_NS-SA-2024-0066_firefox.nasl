#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2024-0066. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(206859);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/06");

  script_cve_id(
    "CVE-2021-4129",
    "CVE-2021-4140",
    "CVE-2021-32810",
    "CVE-2021-38493",
    "CVE-2021-38496",
    "CVE-2021-38497",
    "CVE-2021-38498",
    "CVE-2021-38500",
    "CVE-2021-38501",
    "CVE-2021-38503",
    "CVE-2021-38504",
    "CVE-2021-38506",
    "CVE-2021-38507",
    "CVE-2021-38508",
    "CVE-2021-38509",
    "CVE-2021-43534",
    "CVE-2021-43535",
    "CVE-2021-43536",
    "CVE-2021-43537",
    "CVE-2021-43538",
    "CVE-2021-43539",
    "CVE-2021-43541",
    "CVE-2021-43542",
    "CVE-2021-43543",
    "CVE-2021-43545",
    "CVE-2021-43546",
    "CVE-2022-1097",
    "CVE-2022-1196",
    "CVE-2022-1529",
    "CVE-2022-1802",
    "CVE-2022-2200",
    "CVE-2022-2505",
    "CVE-2022-22737",
    "CVE-2022-22738",
    "CVE-2022-22739",
    "CVE-2022-22740",
    "CVE-2022-22741",
    "CVE-2022-22742",
    "CVE-2022-22743",
    "CVE-2022-22745",
    "CVE-2022-22747",
    "CVE-2022-22748",
    "CVE-2022-22751",
    "CVE-2022-22754",
    "CVE-2022-22756",
    "CVE-2022-22759",
    "CVE-2022-22760",
    "CVE-2022-22761",
    "CVE-2022-22763",
    "CVE-2022-22764",
    "CVE-2022-24713",
    "CVE-2022-25235",
    "CVE-2022-25236",
    "CVE-2022-25315",
    "CVE-2022-26381",
    "CVE-2022-26383",
    "CVE-2022-26384",
    "CVE-2022-26386",
    "CVE-2022-26387",
    "CVE-2022-26485",
    "CVE-2022-26486",
    "CVE-2022-28281",
    "CVE-2022-28282",
    "CVE-2022-28285",
    "CVE-2022-28286",
    "CVE-2022-28289",
    "CVE-2022-29909",
    "CVE-2022-29911",
    "CVE-2022-29912",
    "CVE-2022-29914",
    "CVE-2022-29916",
    "CVE-2022-29917",
    "CVE-2022-31736",
    "CVE-2022-31737",
    "CVE-2022-31738",
    "CVE-2022-31740",
    "CVE-2022-31741",
    "CVE-2022-31742",
    "CVE-2022-31744",
    "CVE-2022-31747",
    "CVE-2022-34468",
    "CVE-2022-34470",
    "CVE-2022-34472",
    "CVE-2022-34479",
    "CVE-2022-34481",
    "CVE-2022-34484",
    "CVE-2022-36318",
    "CVE-2022-36319",
    "CVE-2022-38472",
    "CVE-2022-38473",
    "CVE-2022-38476",
    "CVE-2022-38477",
    "CVE-2022-38478",
    "CVE-2022-40674",
    "CVE-2022-40956",
    "CVE-2022-40957",
    "CVE-2022-40958",
    "CVE-2022-40959",
    "CVE-2022-40960",
    "CVE-2022-40962",
    "CVE-2022-42927",
    "CVE-2022-42928",
    "CVE-2022-42929",
    "CVE-2022-42932",
    "CVE-2022-43680",
    "CVE-2022-45403",
    "CVE-2022-45404",
    "CVE-2022-45405",
    "CVE-2022-45406",
    "CVE-2022-45408",
    "CVE-2022-45409",
    "CVE-2022-45410",
    "CVE-2022-45411",
    "CVE-2022-45412",
    "CVE-2022-45416",
    "CVE-2022-45418",
    "CVE-2022-45420",
    "CVE-2022-45421",
    "CVE-2022-46871",
    "CVE-2022-46872",
    "CVE-2022-46874",
    "CVE-2022-46877",
    "CVE-2022-46878",
    "CVE-2022-46880",
    "CVE-2022-46881",
    "CVE-2022-46882",
    "CVE-2023-1945",
    "CVE-2023-1999",
    "CVE-2023-4045",
    "CVE-2023-4046",
    "CVE-2023-4047",
    "CVE-2023-4048",
    "CVE-2023-4049",
    "CVE-2023-4050",
    "CVE-2023-4051",
    "CVE-2023-4053",
    "CVE-2023-4055",
    "CVE-2023-4056",
    "CVE-2023-4057",
    "CVE-2023-4573",
    "CVE-2023-4574",
    "CVE-2023-4575",
    "CVE-2023-4577",
    "CVE-2023-4578",
    "CVE-2023-4580",
    "CVE-2023-4581",
    "CVE-2023-4583",
    "CVE-2023-4584",
    "CVE-2023-4585",
    "CVE-2023-4863",
    "CVE-2023-5129",
    "CVE-2023-23598",
    "CVE-2023-23599",
    "CVE-2023-23601",
    "CVE-2023-23602",
    "CVE-2023-23603",
    "CVE-2023-23605",
    "CVE-2023-25728",
    "CVE-2023-25729",
    "CVE-2023-25730",
    "CVE-2023-25732",
    "CVE-2023-25735",
    "CVE-2023-25737",
    "CVE-2023-25739",
    "CVE-2023-25742",
    "CVE-2023-25743",
    "CVE-2023-25744",
    "CVE-2023-25746",
    "CVE-2023-25751",
    "CVE-2023-25752",
    "CVE-2023-28162",
    "CVE-2023-28164",
    "CVE-2023-28176",
    "CVE-2023-29533",
    "CVE-2023-29535",
    "CVE-2023-29536",
    "CVE-2023-29539",
    "CVE-2023-29541",
    "CVE-2023-29548",
    "CVE-2023-29550",
    "CVE-2023-32205",
    "CVE-2023-32206",
    "CVE-2023-32207",
    "CVE-2023-32211",
    "CVE-2023-32212",
    "CVE-2023-32213",
    "CVE-2023-32215",
    "CVE-2023-34414",
    "CVE-2023-34416",
    "CVE-2023-37201",
    "CVE-2023-37202",
    "CVE-2023-37207",
    "CVE-2023-37208",
    "CVE-2023-37211"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/21");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/10/04");
  script_xref(name:"IAVA", value:"2021-A-0450-S");
  script_xref(name:"IAVA", value:"2021-A-0461-S");
  script_xref(name:"IAVA", value:"2021-A-0527-S");
  script_xref(name:"IAVA", value:"2021-A-0569-S");
  script_xref(name:"IAVA", value:"2022-A-0017-S");
  script_xref(name:"IAVA", value:"2022-A-0079-S");
  script_xref(name:"IAVA", value:"2022-A-0103-S");
  script_xref(name:"IAVA", value:"2022-A-0134-S");
  script_xref(name:"IAVA", value:"2022-A-0226-S");
  script_xref(name:"IAVA", value:"2022-A-0256-S");
  script_xref(name:"IAVA", value:"2022-A-0298-S");
  script_xref(name:"IAVA", value:"2022-A-0339-S");
  script_xref(name:"IAVA", value:"2022-A-0384-S");
  script_xref(name:"IAVA", value:"2022-A-0435-S");
  script_xref(name:"IAVA", value:"2022-A-0491-S");
  script_xref(name:"IAVA", value:"2022-A-0517-S");
  script_xref(name:"IAVA", value:"2023-A-0048-S");
  script_xref(name:"IAVA", value:"2023-A-0081-S");
  script_xref(name:"IAVA", value:"2023-A-0132-S");
  script_xref(name:"IAVA", value:"2023-A-0182-S");
  script_xref(name:"IAVA", value:"2023-A-0242-S");
  script_xref(name:"IAVA", value:"2023-A-0277-S");
  script_xref(name:"IAVA", value:"2023-A-0328-S");
  script_xref(name:"IAVA", value:"2023-A-0388-S");
  script_xref(name:"IAVA", value:"2023-A-0449-S");
  script_xref(name:"IAVA", value:"2023-A-0491-S");
  script_xref(name:"IAVA", value:"2022-A-0188-S");
  script_xref(name:"IAVA", value:"2022-A-0190-S");
  script_xref(name:"IAVA", value:"2022-A-0217-S");
  script_xref(name:"IAVA", value:"2021-A-0405-S");

  script_name(english:"NewStart CGSL MAIN 6.02 : firefox Multiple Vulnerabilities (NS-SA-2024-0066)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 6.02, has firefox packages installed that are affected by multiple
vulnerabilities:

  - crossbeam-deque is a package of work-stealing deques for building task schedulers when programming in
    Rust. In versions prior to 0.7.4 and 0.8.0, the result of the race condition is that one or more tasks in
    the worker queue can be popped twice instead of other tasks that are forgotten and never popped. If tasks
    are allocated on the heap, this can cause double free and a memory leak. If not, this still can cause a
    logical bug. Crates using `Stealer::steal`, `Stealer::steal_batch`, or `Stealer::steal_batch_and_pop` are
    affected by this issue. This has been fixed in crossbeam-deque 0.8.1 and 0.7.4. (CVE-2021-32810)

  - Mozilla developers reported memory safety bugs present in Firefox 91 and Firefox ESR 78.13. Some of these
    bugs showed evidence of memory corruption and we presume that with enough effort some of these could have
    been exploited to run arbitrary code. This vulnerability affects Firefox ESR < 78.14, Thunderbird < 78.14,
    and Firefox < 92. (CVE-2021-38493)

  - During operations on MessageTasks, a task may have been removed while it was still scheduled, resulting in
    memory corruption and a potentially exploitable crash. This vulnerability affects Thunderbird < 78.15,
    Thunderbird < 91.2, Firefox ESR < 91.2, Firefox ESR < 78.15, and Firefox < 93. (CVE-2021-38496)

  - Through use of reportValidity() and window.open(), a plain-text validation message could have been
    overlaid on another origin, leading to possible user confusion and spoofing attacks. This vulnerability
    affects Firefox < 93, Thunderbird < 91.2, and Firefox ESR < 91.2. (CVE-2021-38497)

  - During process shutdown, a document could have caused a use-after-free of a languages service object,
    leading to memory corruption and a potentially exploitable crash. This vulnerability affects Firefox < 93,
    Thunderbird < 91.2, and Firefox ESR < 91.2. (CVE-2021-38498)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/notice/NS-SA-2024-0066");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-32810");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-38493");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-38496");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-38497");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-38498");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-38500");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-38501");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-38503");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-38504");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-38506");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-38507");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-38508");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-38509");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-4129");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-4140");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-43534");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-43535");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-43536");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-43537");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-43538");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-43539");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-43541");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-43542");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-43543");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-43545");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-43546");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-1097");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-1196");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-1529");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-1802");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-2200");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-22737");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-22738");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-22739");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-22740");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-22741");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-22742");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-22743");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-22745");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-22747");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-22748");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-22751");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-22754");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-22756");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-22759");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-22760");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-22761");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-22763");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-22764");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-24713");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-2505");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-25235");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-25236");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-25315");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-26381");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-26383");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-26384");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-26386");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-26387");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-26485");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-26486");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-28281");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-28282");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-28285");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-28286");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-28289");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-29909");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-29911");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-29912");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-29914");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-29916");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-29917");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-31736");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-31737");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-31738");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-31740");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-31741");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-31742");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-31744");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-31747");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-34468");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-34470");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-34472");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-34479");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-34481");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-34484");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-36318");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-36319");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-38472");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-38473");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-38476");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-38477");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-38478");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-40674");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-40956");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-40957");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-40958");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-40959");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-40960");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-40962");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-42927");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-42928");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-42929");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-42932");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-43680");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-45403");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-45404");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-45405");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-45406");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-45408");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-45409");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-45410");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-45411");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-45412");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-45416");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-45418");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-45420");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-45421");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-46871");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-46872");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-46874");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-46877");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-46878");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-46880");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-46881");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-46882");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-1945");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-1999");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-23598");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-23599");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-23601");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-23602");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-23603");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-23605");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-25728");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-25729");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-25730");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-25732");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-25735");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-25737");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-25739");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-25742");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-25743");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-25744");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-25746");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-25751");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-25752");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-28162");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-28164");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-28176");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-29533");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-29535");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-29536");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-29539");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-29541");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-29548");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-29550");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-32205");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-32206");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-32207");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-32211");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-32212");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-32213");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-32215");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-34414");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-34416");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-37201");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-37202");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-37207");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-37208");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-37211");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-4045");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-4046");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-4047");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-4048");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-4049");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-4050");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-4051");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-4053");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-4055");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-4056");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-4057");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-4573");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-4574");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-4575");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-4577");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-4578");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-4580");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-4581");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-4583");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-4584");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-4585");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-4863");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-5129");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL firefox packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-25315");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-4140");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:firefox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var os_release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(os_release) || os_release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (os_release !~ "CGSL MAIN 6.02")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 6.02');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL MAIN 6.02': [
    'firefox-102.15.1-1.el8_8'
  ]
};
var pkg_list = pkgs[os_release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + os_release, reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'firefox');
}
