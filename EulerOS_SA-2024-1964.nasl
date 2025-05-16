#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(202537);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/17");

  script_cve_id(
    "CVE-2019-25162",
    "CVE-2021-46904",
    "CVE-2021-46906",
    "CVE-2021-46915",
    "CVE-2021-46928",
    "CVE-2021-46934",
    "CVE-2021-46936",
    "CVE-2021-46939",
    "CVE-2021-46955",
    "CVE-2021-46960",
    "CVE-2021-46988",
    "CVE-2021-46998",
    "CVE-2021-47006",
    "CVE-2021-47015",
    "CVE-2021-47024",
    "CVE-2021-47041",
    "CVE-2021-47056",
    "CVE-2021-47061",
    "CVE-2021-47063",
    "CVE-2021-47065",
    "CVE-2021-47070",
    "CVE-2021-47071",
    "CVE-2021-47073",
    "CVE-2021-47074",
    "CVE-2021-47076",
    "CVE-2021-47077",
    "CVE-2021-47078",
    "CVE-2021-47082",
    "CVE-2021-47091",
    "CVE-2021-47103",
    "CVE-2021-47110",
    "CVE-2021-47112",
    "CVE-2021-47142",
    "CVE-2021-47144",
    "CVE-2021-47153",
    "CVE-2021-47162",
    "CVE-2021-47163",
    "CVE-2021-47166",
    "CVE-2021-47167",
    "CVE-2021-47168",
    "CVE-2021-47170",
    "CVE-2021-47171",
    "CVE-2021-47173",
    "CVE-2021-47182",
    "CVE-2021-47183",
    "CVE-2021-47184",
    "CVE-2021-47194",
    "CVE-2021-47201",
    "CVE-2021-47203",
    "CVE-2021-47209",
    "CVE-2021-47210",
    "CVE-2021-47217",
    "CVE-2021-47274",
    "CVE-2022-48626",
    "CVE-2022-48627",
    "CVE-2022-48631",
    "CVE-2022-48639",
    "CVE-2022-48659",
    "CVE-2022-48671",
    "CVE-2022-48686",
    "CVE-2022-48688",
    "CVE-2022-48695",
    "CVE-2022-48697",
    "CVE-2023-52445",
    "CVE-2023-52454",
    "CVE-2023-52458",
    "CVE-2023-52475",
    "CVE-2023-52476",
    "CVE-2023-52477",
    "CVE-2023-52478",
    "CVE-2023-52486",
    "CVE-2023-52504",
    "CVE-2023-52515",
    "CVE-2023-52522",
    "CVE-2023-52527",
    "CVE-2023-52528",
    "CVE-2023-52530",
    "CVE-2023-52574",
    "CVE-2023-52578",
    "CVE-2023-52583",
    "CVE-2023-52587",
    "CVE-2023-52594",
    "CVE-2023-52597",
    "CVE-2023-52612",
    "CVE-2023-52615",
    "CVE-2023-52619",
    "CVE-2023-52620",
    "CVE-2023-52622",
    "CVE-2023-52623",
    "CVE-2023-52646",
    "CVE-2023-52652",
    "CVE-2023-52835",
    "CVE-2024-1151",
    "CVE-2024-23307",
    "CVE-2024-24855",
    "CVE-2024-26586",
    "CVE-2024-26589",
    "CVE-2024-26602",
    "CVE-2024-26614",
    "CVE-2024-26633",
    "CVE-2024-26635",
    "CVE-2024-26640",
    "CVE-2024-26641",
    "CVE-2024-26642",
    "CVE-2024-26645",
    "CVE-2024-26654",
    "CVE-2024-26663",
    "CVE-2024-26668",
    "CVE-2024-26669",
    "CVE-2024-26671",
    "CVE-2024-26675",
    "CVE-2024-26679",
    "CVE-2024-26686",
    "CVE-2024-26687",
    "CVE-2024-26704",
    "CVE-2024-26720",
    "CVE-2024-26733",
    "CVE-2024-26735",
    "CVE-2024-26739",
    "CVE-2024-26740",
    "CVE-2024-26743",
    "CVE-2024-26744",
    "CVE-2024-26752",
    "CVE-2024-26759",
    "CVE-2024-26763",
    "CVE-2024-26772",
    "CVE-2024-26773",
    "CVE-2024-26804",
    "CVE-2024-26805",
    "CVE-2024-26810",
    "CVE-2024-26812",
    "CVE-2024-26828",
    "CVE-2024-26839",
    "CVE-2024-26840",
    "CVE-2024-26845",
    "CVE-2024-26846",
    "CVE-2024-26851",
    "CVE-2024-26852",
    "CVE-2024-26855",
    "CVE-2024-26857",
    "CVE-2024-26859",
    "CVE-2024-26865",
    "CVE-2024-26872",
    "CVE-2024-26875",
    "CVE-2024-26878",
    "CVE-2024-26880",
    "CVE-2024-26882",
    "CVE-2024-26883",
    "CVE-2024-26884",
    "CVE-2024-26886",
    "CVE-2024-26894",
    "CVE-2024-26900",
    "CVE-2024-26901",
    "CVE-2024-26903",
    "CVE-2024-26907",
    "CVE-2024-26920",
    "CVE-2024-26921",
    "CVE-2024-26923",
    "CVE-2024-26931",
    "CVE-2024-26934",
    "CVE-2024-26958",
    "CVE-2024-26960",
    "CVE-2024-26961",
    "CVE-2024-26973",
    "CVE-2024-26974",
    "CVE-2024-26976",
    "CVE-2024-26982",
    "CVE-2024-26993",
    "CVE-2024-27008",
    "CVE-2024-27010",
    "CVE-2024-27011",
    "CVE-2024-27013",
    "CVE-2024-27014",
    "CVE-2024-27019",
    "CVE-2024-27020",
    "CVE-2024-27043",
    "CVE-2024-27046",
    "CVE-2024-27059",
    "CVE-2024-27073",
    "CVE-2024-27075",
    "CVE-2024-27388",
    "CVE-2024-27395",
    "CVE-2024-27437"
  );

  script_name(english:"EulerOS 2.0 SP9 : kernel (EulerOS-SA-2024-1964)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the EulerOS installation on the remote host is affected by
the following vulnerabilities :

    In the Linux kernel, the following vulnerability has been resolved: i2c: Fix a potential use after free
    Free the adap structure only after we are done using it. This patch just moves the put_device() down a bit
    to avoid the use after free. [wsa: added comment to the code, added Fixes tag](CVE-2019-25162)

    In the Linux kernel, the following vulnerability has been resolved: net: hso: fix null-ptr-deref during
    tty device unregistration Multiple ttys try to claim the same the minor number causing a double
    unregistration of the same device. The first unregistration succeeds but the next one results in a null-
    ptr-deref. The get_free_serial_index() function returns an available minor number but doesn't assign it
    immediately. The assignment is done by the caller later. But before this assignment, calls to
    get_free_serial_index() would return the same minor number. Fix this by modifying get_free_serial_index to
    assign the minor number immediately after one is found to be and rename it to obtain_minor() to better
    reflect what it does. Similary, rename set_serial_by_index() to release_minor() and modify it to free up
    the minor number of the given hso_serial. Every obtain_minor() should have corresponding release_minor()
    call.(CVE-2021-46904)

    In the Linux kernel, the following vulnerability has been resolved: dm-crypt: don't modify the data when
    using authenticated encryption It was said that authenticated encryption could produce invalid tag when
    the data that is being encrypted is modified [1]. So, fix this problem by copying the data into the clone
    bio first and then encrypt them inside the clone bio. This may reduce performance, but it is needed to
    prevent the user from corrupting the device by writing data with O_DIRECT and modifying them at the same
    time.(CVE-2024-26763)

    In the Linux kernel, the following vulnerability has been resolved: HID: usbhid: fix info leak in
    hid_submit_ctrl In hid_submit_ctrl(), the way of calculating the report length doesn't take into account
    that report-size can be zero. When running the syzkaller reproducer, a report of size 0 causes
    hid_submit_ctrl) to calculate transfer_buffer_length as 16384. When this urb is passed to the usb core
    layer, KMSAN reports an info leak of 16384 bytes. To fix this, first modify hid_report_len() to account
    for the zero report size case by using DIV_ROUND_UP for the division. Then, call it from
    hid_submit_ctrl().(CVE-2021-46906)

    In the Linux kernel, the following vulnerability has been resolved: netfilter: nft_limit: avoid possible
    divide error in nft_limit_init div_u64() divides u64 by u32. nft_limit_init() wants to divide u64 by u64,
    use the appropriate math function (div64_u64) divide error: 0000 [#1] PREEMPT SMP KASAN CPU: 1 PID: 8390
    Comm: syz-executor188 Not tainted 5.12.0-rc4-syzkaller(CVE-2021-46915)

    In the Linux kernel, the following vulnerability has been resolved: parisc: Clear stale IIR value on
    instruction access rights trap When a trap 7 (Instruction access rights) occurs, this means the CPU
    couldn't execute an instruction due to missing execute permissions on the memory region. In this case it
    seems the CPU didn't even fetched the instruction from memory and thus did not store it in the cr19 (IIR)
    register before calling the trap handler. So, the trap handler will find some random old stale value in
    cr19. This patch simply overwrites the stale IIR value with a constant magic 'bad food' value
    (0xbaadf00d), in the hope people don't start to try to understand the various random IIR values in trap 7
    dumps.(CVE-2021-46928)

    In the Linux kernel, the following vulnerability has been resolved: media: ttpci: fix two memleaks in
    budget_av_attach When saa7146_register_device and saa7146_vv_init fails, budget_av_attach should free the
    resources it allocates, like the error-handling of ttpci_budget_init does. Besides, there are two fixme
    comment refers to such deallocations.(CVE-2024-27073)

    In the Linux kernel, the following vulnerability has been resolved: i2c: validate user data in compat
    ioctl Wrong user data may cause warning in i2c_transfer(), ex: zero msgs. Userspace should not be able to
    trigger warnings, so this patch adds validation checks for user data in compact ioctl to prevent reported
    warnings(CVE-2021-46934)

    In the Linux kernel, the following vulnerability has been resolved: net: fix use-after-free in
    tw_timer_handler A real world panic issue was found as follow in Linux 5.4. BUG: unable to handle page
    fault for address: ffffde49a863de28 PGD 7e6fe62067 P4D 7e6fe62067 PUD 7e6fe63067 PMD f51e064067 PTE 0 RIP:
    0010:tw_timer_handler+0x20/0x40 Call Trace: IRQ call_timer_fn+0x2b/0x120
    run_timer_softirq+0x1ef/0x450 __do_softirq+0x10d/0x2b8 irq_exit+0xc7/0xd0
    smp_apic_timer_interrupt+0x68/0x120 apic_timer_interrupt+0xf/0x20 This issue was also reported since 2017
    in the thread [1], unfortunately, the issue was still can be reproduced after fixing DCCP. The
    ipv4_mib_exit_net is called before tcp_sk_exit_batch when a net namespace is destroyed since tcp_sk_ops is
    registered befrore ipv4_mib_ops, which means tcp_sk_ops is in the front of ipv4_mib_ops in the list of
    pernet_list. There will be a use-after-free on net-mib.net_statistics in tw_timer_handler after
    ipv4_mib_exit_net if there are some inflight time-wait timers. This bug is not introduced by commit
    f2bf415cfed7 ('mib: add net to NET_ADD_STATS_BH') since the net_statistics is a global variable instead of
    dynamic allocation and freeing. Actually, commit 61a7e26028b9 ('mib: put net statistics on struct net')
    introduces the bug since it put net statistics on struct net and free it when net namespace is destroyed.
    Moving init_ipv4_mibs() to the front of tcp_init() to fix this bug and replace pr_crit() with panic()
    since continuing is meaningless when init_ipv4_mibs() fails. [1]
    https://groups.google.com/g/syzkaller/c/p1tn-_Kc6l4/m/smuL_FMAAgAJ?pli=1(CVE-2021-46936)

    In the Linux kernel, the following vulnerability has been resolved: tracing: Restructure
    trace_clock_global() to never block It was reported that a fix to the ring buffer recursion detection
    would cause a hung machine when performing suspend / resume testing.(CVE-2021-46939)

    In the Linux kernel, the following vulnerability has been resolved: openvswitch: fix stack OOB read while
    fragmenting IPv4 packets running openvswitch on kernels built with KASAN, it's possible to see the
    following splat while testing fragmentation of IPv4 packets: BUG: KASAN: stack-out-of-bounds in
    ip_do_fragment+0x1b03/0x1f60 Read of size 1 at addr ffff888112fc713c by task handler2/1367 CPU: 0 PID:
    1367 Comm: handler2 Not tainted 5.12.0-rc6+ #418 Hardware name: Red Hat KVM, BIOS
    1.11.1-4.module+el8.1.0+4066+0f1aadab 04/01/2014 Call Trace: dump_stack+0x92/0xc1
    print_address_description.constprop.7+0x1a/0x150 kasan_report.cold.13+0x7f/0x111
    ip_do_fragment+0x1b03/0x1f60 ovs_fragment+0x5bf/0x840 [openvswitch] do_execute_actions+0x1bd5/0x2400
    [openvswitch] ovs_execute_actions+0xc8/0x3d0 [openvswitch] ovs_packet_cmd_execute+0xa39/0x1150
    [openvswitch] genl_family_rcv_msg_doit.isra.15+0x227/0x2d0 genl_rcv_msg+0x287/0x490
    netlink_rcv_skb+0x120/0x380 genl_rcv+0x24/0x40 netlink_unicast+0x439/0x630 netlink_sendmsg+0x719/0xbf0
    sock_sendmsg+0xe2/0x110 ____sys_sendmsg+0x5ba/0x890 ___sys_sendmsg+0xe9/0x160 __sys_sendmsg+0xd3/0x170
    do_syscall_64+0x33/0x40 entry_SYSCALL_64_after_hwframe+0x44/0xae RIP: 0033:0x7f957079db07 Code: c3 66 90
    41 54 41 89 d4 55 48 89 f5 53 89 fb 48 83 ec 10 e8 eb ec ff ff 44 89 e2 48 89 ee 89 df 41 89 c0 b8 2e 00
    00 00 0f 05 48 3d 00 f0 ff ff 77 35 44 89 c7 48 89 44 24 08 e8 24 ed ff ff 48 RSP:
    002b:00007f956ce35a50 EFLAGS: 00000293 ORIG_RAX: 000000000000002e RAX: ffffffffffffffda RBX:
    0000000000000019 RCX: 00007f957079db07 RDX: 0000000000000000 RSI: 00007f956ce35ae0 RDI: 0000000000000019
    RBP: 00007f956ce35ae0 R08: 0000000000000000 R09: 00007f9558006730 R10: 0000000000000000 R11:
    0000000000000293 R12: 0000000000000000 R13: 00007f956ce37308 R14: 00007f956ce35f80 R15: 00007f956ce35ae0
    The buggy address belongs to the page: page:00000000af2a1d93 refcount:0 mapcount:0
    mapping:0000000000000000 index:0x0 pfn:0x112fc7 flags: 0x17ffffc0000000() raw: 0017ffffc0000000
    0000000000000000 dead000000000122 0000000000000000 raw: 0000000000000000 0000000000000000 00000000ffffffff
    0000000000000000 page dumped because: kasan: bad access detected addr ffff888112fc713c is located in stack
    of task handler2/1367 at offset 180 in frame: ovs_fragment+0x0/0x840 [openvswitch] this frame has 2
    objects: [32, 144) 'ovs_dst' [192, 424) 'ovs_rt' Memory state around the buggy address: ffff888112fc7000:
    f3 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ffff888112fc7080: 00 f1 f1 f1 f1 00 00 00 00 00 00 00 00
    00 00 00 ffff888112fc7100: 00 00 00 f2 f2 f2 f2 f2 f2 00 00 00 00 00 00 00 ^ ffff888112fc7180: 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 ffff888112fc7200: 00 00 00 00 00 00 f2 f2 f2 00 00 00 00 00 00 00
    for IPv4 packets, ovs_fragment() uses a temporary struct dst_entry. Then, in the following call graph:
    ip_do_fragment() ip_skb_dst_mtu() ip_dst_mtu_maybe_forward() ip_mtu_locked() the pointer to struct
    dst_entry is used as pointer to struct rtable: this turns the access to struct members like rt_mtu_locked
    into an OOB read in the stack. Fix this changing the temporary variable used for IPv4 packets in
    ovs_fragment(), similarly to what is done for IPv6 few lines below.(CVE-2021-46955)

    In the Linux kernel, the following vulnerability has been resolved: cifs: Return correct error code from
    smb2_get_enc_key Avoid a warning if the error percolates back up: [440700.376476] CIFS VFS:
    \\otters.example.com crypt_message: Could not get encryption key [440700.386947] ------------[ cut here
    ]------------ [440700.386948] err = 1 [440700.386977] WARNING: CPU: 11 PID: 2733 at /build/linux-
    hwe-5.4-p6lk6L/linux-hwe-5.4-5.4.0/lib/errseq.c:74 errseq_set+0x5c/0x70 ... [440700.397304] CPU: 11 PID:
    2733 Comm: tar Tainted: G OE 5.4.0-70-generic #78~18.04.1-Ubuntu ... [440700.397334] Call Trace:
    [440700.397346] __filemap_set_wb_err+0x1a/0x70 [440700.397419] cifs_writepages+0x9c7/0xb30 [cifs]
    [440700.397426] do_writepages+0x4b/0xe0 [440700.397444] __filemap_fdatawrite_range+0xcb/0x100
    [440700.397455] filemap_write_and_wait+0x42/0xa0 [440700.397486] cifs_setattr+0x68b/0xf30 [cifs]
    [440700.397493] notify_change+0x358/0x4a0 [440700.397500] utimes_common+0xe9/0x1c0 [440700.397510]
    do_utimes+0xc5/0x150 [440700.397520] __x64_sys_utimensat+0x88/0xd0(CVE-2021-46960)

    In the Linux kernel, the following vulnerability has been resolved: userfaultfd: release page in error
    path to avoid BUG_ON Consider the following sequence of events: 1. Userspace issues a UFFD ioctl, which
    ends up calling into shmem_mfill_atomic_pte(). We successfully account the blocks, we shmem_alloc_page(),
    but then the copy_from_user() fails. We return -ENOENT. We don't release the page we allocated. 2. Our
    caller detects this error code, tries the copy_from_user() after dropping the mmap_lock, and retries,
    calling back into shmem_mfill_atomic_pte(). 3. Meanwhile, let's say another process filled up the tmpfs
    being used. 4. So shmem_mfill_atomic_pte() fails to account blocks this time, and immediately returns -
    without releasing the page. This triggers a BUG_ON in our caller, which asserts that the page should
    always be consumed, unless -ENOENT is returned. To fix this, detect if we have such a 'dangling' page when
    accounting fails, and if so, release it before returning.(CVE-2021-46988)

    In the Linux kernel, the following vulnerability has been resolved: ARM: 9064/1: hw_breakpoint: Do not
    directly check the event's overflow_handler hook The commit 1879445dfa7b ('perf/core: Set event's default
    ::overflow_handler()') set a default event-overflow_handler in perf_event_alloc(), and replace the
    check event-overflow_handler with is_default_overflow_handler(), but one is missing. Currently, the bp-
    overflow_handler can not be NULL. As a result, enable_single_step() is always not
    invoked.(CVE-2021-47006)

    In the Linux kernel, the following vulnerability has been resolved: HID: logitech-hidpp: Fix kernel crash
    on receiver USB disconnect hidpp_connect_event() has *four* time-of-check vs time-of-use (TOCTOU) races
    when it races with itself. hidpp_connect_event() primarily runs from a workqueue but it also runs on
    probe() and if a 'device-connected' packet is received by the hw when the thread running
    hidpp_connect_event() from probe() is waiting on the hw, then a second thread running
    hidpp_connect_event() will be started from the workqueue. This opens the following races (note the below
    code is simplified): 1. Retrieving + printing the protocol (harmless race): if (!hidpp-protocol_major)
    { hidpp_root_get_protocol_version() hidpp-protocol_major = response.rap.params[0]; } We can actually
    see this race hit in the dmesg in the abrt output attached to rhbz#2227968: [ 3064.624215] logitech-hidpp-
    device 0003:046D:4071.0049: HID++ 4.5 device connected. [ 3064.658184] logitech-hidpp-device
    0003:046D:4071.0049: HID++ 4.5 device connected. Testing with extra logging added has shown that after
    this the 2 threads take turn grabbing the hw access mutex (send_mutex) so they ping-pong through all the
    other TOCTOU cases managing to hit all of them: 2. Updating the name to the HIDPP name (harmless race): if
    (hidpp-name == hdev-name) { ... hidpp-name = new_name; } 3. Initializing the power_supply class
    for the battery (problematic!): hidpp_initialize_battery() { if (hidpp-battery.ps) return 0;
    probe_battery(); /* Blocks, threads take turns executing this */ hidpp-battery.desc.properties =
    devm_kmemdup(dev, hidpp_battery_props, cnt, GFP_KERNEL); hidpp-battery.ps =
    devm_power_supply_register(hidpp-hid_dev-dev, hidpp-battery.desc, cfg); } 4. Creating
    delayed input_device (potentially problematic): if (hidpp-delayed_input) return; hidpp-delayed_input
    = hidpp_allocate_input(hdev); The really big problem here is 3. Hitting the race leads to the following
    sequence: hidpp-battery.desc.properties = devm_kmemdup(dev, hidpp_battery_props, cnt, GFP_KERNEL);
    hidpp-battery.ps = devm_power_supply_register(hidpp-hid_dev-dev, hidpp-battery.desc,
    cfg); ... hidpp-battery.desc.properties = devm_kmemdup(dev, hidpp_battery_props, cnt, GFP_KERNEL);
    hidpp-battery.ps = devm_power_supply_register(hidpp-hid_dev-dev, hidpp-battery.desc,
    cfg); So now we have registered 2 power supplies for the same battery, which looks a bit weird from
    userspace's pov but this is not even the really big problem. Notice how: 1. This is all devm-maganaged 2.
    The hidpp-battery.desc struct is shared between the 2 power supplies 3. hidpp-
    battery.desc.properties points to the result from the second devm_kmemdup() This causes a use after
    free scenario on USB disconnect of the receiver: 1. The last registered power supply class device gets
    unregistered 2. The memory from the last devm_kmemdup() call gets freed, hidpp-battery.desc.properties
    now points to freed memory 3. The first registered power supply class device gets unregistered, this
    involves sending a remove uevent to userspace which invokes power_supply_uevent() to fill the uevent data
    4. power_supply_uevent() uses hidpp-battery.desc.properties which now points to freed memory leading to
    backtraces like this one: Sep 22 20:01:35 eric kernel: BUG: unable to handle page fault for address:
    ffffb2140e017f08 ... Sep 22 20:01:35 eric kernel: Workqueue: usb_hub_wq hub_event Sep 22 20:01:35 eric
    kernel: RIP: 0010:power_supply_uevent+0xee/0x1d0 ... Sep 22 20:01:35 eric kernel: ?
    asm_exc_page_fault+0x26/0x30 Sep 22 20:01:35 eric kernel: ? power_supply_uevent+0xee/0x1d0 Sep 22 20:01:35
    eric kernel: ? power_supply_uevent+0x10d/0x1d0 Sep 22 20:01:35 eric kernel: dev_uevent+0x10f/0x2d0 Sep 22
    20:01:35 eric kernel: kobject_uevent_env+0x291/0x680 Sep 22 20:01:35 eric kernel:
    ---truncated---(CVE-2023-52478)

    In the Linux kernel, the following vulnerability has been resolved: pstore/ram: Fix crash when setting
    number of cpus to an odd number When the number of cpu cores is adjusted to 7 or other odd numbers, the
    zone size will become an odd number. The address of the zone will become: addr of zone0 = BASE addr of
    zone1 = BASE + zone_size addr of zone2 = BASE + zone_size*2 ... The address of zone1/3/5/7 will be mapped
    to non-alignment va. Eventually crashes will occur when accessing these va. So, use ALIGN_DOWN() to make
    sure the zone size is even to avoid this bug.(CVE-2023-52619)

    In the Linux kernel, the following vulnerability has been resolved:crypto: scomp - fix req-dst buffer
    overflow.The req-dst buffer size should be checked before copying from the scomp_scratch-dst to
    avoid req-dst buffer overflow problem.(CVE-2023-52612)

    In the Linux kernel, the following vulnerability has been resolved: bnxt_en: Fix RX consumer index logic
    in the error path. In bnxt_rx_pkt(), the RX buffers are expected to complete in order. If the RX consumer
    index indicates an out of order buffer completion, it means we are hitting a hardware bug and the driver
    will abort all remaining RX packets and reset the RX ring. The RX consumer index that we pass to
    bnxt_discard_rx() is not correct. We should be passing the current index (tmp_raw_cons) instead of the old
    index (raw_cons). This bug can cause us to be at the wrong index when trying to abort the next RX
    packet.(CVE-2021-47015)

    In the Linux kernel, the following vulnerability has been resolved: nvmet-tcp: fix incorrect locking in
    state_change sk callback We are not changing anything in the TCP connection state so we should not take a
    write_lock but rather a read lock. This caused a deadlock when running nvmet-tcp and nvme-tcp on the same
    system, where state_change callbacks on the host and on the controller side have causal relationship and
    made lockdep report on this with blktests(CVE-2021-47041)

    In the Linux kernel, the following vulnerability has been resolved:NFS: Fix an Oopsable condition in
    __nfs_pageio_add_request().Ensure that nfs_pageio_error_cleanup() resets the mirror array contents,so that
    the structure reflects the fact that it is now empty.Also change the test in nfs_pageio_do_add_request()
    to be more robust by checking whether or not the list is empty rather than relying on the value of
    pg_count.(CVE-2021-47167)

    In the Linux kernel, the following vulnerability has been resolved: crypto: qat - ADF_STATUS_PF_RUNNING
    should be set after adf_dev_init ADF_STATUS_PF_RUNNING is (only) used and checked by adf_vf2pf_shutdown()
    before calling adf_iov_putmsg()-mutex_lock(vf2pf_lock), however the vf2pf_lock is initialized in
    adf_dev_init(), which can fail and when it fail, the vf2pf_lock is either not initialized or destroyed, a
    subsequent use of vf2pf_lock will cause issue. To fix this issue, only set this flag if adf_dev_init()
    returns 0. [ 7.178404] BUG: KASAN: user-memory-access in __mutex_lock.isra.0+0x1ac/0x7c0 [ 7.180345] Call
    Trace: [ 7.182576] mutex_lock+0xc9/0xd0 [ 7.183257] adf_iov_putmsg+0x118/0x1a0 [intel_qat] [ 7.183541]
    adf_vf2pf_shutdown+0x4d/0x7b [intel_qat] [ 7.183834] adf_dev_shutdown+0x172/0x2b0 [intel_qat] [ 7.184127]
    adf_probe+0x5e9/0x600 [qat_dh895xccvf](CVE-2021-47056)

    In the Linux kernel, the following vulnerability has been resolved: ext4: avoid online resizing failures
    due to oversized flex bg When we online resize an ext4 filesystem with a oversized flexbg_size, mkfs.ext4
    -F -G 67108864 $dev -b 4096 100M mount $dev $dir resize2fs $dev 16G the following WARN_ON is triggered:
    ================================================================== WARNING: CPU: 0 PID: 427 at
    mm/page_alloc.c:4402 __alloc_pages+0x411/0x550 Modules linked in: sg(E) CPU: 0 PID: 427 Comm: resize2fs
    Tainted: G E 6.6.0-rc5+ #314 RIP: 0010:__alloc_pages+0x411/0x550 Call Trace: TASK
    __kmalloc_large_node+0xa2/0x200 __kmalloc+0x16e/0x290 ext4_resize_fs+0x481/0xd80
    __ext4_ioctl+0x1616/0x1d90 ext4_ioctl+0x12/0x20 __x64_sys_ioctl+0xf0/0x150 do_syscall_64+0x3b/0x90
    ================================================================== This is because flexbg_size is too
    large and the size of the new_group_data array to be allocated exceeds MAX_ORDER. Currently, the minimum
    value of MAX_ORDER is 8, the minimum value of PAGE_SIZE is 4096, the corresponding maximum number of
    groups that can be allocated is: (PAGE_SIZE  MAX_ORDER) / sizeof(struct ext4_new_group_data) 
    21845 And the value that is down-aligned to the power of 2 is 16384. Therefore, this value is defined as
    MAX_RESIZE_BG, and the number of groups added each time does not exceed this value during resizing, and is
    added multiple times to complete the online resizing. The difference is that the metadata in a flex_bg may
    be more dispersed.(CVE-2023-52622)

    In the Linux kernel, the following vulnerability has been resolved: net: usb: fix memory leak in
    smsc75xx_bind Syzbot reported memory leak in smsc75xx_bind(). The problem was is non-freed memory in case
    of errors after memory allocation.(CVE-2021-47171)

    In the Linux kernel, the following vulnerability has been resolved: RDMA/rxe: Return CQE error if invalid
    lkey was supplied RXE is missing update of WQE status in LOCAL_WRITE failures. This caused the following
    kernel panic if someone sent an atomic operation with an explicitly wrong lkey.(CVE-2021-47076)

    In the Linux kernel, the following vulnerability has been resolved: KVM: Destroy I/O bus devices on
    unregister failure _after_ sync'ing SRCU If allocating a new instance of an I/O bus fails when
    unregistering a device, wait to destroy the device until after all readers are guaranteed to see the new
    null bus. Destroying devices before the bus is nullified could lead to use-after-free since readers expect
    the devices on their reference of the bus to remain valid.(CVE-2021-47061)

    In the Linux kernel, the following vulnerability has been resolved: ethernet:enic: Fix a use after free
    bug in enic_hard_start_xmit In enic_hard_start_xmit, it calls enic_queue_wq_skb(). Inside
    enic_queue_wq_skb, if some error happens, the skb will be freed by dev_kfree_skb(skb). But the freed skb
    is still used in skb_tx_timestamp(skb). My patch makes enic_queue_wq_skb() return error and goto
    spin_unlock() incase of error.(CVE-2021-46998)

    In the Linux kernel, the following vulnerability has been resolved: ip6_tunnel: make sure to pull inner
    header in __ip6_tnl_rcv() syzbot found __ip6_tnl_rcv() could access unitiliazed data [1]. Call
    pskb_inet_may_pull() to fix this, and initialize ipv6h variable after this call as it can change skb-
    head.(CVE-2024-26641)

    In the Linux kernel, the following vulnerability has been resolved: drm: bridge/panel: Cleanup connector
    on bridge detach If we don't call drm_connector_cleanup() manually in panel_bridge_detach(), the connector
    will be cleaned up with the other DRM objects in the call to drm_mode_config_cleanup(). However, since our
    drm_connector is devm-allocated, by the time drm_mode_config_cleanup() will be called, our connector will
    be long gone. Therefore, the connector must be cleaned up when the bridge is detached to avoid use-after-
    free conditions. v2: Cleanup connector only if it was created v3: Add FIXME v4: (Use connector-dev)
    directly in if() block(CVE-2021-47063)

    In the Linux kernel, the following vulnerability has been resolved: tcp: add sanity checks to rx zerocopy
    TCP rx zerocopy intent is to map pages initially allocated from NIC drivers, not pages owned by a fs. This
    patch adds to can_map_frag() these additional checks: - Page must not be a compound one. - page-mapping
    must be NULL. This fixes the panic reported by ZhangPeng. syzbot was able to loopback packets built with
    sendfile(), mapping pages owned by an ext4 file to TCP rx zerocopy. r3 = socket$inet_tcp(0x2, 0x1, 0x0)
    mmap((0x7f0000ff9000/0x4000)=nil, 0x4000, 0x0, 0x12, r3, 0x0) r4 = socket$inet_tcp(0x2, 0x1, 0x0)
    bind$inet(r4, (0x7f0000000000)={0x2, 0x4e24, @multicast1}, 0x10) connect$inet(r4,
    (0x7f00000006c0)={0x2, 0x4e24, @empty}, 0x10) r5 = openat$dir(0xffffffffffffff9c,
    (0x7f00000000c0)='./file0\x00', 0x181e42, 0x0) fallocate(r5, 0x0, 0x0, 0x85b8) sendfile(r4, r5, 0x0,
    0x8ba0) getsockopt$inet_tcp_TCP_ZEROCOPY_RECEIVE(r4, 0x6, 0x23,
    (0x7f00000001c0)={(0x7f0000ffb000/0x3000)=nil, 0x3000, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
    (0x7f0000000440)=0x40) r6 = openat$dir(0xffffffffffffff9c, (0x7f00000000c0)='./file0\x00', 0x181e42,
    0x0)(CVE-2024-26640)

    In the Linux kernel, the following vulnerability has been resolved: rtw88: Fix array overrun in
    rtw_get_tx_power_params() Using a kernel with the Undefined Behaviour Sanity Checker (UBSAN)
    enabled(CVE-2021-47065)

    In the Linux kernel, the following vulnerability has been resolved: uio_hv_generic: Fix another memory
    leak in error handling paths Memory allocated by 'vmbus_alloc_ring()' at the beginning of the probe
    function is never freed in the error handling path. Add the missing 'vmbus_free_ring()' call. Note that it
    is already freed in the .remove function.(CVE-2021-47070)

    In the Linux kernel, the following vulnerability has been resolved: uio_hv_generic: Fix a memory leak in
    error handling paths If 'vmbus_establish_gpadl()' fails, the (recv|send)_gpadl will not be updated and
    'hv_uio_cleanup()' in the error handling path will not be able to free the corresponding buffer. In such a
    case, we need to free the buffer explicitly.(CVE-2021-47071)

    In the Linux kernel, the following vulnerability has been resolved: platform/x86: dell-smbios-wmi: Fix
    oops on rmmod dell_smbios init_dell_smbios_wmi() only registers the dell_smbios_wmi_driver on systems
    where the Dell WMI interface is supported. While exit_dell_smbios_wmi() unregisters it unconditionally,
    this leads to the following oops: [ 175.722921](CVE-2021-47073)

    In the Linux kernel, the following vulnerability has been resolved: net/sched: flower: Fix chain template
    offload When a qdisc is deleted from a net device the stack instructs the underlying driver to remove its
    flow offload callback from the associated filter block using the 'FLOW_BLOCK_UNBIND' command. The stack
    then continues to replay the removal of the filters in the block for this driver by iterating over the
    chains in the block and invoking the 'reoffload' operation of the classifier being used. In turn, the
    classifier in its 'reoffload' operation prepares and emits a 'FLOW_CLS_DESTROY' command for each filter.
    However, the stack does not do the same for chain templates and the underlying driver never receives a
    'FLOW_CLS_TMPLT_DESTROY' command when a qdisc is deleted.(CVE-2024-26671)

    In the Linux kernel, the following vulnerability has been resolved: l2tp: pass correct message length to
    ip6_append_data l2tp_ip6_sendmsg needs to avoid accounting for the transport header twice when splicing
    more data into an already partially-occupied skbuff. To manage this, we check whether the skbuff contains
    data using skb_queue_empty when deciding how much data to append using ip6_append_data. However, the code
    which performed the calculation was incorrect: ulen = len + skb_queue_empty(sk-sk_write_queue) ?
    transhdrlen : 0; ...due to C operator precedence, this ends up setting ulen to transhdrlen for messages
    with a non-zero length, which results in corrupted packets on the wire. Add parentheses to correct the
    calculation in line with the original intent.(CVE-2024-26752)

    In the Linux kernel, the following vulnerability has been resolved: ipv4, ipv6: Fix handling of
    transhdrlen in __ip{,6}_append_data() Including the transhdrlen in length is a problem when the packet is
    partially filled (e.g. something like send(MSG_MORE) happened previously) when appending to an IPv4 or
    IPv6 packet as we don't want to repeat the transport header or account for it twice. This can happen under
    some circumstances, such as splicing into an L2TP socket. The symptom observed is a warning in
    __ip6_append_data(): WARNING: CPU: 1 PID: 5042 at net/ipv6/ip6_output.c:1800
    __ip6_append_data.isra.0+0x1be8/0x47f0 net/ipv6/ip6_output.c:1800 that occurs when MSG_SPLICE_PAGES is
    used to append more data to an already partially occupied skbuff. The warning occurs when 'copy' is larger
    than the amount of data in the message iterator. This is because the requested length includes the
    transport header length when it shouldn't. This can be triggered by, for example: sfd = socket(AF_INET6,
    SOCK_DGRAM, IPPROTO_L2TP); bind(sfd, ...); // ::1 connect(sfd, ...); // ::1 port 7 send(sfd, buffer, 4100,
    MSG_MORE); sendfile(sfd, dfd, NULL, 1024); Fix this by only adding transhdrlen into the length if the
    write queue is empty in l2tp_ip6_sendmsg(), analogously to how UDP does things. l2tp_ip_sendmsg() looks
    like it won't suffer from this problem as it builds the UDP packet itself.(CVE-2023-52527)

    In the Linux kernel, the following vulnerability has been resolved: ipv6: sr: fix possible use-after-free
    and null-ptr-deref The pernet operations structure for the subsystem must be registered before registering
    the generic netlink family.(CVE-2024-26735)

    In the Linux kernel, the following vulnerability has been resolved: nvme-loop: fix memory leak in
    nvme_loop_create_ctrl() When creating loop ctrl in nvme_loop_create_ctrl(), if nvme_init_ctrl() fails, the
    loop ctrl should be freed before jumping to the 'out' label.(CVE-2021-47074)

    In the Linux kernel, the following vulnerability has been resolved: RDMA/rxe: Clear all QP fields if
    creation failed rxe_qp_do_cleanup() relies on valid pointer values in QP for the properly created ones,
    but in case rxe_qp_from_init() failed it was filled with garbage and caused tot the following error.
    refcount_t: underflow; use-after-free.(CVE-2021-47078)

    In the Linux kernel, the following vulnerability has been resolved: quota: Fix potential NULL pointer
    dereference Below race may cause NULL pointer dereference P1 P2 dquot_free_inode quota_off drop_dquot_ref
    remove_dquot_ref dquots = i_dquot(inode) dquots = i_dquot(inode) srcu_read_lock dquots[cnt]) != NULL (1)
    dquots[type] = NULL (2) spin_lock(dquots[cnt]-dq_dqb_lock) (3) .... If dquot_free_inode(or other
    routines) checks inode's quota pointers (1) before quota_off sets it to NULL(2) and use it (3) after that,
    NULL pointer dereference will be triggered. So let's fix it by using a temporary pointer to avoid this
    issue.(CVE-2024-26880)

    Integer Overflow or Wraparound vulnerability in Linux Linux kernel kernel on Linux, x86, ARM (md, raid,
    raid5 modules) allows Forced Integer Overflow.(CVE-2024-23307)

    In the Linux kernel, the following vulnerability has been resolved: tun: avoid double free in
    tun_free_netdev Avoid double free in tun_free_netdev() by moving the dev-tstats and tun-security
    allocs to a new ndo_init routine (tun_net_init()) that will be called by register_netdevice(). ndo_init is
    paired with the desctructor (tun_free_netdev()), so if there's an error in register_netdevice() the
    destructor will handle the frees.(CVE-2021-47082)

    In the Linux kernel, the following vulnerability has been resolved: mac80211: fix locking in
    ieee80211_start_ap error path We need to hold the local-mtx to release the channel context, as even
    encoded by the lockdep_assert_held() there.(CVE-2021-47091)

    In the Linux kernel, the following vulnerability has been resolved: inet: fully convert sk-sk_rx_dst to
    RCU rules syzbot reported various issues around early demux, one being included in this changelog [1] sk-
    sk_rx_dst is using RCU protection without clearly documenting it. And following sequences in
    tcp_v4_do_rcv()/tcp_v6_do_rcv() are not following standard RCU rules. [a] dst_release(dst); [b] sk-
    sk_rx_dst = NULL; They look wrong because a delete operation of RCU protected pointer is supposed to
    clear the pointer before the call_rcu()/synchronize_rcu() guarding actual memory freeing. In some cases
    indeed, dst could be freed before [b] is done. We could cheat by clearing sk_rx_dst before calling
    dst_release(), but this seems the right time to stick to standard RCU annotations and debugging
    facilities.(CVE-2021-47103)

    In the Linux kernel, the following vulnerability has been resolved: x86/kvm: Disable kvmclock on all CPUs
    on shutdown Currenly, we disable kvmclock from machine_shutdown() hook and this only happens for boot CPU.
    We need to disable it for all CPUs to guard against memory corruption e.g. on restore from hibernate.
    Note, writing '0' to kvmclock MSR doesn't clear memory location, it just prevents hypervisor from updating
    the location so for the short while after write and while CPU is still alive, the clock remains usable and
    correct so we don't need to switch to some other clocksource.(CVE-2021-47110)

    A race condition was found in the Linux kernel's scsi device driver in lpfc_unregister_fcf_rescan()
    function. This can result in a null pointer dereference issue, possibly leading to a kernel panic or
    denial of service issue.(CVE-2024-24855)

    In the Linux kernel, the following vulnerability has been resolved: mm/swap: fix race when skipping
    swapcache When skipping swapcache for SWP_SYNCHRONOUS_IO, if two or more threads swapin the same entry at
    the same time, they get different pages (A, B). Before one thread (T0) finishes the swapin and installs
    page (A) to the PTE, another thread (T1) could finish swapin of page (B), swap_free the entry, then swap
    out the possibly modified page reusing the same entry. It breaks the pte_same check in (T0) because PTE
    value is unchanged, causing ABA problem. Thread (T0) will install a stalled page (A) into the PTE and
    cause data corruption.(CVE-2024-26759)

    In the Linux kernel, the following vulnerability has been resolved: mm/writeback: fix possible divide-by-
    zero in wb_dirty_limits(), again (struct dirty_throttle_control *)-thresh is an unsigned long, but is
    passed as the u32 divisor argument to div_u64(). On architectures where unsigned long is 64 bytes, the
    argument will be implicitly truncated. Use div64_u64() instead of div_u64() so that the value used in the
    'is this a safe division' check is the same as the divisor. Also, remove redundant cast of the numerator
    to u64, as that should happen implicitly. This would be difficult to exploit in memcg domain, given the
    ratio-based arithmetic domain_drity_limits() uses, but is much easier in global writeback domain with a
    BDI_CAP_STRICTLIMIT-backing device, using e.g. vm.dirty_bytes=(132)*PAGE_SIZE so that dtc-thresh
    == (132)(CVE-2024-26720)

    In the Linux kernel, the following vulnerability has been resolved: ext4: avoid allocating blocks from
    corrupted group in ext4_mb_try_best_found() Determine if the group block bitmap is corrupted before using
    ac_b_ex in ext4_mb_try_best_found() to avoid allocating blocks from a group with a corrupted block bitmap
    in the following concurrency and making the situation worse. ext4_mb_regular_allocator ext4_lock_group(sb,
    group) ext4_mb_good_group // check if the group bbitmap is corrupted ext4_mb_complex_scan_group // Scan
    group gets ac_b_ex but doesn't use it ext4_unlock_group(sb, group) ext4_mark_group_bitmap_corrupted(group)
    // The block bitmap was corrupted during // the group unlock gap. ext4_mb_try_best_found
    ext4_lock_group(ac-ac_sb, group) ext4_mb_use_best_found mb_mark_used // Allocating blocks in block
    bitmap corrupted group(CVE-2024-26773)

    In the Linux kernel, the following vulnerability has been resolved: i40e: Fix NULL ptr dereference on VSI
    filter sync Remove the reason of null pointer dereference in sync VSI filters. Added new
    I40E_VSI_RELEASING flag to signalize deleting and releasing of VSI resources to sync this thread with sync
    filters subtask. Without this patch it is possible to start update the VSI filter list after VSI is
    removed, that's causing a kernel oops.(CVE-2021-47184)

    In the Linux kernel, the following vulnerability has been resolved: arp: Prevent overflow in
    arp_req_get(). syzkaller reported an overflown write in arp_req_get(). [0] When ioctl(SIOCGARP) is issued,
    arp_req_get() looks up an neighbour entry and copies neigh-ha to struct arpreq.arp_ha.sa_data. The
    arp_ha here is struct sockaddr, not struct sockaddr_storage, so the sa_data buffer is just 14 bytes. In
    the splat below, 2 bytes are overflown to the next int field, arp_flags. We initialise the field just
    after the memcpy(), so it's not a problem. However, when dev-addr_len is greater than 22 (e.g.
    MAX_ADDR_LEN), arp_netmask is overwritten, which could be set as htonl(0xFFFFFFFFUL) in arp_ioctl() before
    calling arp_req_get(). To avoid the overflow, let's limit the max length of memcpy().(CVE-2024-26733)

    In the Linux kernel, the following vulnerability has been resolved: iavf: free q_vectors before queues in
    iavf_disable_vf iavf_free_queues() clears adapter-num_active_queues, which iavf_free_q_vectors() relies
    on, so swap the order of these two function calls in iavf_disable_vf(). This resolves a panic encountered
    when the interface is disabled and then later brought up again after PF communication is
    restored.(CVE-2021-47201)

    In the Linux kernel, the following vulnerability has been resolved: sched/fair: Prevent dead task groups
    from regaining cfs_rq's Kevin is reporting crashes which point to a use-after-free of a cfs_rq in
    update_blocked_averages(). Initial debugging revealed that we've live cfs_rq's (on_list=1) in an about to
    be kfree()'d task group in free_fair_sched_group(). However, it was unclear how that can happen. His
    kernel config happened to lead to a layout of struct sched_entity that put the 'my_q' member directly into
    the middle of the object which makes it incidentally overlap with SLUB's freelist pointer. That, in
    combination with SLAB_FREELIST_HARDENED's freelist pointer mangling, leads to a reliable access violation
    in form of a #GP which made the UAF fail fast.(CVE-2021-47209)

    In the Linux kernel, the following vulnerability has been resolved: SUNRPC: Fix a suspicious RCU usage
    warning I received the following warning while running cthon against an ontap server running pNFS: [
    57.202521] ============================= [ 57.202522] WARNING: suspicious RCU usage [ 57.202523]
    6.7.0-rc3-g2cc14f52aeb7 #41492 Not tainted [ 57.202525] ----------------------------- [ 57.202525]
    net/sunrpc/xprtmultipath.c:349 RCU-list traversed in non-reader section!! [ 57.202527] other info that
    might help us debug this: [ 57.202528] rcu_scheduler_active = 2, debug_locks = 1 [ 57.202529] no locks
    held by test5/3567. [ 57.202530] stack backtrace: [ 57.202532] CPU: 0 PID: 3567 Comm: test5 Not tainted
    6.7.0-rc3-g2cc14f52aeb7 #41492 5b09971b4965c0aceba19f3eea324a4a806e227e [ 57.202534] Hardware name: QEMU
    Standard PC (Q35 + ICH9, 2009), BIOS unknown 2/2/2022 [ 57.202536](CVE-2023-52623)

    In the Linux kernel, the following vulnerability has been resolved: tracing: Ensure visibility when
    inserting an element into tracing_map Running the following two commands in parallel on a multi-processor
    AArch64 machine can sporadically produce an unexpected warning about duplicate histogram entries: $ while
    true; do echo hist:key=id.syscall:val=hitcount  \
    /sys/kernel/debug/tracing/events/raw_syscalls/sys_enter/trigger cat
    /sys/kernel/debug/tracing/events/raw_syscalls/sys_enter/hist sleep 0.001 done $ stress-ng --sysbadaddr
    $(nproc)(CVE-2024-26645)

    In the Linux kernel, the following vulnerability has been resolved: i2c: i801: Don't generate an interrupt
    on bus reset Now that the i2c-i801 driver supports interrupts, setting the KILL bit in a attempt to
    recover from a timed out transaction triggers an interrupt. Unfortunately, the interrupt handler
    (i801_isr) is not prepared for this situation and will try to process the interrupt as if it was signaling
    the end of a successful transaction. In the case of a block transaction, this can result in an out-of-
    range memory access.(CVE-2021-47153)

    In the Linux kernel, the following vulnerability has been resolved: net: ip_tunnel: prevent perpetual
    headroom growth syzkaller triggered following kasan splat: BUG: KASAN: use-after-free in
    __skb_flow_dissect+0x19d1/0x7a50(CVE-2024-26804)

    In the Linux kernel, the following vulnerability has been resolved: net/sched: flower: Fix chain template
    offload When a qdisc is deleted from a net device the stack instructs the underlying driver to remove its
    flow offload callback from the associated filter block using the 'FLOW_BLOCK_UNBIND' command. The stack
    then continues to replay the removal of the filters in the block for this driver by iterating over the
    chains in the block and invoking the 'reoffload' operation of the classifier being used. In turn, the
    classifier in its 'reoffload' operation prepares and emits a 'FLOW_CLS_DESTROY' command for each filter.
    However, the stack does not do the same for chain templates and the underlying driver never receives a
    'FLOW_CLS_TMPLT_DESTROY' command when a qdisc is deleted.(CVE-2024-26669)

    In the Linux kernel, the following vulnerability has been resolved: tracing: Correct the length check
    which causes memory corruption We've suffered from severe kernel crashes due to memory corruption on our
    production environment(CVE-2021-47274)

    In the Linux kernel, the following vulnerability has been resolved: cachefiles: fix memory leak in
    cachefiles_add_cache()(CVE-2024-26840)

    In the Linux kernel, the following vulnerability has been resolved: do_sys_name_to_handle(): use kzalloc()
    to fix kernel-infoleak syzbot identified a kernel information leak vulnerability in
    do_sys_name_to_handle() and issued the following report [1]. [1] 'BUG: KMSAN: kernel-infoleak in
    instrument_copy_to_user include/linux/instrumented.h:114 [inline] BUG: KMSAN: kernel-infoleak in
    _copy_to_user+0xbc/0x100 lib/usercopy.c:40 instrument_copy_to_user include/linux/instrumented.h:114
    [inline] _copy_to_user+0xbc/0x100 lib/usercopy.c:40 copy_to_user include/linux/uaccess.h:191 [inline]
    do_sys_name_to_handle fs/fhandle.c:73 [inline] __do_sys_name_to_handle_at fs/fhandle.c:112 [inline]
    __se_sys_name_to_handle_at+0x949/0xb10 fs/fhandle.c:94 __x64_sys_name_to_handle_at+0xe4/0x140
    fs/fhandle.c:94 ... Uninit was created at: slab_post_alloc_hook+0x129/0xa70 mm/slab.h:768 slab_alloc_node
    mm/slub.c:3478 [inline] __kmem_cache_alloc_node+0x5c9/0x970 mm/slub.c:3517 __do_kmalloc_node
    mm/slab_common.c:1006 [inline] __kmalloc+0x121/0x3c0 mm/slab_common.c:1020 kmalloc
    include/linux/slab.h:604 [inline] do_sys_name_to_handle fs/fhandle.c:39 [inline]
    __do_sys_name_to_handle_at fs/fhandle.c:112 [inline] __se_sys_name_to_handle_at+0x441/0xb10
    fs/fhandle.c:94 __x64_sys_name_to_handle_at+0xe4/0x140 fs/fhandle.c:94 ... Bytes 18-19 of 20 are
    uninitialized Memory access of size 20 starts at ffff888128a46380 Data copied to user address
    0000000020000240' Per Chuck Lever's suggestion, use kzalloc() instead of kmalloc() to solve the
    problem.(CVE-2024-26901)

    In the Linux kernel, the following vulnerability has been resolved: NFS: Don't corrupt the value of
    pg_bytes_written in nfs_do_recoalesce() The value of mirror-pg_bytes_written should only be updated
    after a successful attempt to flush out the requests on the list.(CVE-2021-47166)

    In the Linux kernel, the following vulnerability has been resolved: cifs: fix underflow in
    parse_server_interfaces() In this loop, we step through the buffer and after each item we check if the
    size_left is greater than the minimum size we need. However, the problem is that 'bytes_left' is type
    ssize_t while sizeof() is type size_t. That means that because of type promotion, the comparison is done
    as an unsigned and if we have negative bytes left the loop continues instead of ending.(CVE-2024-26828)

    In the Linux kernel, the following vulnerability has been resolved: quota: Fix potential NULL pointer
    dereference Below race may cause NULL pointer dereference P1 P2 dquot_free_inode quota_off drop_dquot_ref
    remove_dquot_ref dquots = i_dquot(inode) dquots = i_dquot(inode) srcu_read_lock dquots[cnt]) != NULL (1)
    dquots[type] = NULL (2) spin_lock(dquots[cnt]-dq_dqb_lock) (3) .... If dquot_free_inode(or other
    routines) checks inode's quota pointers (1) before quota_off sets it to NULL(2) and use it (3) after that,
    NULL pointer dereference will be triggered. So let's fix it by using a temporary pointer to avoid this
    issue.(CVE-2024-26878)

    In the Linux kernel, the following vulnerability has been resolved: media: pvrusb2: fix uaf in
    pvr2_context_set_notify(CVE-2024-26875)

    In the Linux kernel, the following vulnerability has been resolved: scsi: mpt3sas: Fix use-after-free
    warning Fix the following use-after-free warning which is observed during controller reset: refcount_t:
    underflow; use-after-free.(CVE-2022-48695)

    In the Linux kernel, the following vulnerability has been resolved: media: ttpci: fix two memleaks in
    budget_av_attach When saa7146_register_device and saa7146_vv_init fails, budget_av_attach should free the
    resources it allocates, like the error-handling of ttpci_budget_init does. Besides, there are two fixme
    comment refers to such deallocations.(CVE-2024-27075)

    In the Linux kernel, the following vulnerability has been resolved: fs: sysfs: Fix reference leak in
    sysfs_break_active_protection() The sysfs_break_active_protection() routine has an obvious reference leak
    in its error path. If the call to kernfs_find_and_get() fails then kn will be NULL, so the companion
    sysfs_unbreak_active_protection() routine won't get called (and would only cause an access violation by
    trying to dereference kn-parent if it was called). As a result, the reference to kobj acquired at the
    start of the function will never be released. Fix the leak by adding an explicit kobject_put() call when
    kn is NULL.(CVE-2024-26993)

    In the Linux kernel, the following vulnerability has been resolved: moxart: fix potential use-after-free
    on remove path It was reported that the mmc host structure could be accessed after it was freed in
    moxart_remove(), so fix this by saving the base register of the device and using it instead of the pointer
    dereference.(CVE-2022-48626)

    In the Linux kernel, the following vulnerability has been resolved: vt: fix memory overlapping when
    deleting chars in the buffer A memory overlapping copy occurs when deleting a long line. This memory
    overlapping copy can cause data corruption when scr_memcpyw is optimized to memcpy because memcpy does not
    ensure its behavior if the destination buffer overlaps with the source buffer. The line buffer is not
    always broken, because the memcpy utilizes the hardware acceleration, whose result is not deterministic.
    Fix this problem by using replacing the scr_memcpyw with scr_memmovew.(CVE-2022-48627)

    In the Linux kernel, the following vulnerability has been resolved: ext4: fix bug in extents parsing when
    eh_entries == 0 and eh_depth  0 When walking through an inode extents, the ext4_ext_binsearch_idx()
    function assumes that the extent header has been previously validated. However, there are no checks that
    verify that the number of entries (eh-eh_entries) is non-zero when depth is  0.(CVE-2022-48631)

    In the Linux kernel, the following vulnerability has been resolved: mm/slub: fix to return errno if
    kmalloc() fails In create_unique_id(), kmalloc(, GFP_KERNEL) can fail due to out-of-memory, if it fails,
    return errno correctly rather than triggering panic via BUG_ON(); kernel BUG at
    mm/slub.c:5893!(CVE-2022-48659)

    In the Linux kernel, the following vulnerability has been resolved:NFS: fix an incorrect limit in
    filelayout_decode_layout().The 'sizeof(struct nfs_fh)' is two bytes too large and could lead to memory
    corruption.  It should be NFS_MAXFHSIZE because that's the sizethe -data[] buffer. I reversed the size
    of the arguments to put the variable on the left.(CVE-2021-47168)

    In the Linux kernel, the following vulnerability has been resolved: crypto: qat - resolve race condition
    during AER recovery During the PCI AER system's error recovery process, the kernel driver may encounter a
    race condition with freeing the reset_data structure's memory. If the device restart will take more than
    10 seconds the function scheduling that restart will exit due to a timeout, and the reset_data structure
    will be freed. However, this data structure is used for completion notification after the restart is
    completed, which leads to a UAF bug.(CVE-2024-26974)

    In the Linux kernel, the following vulnerability has been resolved: fat: fix uninitialized field in
    nostale filehandles When fat_encode_fh_nostale() encodes file handle without a parent it stores only first
    10 bytes of the file handle. However the length of the file handle must be a multiple of 4 so the file
    handle is actually 12 bytes long and the last two bytes remain uninitialized. This is not great at we
    potentially leak uninitialized information with the handle to userspace. Properly initialize the full
    handle length.(CVE-2024-26973)

    In the Linux kernel, the following vulnerability has been resolved: netfilter: nf_tables: disallow
    anonymous set with timeout flag Anonymous sets are never used with timeout from userspace, reject this.
    Exception to this rule is NFT_SET_EVAL to ensure legacy meters still work.(CVE-2024-26642)

    In the Linux kernel, the following vulnerability has been resolved: xen/events: close evtchn after mapping
    cleanup shutdown_pirq and startup_pirq are not taking the irq_mapping_update_lock because they can't due
    to lock inversion. Both are called with the irq_desc-lock being taking. The lock order, however, is
    first irq_mapping_update_lock and then irq_desc-lock. This opens multiple races: - shutdown_pirq can be
    interrupted by a function that allocates an event channel: CPU0 CPU1 shutdown_pirq { xen_evtchn_close(e)
    __startup_pirq { EVTCHNOP_bind_pirq - returns just freed evtchn e set_evtchn_to_irq(e, irq) }
    xen_irq_info_cleanup() { set_evtchn_to_irq(e, -1) } } Assume here event channel e refers here to the same
    event channel number. After this race the evtchn_to_irq mapping for e is invalid (-1). - __startup_pirq
    races with __unbind_from_irq in a similar way. Because __startup_pirq doesn't take irq_mapping_update_lock
    it can grab the evtchn that __unbind_from_irq is currently freeing and cleaning up. In this case even
    though the event channel is allocated, its mapping can be unset in evtchn_to_irq. The fix is to first
    cleanup the mappings and then close the event channel. In this way, when an event channel gets allocated
    it's potential previous evtchn_to_irq mappings are guaranteed to be unset already. This is also the
    reverse order of the allocation where first the event channel is allocated and then the mappings are
    setup. On a 5.10 kernel prior to commit 3fcdaf3d7634 ('xen/events: modify internal [un]bind interfaces'),
    we hit a BUG like the following during probing of NVMe devices. The issue is that during
    nvme_setup_io_queues, pci_free_irq is called for every device which results in a call to shutdown_pirq.
    With many nvme devices it's therefore likely to hit this race during boot because there will be multiple
    calls to shutdown_pirq and startup_pirq are running potentially in parallel.(CVE-2024-26687)

    In the Linux kernel, the following vulnerability has been resolved: mac802154: fix llsec key resources
    release in mac802154_llsec_key_del mac802154_llsec_key_del() can free resources of a key directly without
    following the RCU rules for waiting before the end of a grace period. This may lead to use-after-free in
    case llsec_lookup_key() is traversing the list of keys in parallel with a key deletion: refcount_t:
    addition on 0; use-after-free.(CVE-2024-26961)

    In the Linux kernel, the following vulnerability has been resolved: netfilter: nf_tables: fix memleak in
    map from abort path The delete set command does not rely on the transaction object for element removal,
    therefore, a combination of delete element + delete set from the abort path could result in restoring
    twice the refcount of the mapping. Check for inactive element in the next generation for the delete
    element command in the abort path, skip restoring state if next generation bit has been already cleared.
    This is similar to the activate logic using the set walk iterator.(CVE-2024-27011)

    In the Linux kernel, the following vulnerability has been resolved: USB: core: Fix deadlock in
    usb_deauthorize_interface() Among the attribute file callback routines in drivers/usb/core/sysfs.c, the
    interface_authorized_store() function is the only one which acquires a device lock on an ancestor device:
    It calls usb_deauthorize_interface(), which locks the interface's parent USB device. The will lead to
    deadlock if another process already owns that lock and tries to remove the interface, whether through a
    configuration change or because the device has been disconnected. As part of the removal procedure,
    device_del() waits for all ongoing sysfs attribute callbacks to complete. But usb_deauthorize_interface()
    can't complete until the device lock has been released, and the lock won't be released until the removal
    has finished. The mechanism provided by sysfs to prevent this kind of deadlock is to use the
    sysfs_break_active_protection() function, which tells sysfs not to wait for the attribute
    callback.(CVE-2024-26934)

    In the Linux kernel, the following vulnerability has been resolved: tun: limit printing rate when illegal
    packet received by tun dev vhost_worker will call tun call backs to receive packets. If too many illegal
    packets arrives, tun_do_read will keep dumping packet contents. When console is enabled, it will costs
    much more cpu time to dump packet and soft lockup will be detected. net_ratelimit mechanism can be used to
    limit the dumping rate.(CVE-2024-27013)

    In the Linux kernel, the following vulnerability has been resolved:SUNRPC: fix some memleaks in
    gssx_dec_option_array.The creds and oa-data need to be freed in the error-handling paths after their
    allocation. So this patch add these deallocations in the corresponding paths.(CVE-2024-27388)

    In the Linux kernel, the following vulnerability has been resolved: netfilter: nf_tables: Fix potential
    data-race in __nft_obj_type_get() nft_unregister_obj() can concurrent with __nft_obj_type_get(), and there
    is not any protection when iterate over nf_tables_objects list in __nft_obj_type_get(). Therefore, there
    is potential data-race of nf_tables_objects list entry. Use list_for_each_entry_rcu() to iterate over
    nf_tables_objects list in __nft_obj_type_get(), and use rcu_read_lock() in the caller nft_obj_type_get()
    to protect the entire type query process.(CVE-2024-27019)

    In the Linux kernel, the following vulnerability has been resolved: net/sched: Fix mirred deadlock on
    device recursion When the mirred action is used on a classful egress qdisc and a packet is mirrored or
    redirected to self we hit a qdisc lock deadlock.(CVE-2024-27010)

    In the Linux kernel, the following vulnerability has been resolved: cgroup: Add missing cpus_read_lock()
    to cgroup_attach_task_all() syzbot is hitting percpu_rwsem_assert_held(cpu_hotplug_lock) warning at
    cpuset_attach() [1], for commit 4f7e7236435ca0ab ('cgroup: Fix threadgroup_rwsem - cpus_read_lock()
    deadlock') missed that cpuset_attach() is also called from cgroup_attach_task_all(). Add cpus_read_lock()
    like what cgroup_procs_write_start() does.(CVE-2022-48671)

    In the Linux kernel, the following vulnerability has been resolved: net/sched: act_mirred: use the backlog
    for mirred ingress The test Davide added in commit ca22da2fbd69 ('act_mirred: use the backlog for nested
    calls to mirred ingress') hangs our testing VMs every 10 or so runs, with the familiar tcp_v4_rcv -
    tcp_v4_rcv deadlock reported by lockdep. The problem as previously described by Davide (see Link) is that
    if we reverse flow of traffic with the redirect (egress - ingress) we may reach the same socket which
    generated the packet. And we may still be holding its socket lock. The common solution to such deadlocks
    is to put the packet in the Rx backlog, rather than run the Rx path inline. Do that for all egress -
    ingress reversals, not just once we started to nest mirred calls. In the past there was a concern that the
    backlog indirection will lead to loss of error reporting / less accurate stats. But the current workaround
    does not seem to address the issue.(CVE-2024-26740)

    In the Linux kernel, the following vulnerability has been resolved: RDMA/srp: Do not call scsi_done() from
    srp_abort() After scmd_eh_abort_handler() has called the SCSI LLD eh_abort_handler callback, it performs
    one of the following actions: * Call scsi_queue_insert(). * Call scsi_finish_command(). * Call
    scsi_eh_scmd_add(). Hence, SCSI abort handlers must not call scsi_done(). Otherwise all the above actions
    would trigger a use-after-free. Hence remove the scsi_done() call from srp_abort(). Keep the
    srp_free_req() call before returning SUCCESS because we may not see the command again if SUCCESS is
    returned.(CVE-2023-52515)

    In the Linux kernel, the following vulnerability has been resolved: wifi: ath9k: Fix potential array-
    index-out-of-bounds read in ath9k_htc_txstatus() Fix an array-index-out-of-bounds read in
    ath9k_htc_txstatus(). The bug occurs when txs-cnt, data from a URB provided by a USB device, is bigger
    than the size of the array txs-txstatus, which is HTC_MAX_TX_STATUS. WARN_ON() already checks it, but
    there is no bug handling code after the check. Make the function return if that is the case. Found by a
    modified version of syzkaller. UBSAN: array-index-out-of-bounds in htc_drv_txrx.c index 13 is out of range
    for type '__wmi_event_txstatus [12]' Call Trace: ath9k_htc_txstatus ath9k_wmi_event_tasklet
    tasklet_action_common __do_softirq irq_exit_rxu sysvec_apic_timer_interrupt(CVE-2023-52594)

    In the Linux kernel, the following vulnerability has been resolved: bpf: Fix hashtab overflow check on
    32-bit arches The hashtab code relies on roundup_pow_of_two() to compute the number of hash buckets, and
    contains an overflow check by checking if the resulting value is 0. However, on 32-bit arches, the roundup
    code itself can overflow by doing a 32-bit left-shift of an unsigned long value, which is undefined
    behaviour, so it is not guaranteed to truncate neatly. This was triggered by syzbot on the DEVMAP_HASH
    type, which contains the same check, copied from the hashtab code. So apply the same fix to hashtab, by
    moving the overflow check to before the roundup.(CVE-2024-26884)

    In the Linux kernel, the following vulnerability has been resolved: scsi: target: core: Add TMF to
    tmr_list handling An abort that is responded to by iSCSI itself is added to tmr_list but does not go to
    target core. A LUN_RESET that goes through tmr_list takes a refcounter on the abort and waits for
    completion. However, the abort will be never complete because it was not started in target
    core.(CVE-2024-26845)

    In the Linux kernel, the following vulnerability has been resolved: net/mlx5e: Prevent deadlock while
    disabling aRFS When disabling aRFS under the `priv-state_lock`, any scheduled aRFS works are canceled
    using the `cancel_work_sync` function, which waits for the work to end if it has already started. However,
    while waiting for the work handler, the handler will try to acquire the `state_lock` which is already
    acquired. The worker acquires the lock to delete the rules if the state is down, which is not the worker's
    responsibility since disabling aRFS deletes the rules. Add an aRFS state variable, which indicates whether
    the aRFS is enabled and prevent adding rules when the aRFS is disabled.(CVE-2024-27014)

    In the Linux kernel, the following vulnerability has been resolved: hwrng: core - Fix page fault dead lock
    on mmap-ed hwrng There is a dead-lock in the hwrng device read path. This triggers when the user reads
    from /dev/hwrng into memory also mmap-ed from /dev/hwrng. The resulting page fault triggers a recursive
    read which then dead-locks. Fix this by using a stack buffer when calling copy_to_user.(CVE-2023-52615)

    In the Linux kernel, the following vulnerability has been resolved: media: pvrusb2: fix use after free on
    context disconnection Upon module load, a kthread is created targeting the pvr2_context_thread_func
    function, which may call pvr2_context_destroy and thus call kfree() on the context object. However, that
    might happen before the usb hub_event handler is able to notify the driver. This patch adds a sanity check
    before the invalid read reported by syzbot, within the context disconnection call stack.(CVE-2023-52445)

    In the Linux kernel, the following vulnerability has been resolved: nvmet-tcp: Fix a kernel panic when
    host sends an invalid H2C PDU length If the host sends an H2CData command with an invalid DATAL, the
    kernel may crash in nvmet_tcp_build_pdu_iovec(). Unable to handle kernel NULL pointer dereference at
    virtual address 0000000000000000 lr : nvmet_tcp_io_work+0x6ac/0x718 [nvmet_tcp] Call trace:
    process_one_work+0x174/0x3c8 worker_thread+0x2d0/0x3e8 kthread+0x104/0x110 Fix the bug by raising a fatal
    error if DATAL isn't coherent with the packet size. Also, the PDU length should never exceed the
    MAXH2CDATA parameter which has been communicated to the host in nvmet_tcp_handle_icreq().(CVE-2023-52454)

    In the Linux kernel, the following vulnerability has been resolved: llc: Drop support for ETH_P_TR_802_2.
    syzbot reported an uninit-value bug below. [0] llc supports ETH_P_802_2 (0x0004) and used to support
    ETH_P_TR_802_2 (0x0011), and syzbot abused the latter to trigger the bug. write$tun(r0,
    (0x7f0000000040)={@val={0x0, 0x11}, @val, @mpls={[], @llc={@snap={0xaa, 0x1, ')', '90e5dd'}}}}, 0x16)
    llc_conn_handler() initialises local variables {saddr,daddr}.mac based on skb in
    llc_pdu_decode_sa()/llc_pdu_decode_da() and passes them to __llc_lookup(). However, the initialisation is
    done only when skb-protocol is htons(ETH_P_802_2), otherwise, __llc_lookup_established() and
    __llc_lookup_listener() will read garbage. The missing initialisation existed prior to commit 211ed865108e
    ('net: delete all instances of special processing for token ring'). It removed the part to kick out the
    token ring stuff but forgot to close the door allowing ETH_P_TR_802_2 packets to sneak into llc_rcv().
    Let's remove llc_tr_packet_type and complete the deprecation.(CVE-2024-26635)

    In the Linux kernel, the following vulnerability has been resolved: RDMA/srpt: Support specifying the
    srpt_service_guid parameter Make loading ib_srpt with this parameter set work. The current behavior is
    that setting that parameter while loading the ib_srpt kernel module triggers the following kernel crash:
    BUG: kernel NULL pointer dereference, address: 0000000000000000(CVE-2024-26744)

    In the Linux kernel, the following vulnerability has been resolved: KVM: Always flush async #PF workqueue
    when vCPU is being destroyed Always flush the per-vCPU async #PF workqueue when a vCPU is clearing its
    completion queue, e.g. when a VM and all its vCPUs is being destroyed. KVM must ensure that none of its
    workqueue callbacks is running when the last reference to the KVM _module_ is put. Gifting a reference to
    the associated VM prevents the workqueue callback from dereferencing freed vCPU/VM memory, but does not
    prevent the KVM module from being unloaded before the callback completes. Drop the misguided VM refcount
    gifting, as calling kvm_put_kvm() from async_pf_execute() if kvm_put_kvm() flushes the async #PF workqueue
    will result in deadlock. async_pf_execute() can't return until kvm_put_kvm() finishes, and kvm_put_kvm()
    can't return until async_pf_execute() finishes: WARNING: CPU: 8 PID: 251 at virt/kvm/kvm_main.c:1435
    kvm_put_kvm+0x2d/0x320 [kvm] Modules linked in: vhost_net vhost vhost_iotlb tap kvm_intel kvm irqbypass
    CPU: 8 PID: 251 Comm: kworker/8:1 Tainted: G W 6.6.0-rc1-e7af8d17224a-x86/gmem-vm #119 Hardware name: QEMU
    Standard PC (Q35 + ICH9, 2009), BIOS 0.0.0 02/06/2015 Workqueue: events async_pf_execute [kvm] RIP:
    0010:kvm_put_kvm+0x2d/0x320 [kvm](CVE-2024-26976)

    In the Linux kernel, the following vulnerability has been resolved: RDMA/qedr: Fix qedr_create_user_qp
    error flow Avoid the following warning by making sure to free the allocated resources in case that
    qedr_init_user_queue() fail.(CVE-2024-26743)

    In the Linux kernel, the following vulnerability has been resolved: Squashfs: check the inode number is
    not the invalid value of zero Syskiller has produced an out of bounds access in fill_meta_index(). That
    out of bounds access is ultimately caused because the inode has an inode number with the invalid value of
    zero, which was not checked. The reason this causes the out of bounds access is due to following sequence
    of events: 1. Fill_meta_index() is called to allocate (via empty_meta_index()) and fill a metadata index.
    It however suffers a data read error and aborts, invalidating the newly returned empty metadata index. It
    does this by setting the inode number of the index to zero, which means unused (zero is not a valid inode
    number). 2. When fill_meta_index() is subsequently called again on another read operation,
    locate_meta_index() returns the previous index because it matches the inode number of 0. Because this
    index has been returned it is expected to have been filled, and because it hasn't been, an out of bounds
    access is performed. This patch adds a sanity check which checks that the inode number is not zero when
    the inode is created and returns -EINVAL if it is.(CVE-2024-26982)

    In the Linux kernel, the following vulnerability has been resolved: media: edia: dvbdev: fix a use-after-
    free In dvb_register_device, *pdvbdev is set equal to dvbdev, which is freed in several error-handling
    paths. However, *pdvbdev is not set to NULL after dvbdev's deallocation, causing use-after-frees in many
    places, for example, in the following call chain: budget_register |- dvb_dmxdev_init |-
    dvb_register_device |- dvb_dmxdev_release |- dvb_unregister_device |- dvb_remove_device |-
    dvb_device_put |- kref_put When calling dvb_unregister_device, dmxdev-dvbdev (i.e. *pdvbdev in
    dvb_register_device) could point to memory that had been freed in dvb_register_device. Thereafter, this
    pointer is transferred to kref_put and triggering a use-after-free.(CVE-2024-27043)

    In the Linux kernel, the following vulnerability has been resolved: inet: read sk-sk_family once in
    inet_recv_error() inet_recv_error() is called without holding the socket lock. IPv6 socket could mutate to
    IPv4 with IPV6_ADDRFORM socket option and trigger a KCSAN warning.(CVE-2024-26679)

    In the Linux kernel, the following vulnerability has been resolved: ext4: avoid allocating blocks from
    corrupted group in ext4_mb_find_by_goal() Places the logic for checking if the group's block bitmap is
    corrupt under the protection of the group lock to avoid allocating blocks from the group with a corrupted
    block bitmap.(CVE-2024-26772)

    In the Linux kernel, the following vulnerability has been resolved: net/sched: act_mirred: don't override
    retval if we already lost the skb If we're redirecting the skb, and haven't called tcf_mirred_forward(),
    yet, we need to tell the core to drop the skb by setting the retcode to SHOT. If we have called
    tcf_mirred_forward(), however, the skb is out of our hands and returning SHOT will lead to UaF. Move the
    retval override to the error path which actually need it.(CVE-2024-26739)

    In the Linux kernel, the following vulnerability has been resolved: x86/kvm: Teardown PV features on boot
    CPU as well Various PV features (Async PF, PV EOI, steal time) work through memory shared with hypervisor
    and when we restore from hibernation we must properly teardown all these features to make sure hypervisor
    doesn't write to stale locations after we jump to the previously hibernated kernel (which can try to place
    anything there). For secondary CPUs the job is already done by kvm_cpu_down_prepare(), register syscore
    ops to do the same for boot CPU.(CVE-2021-47112)

    In the Linux kernel, the following vulnerability has been resolved: ppp_async: limit MRU to 64K syzbot
    triggered a warning [1] in __alloc_pages(): WARN_ON_ONCE_GFP(order  MAX_PAGE_ORDER, gfp) Willem fixed a
    similar issue in commit c0a2a1b0d631 ('ppp: limit MRU to 64K') Adopt the same sanity check for
    ppp_async_ioctl(PPPIOCSMRU)(CVE-2024-26675)

    In the Linux kernel, the following vulnerability has been resolved: md: fix kmemleak of rdev-serial If
    kobject_add() is fail in bind_rdev_to_array(), 'rdev-serial' will be alloc not be freed, and kmemleak
    occurs. unreferenced object 0xffff88815a350000 (size 49152): comm 'mdadm', pid 789, jiffies 4294716910 hex
    dump (first 32 bytes): 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ................ 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 ................ backtrace (crc f773277a): [0000000058b0a453]
    kmemleak_alloc+0x61/0xe0 [00000000366adf14] __kmalloc_large_node+0x15e/0x270
    [000000002e82961b] __kmalloc_node.cold+0x11/0x7f [00000000f206d60a] kvmalloc_node+0x74/0x150
    [0000000034bf3363] rdev_init_serial+0x67/0x170 [0000000010e08fe9]
    mddev_create_serial_pool+0x62/0x220 [00000000c3837bf0] bind_rdev_to_array+0x2af/0x630
    [0000000073c28560] md_add_new_disk+0x400/0x9f0 [00000000770e30ff] md_ioctl+0x15bf/0x1c10
    [000000006cfab718] blkdev_ioctl+0x191/0x3f0 [0000000085086a11] vfs_ioctl+0x22/0x60
    [0000000018b656fe] __x64_sys_ioctl+0xba/0xe0 [00000000e54e675e] do_syscall_64+0x71/0x150
    [000000008b0ad622] entry_SYSCALL_64_after_hwframe+0x6c/0x74(CVE-2024-26900)

    In the Linux kernel, the following vulnerability has been resolved: nvme-fc: do not wait in vain when
    unloading module The module exit path has race between deleting all controllers and freeing 'left over
    IDs'. To prevent double free a synchronization between nvme_delete_ctrl and ida_destroy has been added by
    the initial commit. There is some logic around trying to prevent from hanging forever in
    wait_for_completion, though it does not handling all cases. E.g. blktests is able to reproduce the
    situation where the module unload hangs forever. If we completely rely on the cleanup code executed from
    the nvme_delete_ctrl path, all IDs will be freed eventually. This makes calling ida_destroy unnecessary.
    We only have to ensure that all nvme_delete_ctrl code has been executed before we leave
    nvme_fc_exit_module. This is done by flushing the nvme_delete_wq workqueue. While at it, remove the unused
    nvme_fc_wq workqueue too.(CVE-2024-26846)

    In the Linux kernel, the following vulnerability has been resolved: net/ipv6: avoid possible UAF in
    ip6_route_mpath_notify() syzbot found another use-after-free in ip6_route_mpath_notify() [1] Commit
    f7225172f25a ('net/ipv6: prevent use after free in ip6_route_mpath_notify') was not able to fix the root
    cause. We need to defer the fib6_info_release() calls after ip6_route_mpath_notify(), in the cleanup
    phase.(CVE-2024-26852)

    In the Linux kernel, the following vulnerability has been resolved: block: add check that partition length
    needs to be aligned with block size Before calling add partition or resize partition, there is no check on
    whether the length is aligned with the logical block size. If the logical block size of the disk is larger
    than 512 bytes, then the partition size maybe not the multiple of the logical block size, and when the
    last sector is read, bio_truncate() will adjust the bio size, resulting in an IO error if the size of the
    read command is smaller than the logical block size.If integrity data is supported, this will also result
    in a null pointer dereference when calling bio_integrity_free.(CVE-2023-52458)

    In the Linux kernel, the following vulnerability has been resolved: geneve: make sure to pull inner header
    in geneve_rx() syzbot triggered a bug in geneve_rx() [1] Issue is similar to the one I fixed in commit
    8d975c15c0cd ('ip6_tunnel: make sure to pull inner header in __ip6_tnl_rcv()') We have to save skb-
    network_header in a temporary variable in order to be able to recompute the network_header pointer
    after a pskb_inet_may_pull() call. pskb_inet_may_pull() makes sure the needed headers are in skb-
    head.(CVE-2024-26857)

    In the Linux kernel, the following vulnerability has been resolved: net/bnx2x: Prevent access to a freed
    page in page_pool Fix race condition leading to system crash during EEH error handling During EEH error
    recovery, the bnx2x driver's transmit timeout logic could cause a race condition when handling reset
    tasks. The bnx2x_tx_timeout() schedules reset tasks via bnx2x_sp_rtnl_task(), which ultimately leads to
    bnx2x_nic_unload(). In bnx2x_nic_unload() SGEs are freed using bnx2x_free_rx_sge_range(). However, this
    could overlap with the EEH driver's attempt to reset the device using bnx2x_io_slot_reset(), which also
    tries to free SGEs.(CVE-2024-26859)

    In the Linux kernel, the following vulnerability has been resolved: RDMA/srpt: Do not register event
    handler until srpt device is fully setup Upon rare occasions, KASAN reports a use-after-free Write in
    srpt_refresh_port(). This seems to be because an event handler is registered before the srpt device is
    fully setup and a race condition upon error may leave a partially setup event handler in place. Instead,
    only register the event handler after srpt device initialization is complete.(CVE-2024-26872)

    In the Linux kernel, the following vulnerability has been resolved: Input: powermate - fix use-after-free
    in powermate_config_complete syzbot has found a use-after-free bug [1] in the powermate driver. This
    happens when the device is disconnected, which leads to a memory free from the powermate_device struct.
    When an asynchronous control message completes after the kfree and its callback is invoked, the lock does
    not exist anymore and hence the bug. Use usb_kill_urb() on pm-config to cancel any in-progress requests
    upon device disconnection.(CVE-2023-52475)

    In the Linux kernel, the following vulnerability has been resolved: net: ice: Fix potential NULL pointer
    dereference in ice_bridge_setlink() The function ice_bridge_setlink() may encounter a NULL pointer
    dereference if nlmsg_find_attr() returns NULL and br_spec is dereferenced subsequently in
    nla_for_each_nested(). To address this issue, add a check to ensure that br_spec is not NULL before
    proceeding with the nested attribute iteration.(CVE-2024-26855)

    In the Linux kernel, the following vulnerability has been resolved: netfilter: nft_limit: reject
    configurations that cause integer overflow Reject bogus configs where internal token counter wraps around.
    This only occurs with very very large requests, such as 17gbyte/s. Its better to reject this rather than
    having incorrect ratelimit.(CVE-2024-26668)

    In the Linux kernel, the following vulnerability has been resolved: perf/x86/lbr: Filter vsyscall
    addresses We found that a panic can occur when a vsyscall is made while LBR sampling is active. If the
    vsyscall is interrupted (NMI) for perf sampling, this call sequence can occur (most recent at top):
    __insn_get_emulate_prefix() insn_get_emulate_prefix() insn_get_prefixes() insn_get_opcode()
    decode_branch_type() get_branch_type() intel_pmu_lbr_filter() intel_pmu_handle_irq()
    perf_event_nmi_handler() Within __insn_get_emulate_prefix() at frame 0, a macro is called:
    peek_nbyte_next(insn_byte_t, insn, i) Within this macro, this dereference occurs: (insn)-next_byte
    Inspecting registers at this point, the value of the next_byte field is the address of the vsyscall made,
    for example the location of the vsyscall version of gettimeofday() at 0xffffffffff600000. The access to an
    address in the vsyscall region will trigger an oops due to an unhandled page fault. To fix the bug,
    filtering for vsyscalls can be done when determining the branch type. This patch will return a 'none'
    branch if a kernel address if found to lie in the vsyscall region.(CVE-2023-52476)

    In the Linux kernel, the following vulnerability has been resolved: fs/proc: do_task_stat: use sig-
    stats_lock to gather the threads/children stats lock_task_sighand() can trigger a hard lockup. If
    NR_CPUS threads call do_task_stat() at the same time and the process has NR_THREADS, it will spin with
    irqs disabled O(NR_CPUS * NR_THREADS) time. Change do_task_stat() to use sig-stats_lock to gather the
    statistics outside of -siglock protected section, in the likely case this code will run
    lockless.(CVE-2024-26686)

    In the Linux kernel, the following vulnerability has been resolved: tipc: skb_linearize the head skb when
    reassembling msgs It's not a good idea to append the frag skb to a skb's frag_list if the frag_list
    already has skbs from elsewhere, such as this skb was created by pskb_copy() where the frag_list was
    cloned (all the skbs in it were skb_get'ed) and shared by multiple skbs. However, the new appended frag
    skb should have been only seen by the current skb. Otherwise, it will cause use after free crashes as this
    appended frag skb are seen by multiple skbs but it only got skb_get called once. The same thing happens
    with a skb updated by pskb_may_pull() with a skb_cloned skb.(CVE-2021-47162)

    In the Linux kernel, the following vulnerability has been resolved: tipc: wait and exit until all work
    queues are done On some host, a crash could be triggered simply by repeating these commands several times:
    # modprobe tipc # tipc bearer enable media udp name UDP1 localip 127.0.0.1 # rmmod tipc [] BUG: unable to
    handle kernel paging request at ffffffffc096bb00 [] Workqueue: events 0xffffffffc096bb00 [] Call Trace: []
    ? process_one_work+0x1a7/0x360 [] ? worker_thread+0x30/0x390 [] ? create_worker+0x1a0/0x1a0 [] ?
    kthread+0x116/0x130 [] ? kthread_flush_work_fn+0x10/0x10 [] ? ret_from_fork+0x35/0x40 When removing the
    TIPC module, the UDP tunnel sock will be delayed to release in a work queue as sock_release() can't be
    done in rtnl_lock(). If the work queue is schedule to run after the TIPC module is removed, kernel will
    crash as the work queue function cleanup_beareri() code no longer exists when trying to invoke it. To fix
    it, this patch introduce a member wq_count in tipc_net to track the numbers of work queues in schedule,
    and wait and exit until all work queues are done in tipc_exit_net().(CVE-2021-47163)

    In the Linux kernel, the following vulnerability has been resolved: drm/amdgpu: Fix a use-after-free looks
    like we forget to set ttm-sg to NULL.(CVE-2021-47142)

    In the Linux kernel, the following vulnerability has been resolved: drm/amd/amdgpu: fix refcount leak
    [Why] the gem object rfb-base.obj[0] is get according to num_planes in amdgpufb_create, but is not put
    according to num_planes [How] put rfb-base.obj[0] in amdgpu_fbdev_destroy according to
    num_planes(CVE-2021-47144)

    In the Linux kernel, the following vulnerability has been resolved: USB: usbfs: Don't WARN about
    excessively large memory allocations Syzbot found that the kernel generates a WARNing if the user tries to
    submit a bulk transfer through usbfs with a buffer that is way too large. This isn't a bug in the kernel;
    it's merely an invalid request from the user and the usbfs code does handle it correctly. In theory the
    same thing can happen with async transfers, or with the packet descriptor table for isochronous transfers.
    To prevent the MM subsystem from complaining about these bad allocation requests, add the __GFP_NOWARN
    flag to the kmalloc calls for these buffers.(CVE-2021-47170)

    In the Linux kernel, the following vulnerability has been resolved: misc/uss720: fix memory leak in
    uss720_probe uss720_probe forgets to decrease the refcount of usbdev in uss720_probe. Fix this by
    decreasing the refcount of usbdev by usb_put_dev.(CVE-2021-47173)

    In the Linux kernel, the following vulnerability has been resolved: IB/hfi1: Fix a memleak in
    init_credit_return When dma_alloc_coherent fails to allocate dd-cr_base[i].va, init_credit_return
    should deallocate dd-cr_base and dd-cr_base[i] that allocated before. Or those resources would be
    never freed and a memleak is triggered.(CVE-2024-26839)

    In the Linux kernel, the following vulnerability has been resolved: ext4: fix double-free of blocks due to
    wrong extents moved_len In ext4_move_extents(), moved_len is only updated when all moves are successfully
    executed, and only discards orig_inode and donor_inode preallocations when moved_len is not zero. When the
    loop fails to exit after successfully moving some extents, moved_len is not updated and remains at 0, so
    it does not discard the preallocations. If the moved extents overlap with the preallocated extents, the
    overlapped extents are freed twice in ext4_mb_release_inode_pa() and ext4_process_freed_data() (as
    described in commit 94d7c16cbbbd ('ext4: Fix double-free of blocks with EXT4_IOC_MOVE_EXT')), and bb_free
    is incremented twice. Hence when trim is executed, a zero-division bug is triggered in
    mb_update_avg_fragment_size() because bb_free is not zero and bb_fragments is zero. Therefore, update
    move_len after each extent move to avoid the issue.(CVE-2024-26704)

    In the Linux kernel, the following vulnerability has been resolved: netfilter: nf_conntrack_h323: Add
    protection for bmp length out of range UBSAN load reports an exception of BRK#5515 SHIFT_ISSUE:Bitwise
    shifts that are out of bounds for their data type.(CVE-2024-26851)

    In the Linux kernel, the following vulnerability has been resolved: KVM: s390: fix setting of fpc register
    kvm_arch_vcpu_ioctl_set_fpu() allows to set the floating point control (fpc) register of a guest cpu. The
    new value is tested for validity by temporarily loading it into the fpc register. This may lead to
    corruption of the fpc register of the host process: if an interrupt happens while the value is temporarily
    loaded into the fpc register, and within interrupt context floating point or vector registers are used,
    the current fp/vx registers are saved with save_fpu_regs() assuming they belong to user space and will be
    loaded into fp/vx registers when returning to user space. test_fp_ctl() restores the original user space /
    host process fpc register value, however it will be discarded, when returning to user space. In result the
    host process will incorrectly continue to run with the value that was supposed to be used for a guest cpu.
    Fix this by simply removing the test. There is another test right before the SIE context is entered which
    will handles invalid values. This results in a change of behaviour: invalid values will now be accepted
    instead of that the ioctl fails with -EINVAL. This seems to be acceptable, given that this interface is
    most likely not used anymore, and this is in addition the same behaviour implemented with the memory
    mapped interface (replace invalid values with zero) - see sync_regs() in kvm-s390.c.(CVE-2023-52597)

    In the Linux kernel, the following vulnerability has been resolved: usb: hub: Guard against accesses to
    uninitialized BOS descriptors Many functions in drivers/usb/core/hub.c and drivers/usb/core/hub.h access
    fields inside udev-bos without checking if it was allocated and initialized. If
    usb_get_bos_descriptor() fails for whatever reason, udev-bos will be NULL and those accesses will
    result in a crash: BUG: kernel NULL pointer dereference, address: 0000000000000018 PGD 0 P4D
    0(CVE-2023-52477)

    In the Linux kernel, the following vulnerability has been resolved:i40e: Fix kernel crash during module
    removal.The driver incorrectly frees client instance and subsequent i40e module removal leads to kernel
    crash.(CVE-2022-48688)

    In the Linux kernel, the following vulnerability has been resolved: nvmet: fix a use-after-free Fix the
    following use-after-free complaint triggered by blktests nvme/004: BUG: KASAN: user-memory-access in
    blk_mq_complete_request_remote(CVE-2022-48697)

    In the Linux kernel, the following vulnerability has been resolved:nvme-tcp: fix UAF when detecting digest
    errors.We should also bail from the io_work loop when we set rd_enabled to true,so we don't attempt to
    read data from the socket when the TCP stream is
    already out-of-sync or corrupted.(CVE-2022-48686)

    In the Linux kernel, the following vulnerability has been resolved: netfilter: nf_tables: Fix potential
    data-race in __nft_expr_type_get() nft_unregister_expr() can concurrent with __nft_expr_type_get(), and
    there is not any protection when iterate over nf_tables_expressions list in __nft_expr_type_get().
    Therefore, there is potential data-race of nf_tables_expressions list entry. Use list_for_each_entry_rcu()
    to iterate over nf_tables_expressions list in __nft_expr_type_get(), and use rcu_read_lock() in the caller
    nft_expr_type_get() to protect the entire type query process.(CVE-2024-27020)

    In the Linux kernel, the following vulnerability has been resolved: USB: usb-storage: Prevent divide-by-0
    error in isd200_ata_command The isd200 sub-driver in usb-storage uses the HEADS and SECTORS values in the
    ATA ID information to calculate cylinder and head values when creating a CDB for READ or WRITE commands.
    The calculation involves division and modulus operations, which will cause a crash if either of these
    values is 0. While this never happens with a genuine device, it could happen with a flawed or subversive
    emulation, as reported by the syzbot fuzzer. Protect against this possibility by refusing to bind to the
    device if either the ATA_ID_HEADS or ATA_ID_SECTORS value in the device's ID information is 0. This
    requires isd200_Initialization() to return a negative error code when initialization fails; currently it
    always returns 0 (even when there is an error).(CVE-2024-27059)

    In the Linux kernel, the following vulnerability has been resolved: inet: inet_defrag: prevent sk release
    while still in use ip_local_out() and other functions can pass skb-sk as function argument. If the skb
    is a fragment and reassembly happens before such function call returns, the sk must not be released. This
    affects skb fragments reassembled via netfilter or similar modules, e.g. openvswitch or ct_act.c, when run
    as part of tx pipeline. Eric Dumazet made an initial analysis of this bug. Quoting Eric: Calling
    ip_defrag() in output path is also implying skb_orphan(), which is buggy because output path relies on sk
    not disappearing. A relevant old patch about the issue was : 8282f27449bf ('inet: frag: Always orphan skbs
    inside ip_defrag()')(CVE-2024-26921)

    In the Linux kernel, the following vulnerability has been resolved: Bluetooth: rfcomm: Fix null-ptr-deref
    in rfcomm_check_security During our fuzz testing of the connection and disconnection process at the RFCOMM
    layer, we discovered this bug. By comparing the packets from a normal connection and disconnection process
    with the testcase that triggered a KASAN report. We analyzed the cause of this bug as follows: 1. In the
    packets captured during a normal connection, the host sends a `Read Encryption Key Size` type of `HCI_CMD`
    packet (Command Opcode: 0x1408) to the controller to inquire the length of encryption key.After receiving
    this packet, the controller immediately replies with a Command Completepacket (Event Code: 0x0e) to return
    the Encryption Key Size. 2. In our fuzz test case, the timing of the controller's response to this packet
    was delayed to an unexpected point: after the RFCOMM and L2CAP layers had disconnected but before the HCI
    layer had disconnected. 3. After receiving the Encryption Key Size Response at the time described in point
    2, the host still called the rfcomm_check_security function. However, by this time `struct l2cap_conn
    *conn = l2cap_pi(sk)-chan-conn;` had already been released, and when the function executed `return
    hci_conn_security(conn-hcon, d-sec_level, auth_type, d-out);`, specifically when accessing `conn-
    hcon`, a null-ptr-deref error occurred. To fix this bug, check if `sk-sk_state` is BT_CLOSED before
    calling rfcomm_recv_frame in rfcomm_process_rx.(CVE-2024-26903)

    In the Linux kernel, the following vulnerability has been resolved: ACPI: processor_idle: Fix memory leak
    in acpi_processor_power_exit() After unregistering the CPU idle device, the memory associated with it is
    not freed, leading to a memory leak: unreferenced object 0xffff896282f6c000 (size 1024): comm 'swapper/0',
    pid 1, jiffies 4294893170 hex dump (first 32 bytes): 00 00 00 00 0b 00 00 00 00 00 00 00 00 00 00 00
    ................ 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ................ backtrace (crc
    8836a742): [ffffffff993495ed] kmalloc_trace+0x29d/0x340 [ffffffff9972f3b3]
    acpi_processor_power_init+0xf3/0x1c0 [ffffffff9972d263] __acpi_processor_start+0xd3/0xf0
    [ffffffff9972d2bc] acpi_processor_start+0x2c/0x50 [ffffffff99805872] really_probe+0xe2/0x480
    [ffffffff99805c98] __driver_probe_device+0x78/0x160 [ffffffff99805daf]
    driver_probe_device+0x1f/0x90 [ffffffff9980601e] __driver_attach+0xce/0x1c0 [ffffffff99803170]
    bus_for_each_dev+0x70/0xc0 [ffffffff99804822] bus_add_driver+0x112/0x210 [ffffffff99807245]
    driver_register+0x55/0x100 [ffffffff9aee4acb] acpi_processor_driver_init+0x3b/0xc0
    [ffffffff990012d1] do_one_initcall+0x41/0x300 [ffffffff9ae7c4b0]
    kernel_init_freeable+0x320/0x470 [ffffffff99b231f6] kernel_init+0x16/0x1b0 [ffffffff99042e6d]
    ret_from_fork+0x2d/0x50 Fix this by freeing the CPU idle device after unregistering(CVE-2024-26894)

    In the Linux kernel, the following vulnerability has been resolved: NTB: fix possible name leak in
    ntb_register_device() If device_register() fails in ntb_register_device(), the device name allocated by
    dev_set_name() should be freed. As per the comment in device_register(), callers should use put_device()
    to give up the reference in the error path. So fix this by calling put_device() in the error path so that
    the name can be freed in kobject_cleanup(). As a result of this, put_device() in the error path of
    ntb_register_device() is removed and the actual error is returned.(CVE-2023-52652)

    In the Linux kernel, the following vulnerability has been resolved: drm: nv04: Fix out of bounds access
    When Output Resource (dcb-or) value is assigned in fabricate_dcb_output(), there may be out of bounds
    access to dac_users array in case dcb-or is zero because ffs(dcb-or) is used as index there. The
    'or' argument of fabricate_dcb_output() must be interpreted as a number of bit to set, not value. Utilize
    macros from 'enum nouveau_or' in calls instead of hardcoding. Found by Linux Verification Center
    (linuxtesting.org) with SVACE.(CVE-2024-27008)

    In the Linux kernel, the following vulnerability has been resolved: scsi: qla2xxx: Fix command flush on
    cable pull System crash due to command failed to flush back to SCSI layer. BUG: unable to handle kernel
    NULL pointer dereference at 0000000000000000 PGD 0 P4D 0 Oops: 0000(CVE-2024-26931)

    In the Linux kernel, the following vulnerability has been resolved: nfs: fix UAF in direct writes In
    production we have been hitting the following warning consistently(CVE-2024-26958)

    In the Linux kernel, the following vulnerability has been resolved: drm: Don't unref the same fb many
    times by mistake due to deadlock handling If we get a deadlock after the fb lookup in
    drm_mode_page_flip_ioctl() we proceed to unref the fb and then retry the whole thing from the top. But we
    forget to reset the fb pointer back to NULL, and so if we then get another error during the retry, before
    the fb lookup, we proceed the unref the same fb again without having gotten another reference. The end
    result is that the fb will (eventually) end up being freed while it's still in use. Reset fb to NULL once
    we've unreffed it to avoid doing it again until we've done another fb lookup. This turned out to be pretty
    easy to hit on a DG2 when doing async flips (and CONFIG_DEBUG_WW_MUTEX_SLOWPATH=y). The first symptom I
    saw that drm_closefb() simply got stuck in a busy loop while walking the framebuffer list. Fortunately I
    was able to convince it to oops instead, and from there it was easier to track down the
    culprit.(CVE-2023-52486)

    In the Linux kernel, the following vulnerability has been resolved: tipc: Check the bearer type before
    calling tipc_udp_nl_bearer_add() syzbot reported the following general protection fault [1]: general
    protection fault, probably for non-canonical address 0xdffffc0000000010: 0000 [#1] PREEMPT SMP KASAN
    KASAN: null-ptr-deref in range [0x0000000000000080-0x0000000000000087] ...The cause of this issue is
    that when tipc_nl_bearer_add() is called with the TIPC_NLA_BEARER_UDP_OPTS attribute,
    tipc_udp_nl_bearer_add() is called even if the bearer is not UDP. tipc_udp_is_known_peer() called by
    tipc_udp_nl_bearer_add() assumes that the media_ptr field of the tipc_bearer has an udp_bearer type
    object, so the function goes crazy for non-UDP bearers. This patch fixes the issue by checking the bearer
    type before calling tipc_udp_nl_bearer_add() in tipc_nl_bearer_add().(CVE-2024-26663)

    In the Linux kernel, the following vulnerability has been resolved: x86/alternatives: Disable KASAN in
    apply_alternatives() Fei has reported that KASAN triggers during apply_alternatives() on a 5-level paging
    machine: BUG: KASAN: out-of-bounds in rcu_is_watching() Read of size 4 at addr ff110003ee6419a0 by task
    swapper/0/0 ... __asan_load4() rcu_is_watching() trace_hardirqs_on() text_poke_early()
    apply_alternatives() ... On machines with 5-level paging, cpu_feature_enabled(X86_FEATURE_LA57) gets
    patched. It includes KASAN code, where KASAN_SHADOW_START depends on __VIRTUAL_MASK_SHIFT, which is
    defined with cpu_feature_enabled(). KASAN gets confused when apply_alternatives() patches the
    KASAN_SHADOW_START users. A test patch that makes KASAN_SHADOW_START static, by replacing
    __VIRTUAL_MASK_SHIFT with 56, works around the issue. Fix it for real by disabling KASAN while the kernel
    is patching alternatives.(CVE-2023-52504)

    In the Linux kernel, the following vulnerability has been resolved: netlink: Fix kernel-infoleak-after-
    free in __skb_datagram_iter syzbot reported the following uninit-value access issue [1]:
    netlink_to_full_skb() creates a new `skb` and puts the `skb-data` passed as a 1st arg of
    netlink_to_full_skb() onto new `skb`. The data size is specified as `len` and passed to skb_put_data().
    This `len` is based on `skb-end` that is not data offset but buffer offset. The `skb-end` contains
    data and tailroom. Since the tailroom is not initialized when the new `skb` created, KMSAN detects
    uninitialized memory area when copying the data. This patch resolved this issue by correct the len from
    `skb-end` to `skb-len`, which is the actual data offset.(CVE-2024-26805)

    In the Linux kernel, the following vulnerability has been resolved: scsi: lpfc: Fix list_add() corruption
    in lpfc_drain_txq() When parsing the txq list in lpfc_drain_txq(), the driver attempts to pass the
    requests to the adapter. If such an attempt fails, a local 'fail_msg' string is set and a log message
    output. The job is then added to a completions list for cancellation. Processing of any further jobs from
    the txq list continues, but since 'fail_msg' remains set, jobs are added to the completions list
    regardless of whether a wqe was passed to the adapter. If successfully added to txcmplq, jobs are added to
    both lists resulting in list corruption. Fix by clearing the fail_msg string after adding a job to the
    completions list. This stops the subsequent jobs from being added to the completions list unless they had
    an appropriate failure.(CVE-2021-47203)

    In the Linux kernel, the following vulnerability has been resolved: usb: typec: tipd: Remove WARN_ON in
    tps6598x_block_read Calling tps6598x_block_read with a higher than allowed len can be handled by just
    returning an error. There's no need to crash systems with panic-on-warn enabled.(CVE-2021-47210)

    In the Linux kernel, the following vulnerability has been resolved: net: fix possible store tearing in
    neigh_periodic_work() While looking at a related syzbot report involving neigh_periodic_work(), I found
    that I forgot to add an annotation when deleting an RCU protected item from a list. Readers use
    rcu_deference(*np), we need to use either rcu_assign_pointer() or WRITE_ONCE() on writer side to prevent
    store tearing. I use rcu_assign_pointer() to have lockdep support, this was the choice made in
    neigh_flush_dev().(CVE-2023-52522)

    In the Linux kernel, the following vulnerability has been resolved: x86/hyperv: Fix NULL deref in
    set_hv_tscchange_cb() if Hyper-V setup fails Check for a valid hv_vp_index array prior to derefencing
    hv_vp_index when setting Hyper-V's TSC change callback. If Hyper-V setup failed in hyperv_init(), the
    kernel will still report that it's running under Hyper-V, but will have silently disabled nearly all
    functionality. BUG: kernel NULL pointer dereference, address: 0000000000000010 #PF: supervisor read access
    in kernel mode #PF: error_code(0x0000) - not-present page PGD 0 P4D 0 Oops: 0000 [#1] SMP CPU: 4 PID: 1
    Comm: swapper/0 Not tainted 5.15.0-rc2+ #75 Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS 0.0.0
    02/06/2015 RIP: 0010:set_hv_tscchange_cb+0x15/0xa0 Code: 8b 04 82 8b 15 12 17 85 01 48 c1 e0 20 48
    0d ee 00 01 00 f6 c6 08 ... Call Trace: kvm_arch_init+0x17c/0x280 kvm_init+0x31/0x330 vmx_init+0xba/0x13a
    do_one_initcall+0x41/0x1c0 kernel_init_freeable+0x1f2/0x23b kernel_init+0x16/0x120
    ret_from_fork+0x22/0x30(CVE-2021-47217)

    In the Linux kernel, the following vulnerability has been resolved: scsi: lpfc: Fix link down processing
    to address NULL pointer dereference If an FC link down transition while PLOGIs are outstanding to fabric
    well known addresses, outstanding ABTS requests may result in a NULL pointer dereference. Driver unload
    requests may hang with repeated '2878' log messages. The Link down processing results in ABTS requests for
    outstanding ELS requests. The Abort WQEs are sent for the ELSs before the driver had set the link state to
    down. Thus the driver is sending the Abort with the expectation that an ABTS will be sent on the wire. The
    Abort request is stalled waiting for the link to come up. In some conditions the driver may auto-complete
    the ELSs thus if the link does come up, the Abort completions may reference an invalid structure. Fix by
    ensuring that Abort set the flag to avoid link traffic if issued due to conditions where the link
    failed.(CVE-2021-47183)

    In the Linux kernel, the following vulnerability has been resolved: cfg80211: call cfg80211_stop_ap when
    switch from P2P_GO type If the userspace tools switch from NL80211_IFTYPE_P2P_GO to NL80211_IFTYPE_ADHOC
    via send_msg(NL80211_CMD_SET_INTERFACE), it does not call the cleanup cfg80211_stop_ap(), this leads to
    the initialization of in-use data. For example, this path re-init the sdata-assigned_chanctx_list while
    it is still an element of assigned_vifs list, and makes that linked list corrupt.(CVE-2021-47194)

    In the Linux kernel, the following vulnerability has been resolved: scsi: core: Fix scsi_mode_sense()
    buffer length handling Several problems exist with scsi_mode_sense() buffer length handling: 1) The
    allocation length field of the MODE SENSE(10) command is 16-bits, occupying bytes 7 and 8 of the CDB. With
    this command, access to mode pages larger than 255 bytes is thus possible. However, the CDB allocation
    length field is set by assigning len to byte 8 only, thus truncating buffer length larger than 255. 2) If
    scsi_mode_sense() is called with len smaller than 8 with sdev-use_10_for_ms set, or smaller than 4
    otherwise, the buffer length is increased to 8 and 4 respectively, and the buffer is zero filled with
    these increased values, thus corrupting the memory following the buffer. Fix these 2 problems by using
    put_unaligned_be16() to set the allocation length field of MODE SENSE(10) CDB and by returning an error
    when len is too small. Furthermore, if len is larger than 255B, always try MODE SENSE(10) first, even if
    the device driver did not set sdev-use_10_for_ms. In case of invalid opcode error for MODE SENSE(10),
    access to mode pages larger than 255 bytes are not retried using MODE SENSE(6). To avoid buffer length
    overflows for the MODE_SENSE(10) case, check that len is smaller than 65535 bytes. While at it, also fix
    the folowing: * Use get_unaligned_be16() to retrieve the mode data length and block descriptor length
    fields of the mode sense reply header instead of using an open coded calculation. * Fix the kdoc dbd
    argument explanation: the DBD bit stands for Disable Block Descriptor, which is the opposite of what the
    dbd argument description was.(CVE-2021-47182)

    In the Linux kernel, the following vulnerability has been resolved: tcp: make sure init the accept_queue's
    spinlocks once When I run syz's reproduction C program locally, it causes the following issue:
    pvqspinlock: lock 0xffff9d181cd5c660 has corrupted value 0x0!(CVE-2024-26614)

    In the Linux kernel, the following vulnerability has been resolved: rds: tcp: Fix use-after-free of net in
    reqsk_timer_handler(). syzkaller reported a warning of netns tracker [0] followed by KASAN splat [1] and
    another ref tracker warning [1]. syzkaller could not find a repro, but in the log, the only suspicious
    sequence was as follows: 18:26:22 executing program 1: r0 = socket$inet6_mptcp(0xa, 0x1, 0x106) ...
    connect$inet6(r0, (0x7f0000000080)={0xa, 0x4001, 0x0, @loopback}, 0x1c) (async) The notable thing here
    is 0x4001 in connect(), which is RDS_TCP_PORT.(CVE-2024-26865)

    In the Linux kernel, the following vulnerability has been resolved:net: openvswitch: Fix Use-After-Free in
    ovs_ct_exit.Since kfree_rcu, which is called in the hlist_for_each_entry_rcu traversal of
    ovs_ct_limit_exit, is not part of the RCU read critical section, it is possible that the RCU grace period
    will pass during the traversal and the key will be free.To prevent this, it should be changed to
    hlist_for_each_entry_safe.(CVE-2024-27395)

    In the Linux kernel, the following vulnerability has been resolved: nfp: flower: handle acti_netdevs
    allocation failure The kmalloc_array() in nfp_fl_lag_do_work() will return null, if the physical memory
    has run out. As a result, if we dereference the acti_netdevs, the null pointer dereference bugs will
    happen. This patch adds a check to judge whether allocation failure occurs. If it happens, the delayed
    work will be rescheduled and try again.(CVE-2024-27046)

    In the Linux kernel, the following vulnerability has been resolved: bpf: Fix stackmap overflow check on
    32-bit arches The stackmap code relies on roundup_pow_of_two() to compute the number of hash buckets, and
    contains an overflow check by checking if the resulting value is 0. However, on 32-bit arches, the roundup
    code itself can overflow by doing a 32-bit left-shift of an unsigned long value, which is undefined
    behaviour, so it is not guaranteed to truncate neatly. This was triggered by syzbot on the DEVMAP_HASH
    type, which contains the same check, copied from the hashtab code. The commit in the fixes tag actually
    attempted to fix this, but the fix did not account for the UB, so the fix only works on CPUs where an
    overflow does result in a neat truncation to zero, which is not guaranteed. Checking the value before
    rounding does not have this problem.(CVE-2024-26883)

    In the Linux kernel, the following vulnerability has been resolved:net: sched: fix possible refcount leak
    in tc_new_tfilter().tfilter_put need to be called to put the refount got by tp-ops-get to avoid
    possible refcount leak when chain-tmplt_ops != NULL and chain-tmplt_ops != tp-
    ops.(CVE-2022-48639)

    In the Linux kernel, the following vulnerability has been resolved: net: usb: smsc75xx: Fix uninit-value
    access in __smsc75xx_read_reg syzbot reported the following uninit-value access issue:
    ===================================================== BUG: KMSAN: uninit-value in
    smsc75xx_wait_ready(CVE-2023-52528)

    In the Linux kernel, the following vulnerability has been resolved: mm: swap: fix race between
    free_swap_and_cache() and swapoff() There was previously a theoretical window where swapoff() could run
    and teardown a swap_info_struct while a call to free_swap_and_cache() was running in another thread. This
    could cause, amongst other bad possibilities, swap_page_trans_huge_swapped() (called by
    free_swap_and_cache()) to access the freed memory for swap_map. This is a theoretical problem and I
    haven't been able to provoke it from a test case. But there has been agreement based on code review that
    this is possible (see link below). Fix it by using get_swap_device()/put_swap_device(), which will stall
    swapoff(). There was an extra check in _swap_info_get() to confirm that the swap entry was not free. This
    isn't present in get_swap_device() because it doesn't make sense in general due to the race between
    getting the reference and swapoff. So I've added an equivalent check directly in
    free_swap_and_cache().(CVE-2024-26960)

    In the Linux kernel, the following vulnerability has been resolved: ip6_tunnel: fix NEXTHDR_FRAGMENT
    handling in ip6_tnl_parse_tlv_enc_lim() syzbot pointed out [1] that NEXTHDR_FRAGMENT handling is broken.
    Reading frag_off can only be done if we pulled enough bytes to skb-head. Currently we might access
    garbage.(CVE-2024-26633)

    In the Linux kernel, the following vulnerability has been resolved: wifi: mac80211: fix potential key use-
    after-free When ieee80211_key_link() is called by ieee80211_gtk_rekey_add() but returns 0 due to KRACK
    protection (identical key reinstall), ieee80211_gtk_rekey_add() will still return a pointer into the key,
    in a potential use-after-free. This normally doesn't happen since it's only called by iwlwifi in case of
    WoWLAN rekey offload which has its own KRACK protection, but still better to fix, do that by returning an
    error code and converting that to success on the cfg80211 boundary only, leaving the error for bad callers
    of ieee80211_gtk_rekey_add().(CVE-2023-52530)

    In the Linux kernel, the following vulnerability has been resolved: IB/ipoib: Fix mcast list locking
    Releasing the `priv-lock` while iterating the `priv-multicast_list` in `ipoib_mcast_join_task()`
    opens a window for `ipoib_mcast_dev_flush()` to remove the items while in the middle of iteration. If the
    mcast is removed while the lock was dropped, the for loop spins forever resulting in a hard
    lockup(CVE-2023-52587)

    In the Linux kernel, the following vulnerability has been resolved: team: fix null-ptr-deref when team
    device type is changed Get a null-ptr-deref bug as follows with reproducer [1]. BUG: kernel NULL pointer
    dereference, address: 0000000000000228 ... RIP: 0010:vlan_dev_hard_header+0x35/0x140 [8021q] ... Call
    Trace: TASK ? __die+0x24/0x70 ? page_fault_oops+0x82/0x150 ? exc_page_fault+0x69/0x150 ?
    asm_exc_page_fault+0x26/0x30 ? vlan_dev_hard_header+0x35/0x140 [8021q] ? vlan_dev_hard_header+0x8e/0x140
    [8021q] neigh_connected_output+0xb2/0x100 ip6_finish_output2+0x1cb/0x520 ? nf_hook_slow+0x43/0xc0 ?
    ip6_mtu+0x46/0x80 ip6_finish_output+0x2a/0xb0 mld_sendpack+0x18f/0x250 mld_ifc_work+0x39/0x160
    process_one_work+0x1e6/0x3f0 worker_thread+0x4d/0x2f0 ? __pfx_worker_thread+0x10/0x10 kthread+0xe5/0x120 ?
    __pfx_kthread+0x10/0x10 ret_from_fork+0x34/0x50 ? __pfx_kthread+0x10/0x10 ret_from_fork_asm+0x1b/0x30 [1]
    $ teamd -t team0 -d -c '{'runner': {'name': 'loadbalance'}}' $ ip link add name t-dummy type dummy $ ip
    link add link t-dummy name t-dummy.100 type vlan id 100 $ ip link add name t-nlmon type nlmon $ ip link
    set t-nlmon master team0 $ ip link set t-nlmon nomaster $ ip link set t-dummy up $ ip link set team0 up $
    ip link set t-dummy.100 down $ ip link set t-dummy.100 master team0 When enslave a vlan device to team
    device and team device type is changed from non-ether to ether, header_ops of team device is changed to
    vlan_header_ops. That is incorrect and will trigger null-ptr-deref for vlan-real_dev in
    vlan_dev_hard_header() because team device is not a vlan device. Cache eth_header_ops in team_setup(),
    then assign cached header_ops to header_ops of team net device when its type is changed from non-ether to
    ether to fix the bug.(CVE-2023-52574)

    In the Linux kernel, the following vulnerability has been resolved: vsock/virtio: free queued packets when
    closing socket As reported by syzbot [1], there is a memory leak while closing the socket. We partially
    solved this issue with commit ac03046ece2b ('vsock/virtio: free packets during the socket release'), but
    we forgot to drain the RX queue when the socket is definitely closed by the scheduled work. To avoid
    future issues, let's use the new virtio_transport_remove_sock() to drain the RX queue before removing the
    socket from the af_vsock lists calling vsock_remove_sock().(CVE-2021-47024)

    In the Linux kernel, the following vulnerability has been resolved: net: bridge: use DEV_STATS_INC()
    syzbot/KCSAN reported data-races in br_handle_frame_finish() [1] This function can run from multiple cpus
    without mutual exclusion. Adopt SMP safe DEV_STATS_INC() to update dev-stats fields. Handles updates to
    dev-stats.tx_dropped while we are at it.(CVE-2023-52578)

    In the Linux kernel, the following vulnerability has been resolved: af_unix: Fix garbage collector racing
    against connect() Garbage collector does not take into account the risk of embryo getting enqueued during
    the garbage collection. If such embryo has a peer that carries SCM_RIGHTS, two consecutive passes of
    scan_children() may see a different set of children. Leading to an incorrectly elevated inflight count,
    and then a dangling pointer within the gc_inflight_list. sockets are AF_UNIX/SOCK_STREAM S is an
    unconnected socket L is a listening in-flight socket bound to addr, not in fdtable V's fd will be passed
    via sendmsg(), gets inflight count bumped connect(S, addr) sendmsg(S, [V]); close(V) __unix_gc()
    ---------------- ------------------------- ----------- NS = unix_create1() skb1 = sock_wmalloc(NS) L =
    unix_find_other(addr) unix_state_lock(L) unix_peer(S) = NS // V count=1 inflight=0 NS = unix_peer(S) skb2
    = sock_alloc() skb_queue_tail(NS, skb2[V]) // V became in-flight // V count=2 inflight=1 close(V) // V
    count=1 inflight=1 // GC candidate condition met for u in gc_inflight_list: if (total_refs ==
    inflight_refs) add u to gc_candidates // gc_candidates={L, V} for u in gc_candidates: scan_children(u,
    dec_inflight) // embryo (skb1) was not // reachable from L yet, so V's // inflight remains unchanged
    __skb_queue_tail(L, skb1) unix_state_unlock(L) for u in gc_candidates: if (u.inflight) scan_children(u,
    inc_inflight_move_tail) // V count=1 inflight=2 (!) If there is a GC-candidate listening socket,
    lock/unlock its state. This makes GC wait until the end of any ongoing connect() to that socket. After
    flipping the lock, a possibly SCM-laden embryo is already enqueued. And if there is another embryo coming,
    it can not possibly carry SCM_RIGHTS. At this point, unix_inflight() can not happen because unix_gc_lock
    is already taken. Inflight graph remains unaffected.(CVE-2024-26923)

    In the Linux kernel, the following vulnerability has been resolved: net: ip_tunnel: make sure to pull
    inner header in ip_tunnel_rcv() Apply the same fix than ones found in : 8d975c15c0cd ('ip6_tunnel: make
    sure to pull inner header in __ip6_tnl_rcv()') 1ca1ba465e55 ('geneve: make sure to pull inner header in
    geneve_rx()') We have to save skb-network_header in a temporary variable in order to be able to
    recompute the network_header pointer after a pskb_inet_may_pull() call. pskb_inet_may_pull() makes sure
    the needed headers are in skb-head.(CVE-2024-26882)

    In the Linux kernel, the following vulnerability has been resolved: vfio/pci: Create persistent INTx
    handler A vulnerability exists where the eventfd for INTx signaling can be deconfigured, which unregisters
    the IRQ handler but still allows eventfds to be signaled with a NULL context through the SET_IRQS ioctl or
    through unmask irqfd if the device interrupt is pending. Ideally this could be solved with some additional
    locking; the igate mutex serializes the ioctl and config space accesses, and the interrupt handler is
    unregistered relative to the trigger, but the irqfd path runs asynchronous to those. The igate mutex
    cannot be acquired from the atomic context of the eventfd wake function. Disabling the irqfd relative to
    the eventfd registration is potentially incompatible with existing userspace. As a result, the solution
    implemented here moves configuration of the INTx interrupt handler to track the lifetime of the INTx
    context object and irq_type configuration, rather than registration of a particular trigger eventfd.
    Synchronization is added between the ioctl path and eventfd_signal() wrapper such that the eventfd trigger
    can be dynamically updated relative to in-flight interrupts or irqfd callbacks.(CVE-2024-26812)

    In the Linux kernel, the following vulnerability has been resolved: RDMA/mlx5: Fix fortify source warning
    while accessing Eth segment(CVE-2024-26907)

    In the Linux kernel, the following vulnerability has been resolved:tracing/trigger: Fix to return error if
    failed to alloc snapshot.Fix register_snapshot_trigger() to return error code if it failed to allocate a
    snapshot instead of 0 (success). Unless that, it will register snapshot trigger without an
    error.(CVE-2024-26920)

    In the Linux kernel, the following vulnerability has been resolved: netfilter: nf_tables: disallow timeout
    for anonymous sets Never used from userspace, disallow these parameters.(CVE-2023-52620)

    In the Linux kernel, the following vulnerability has been resolved: vfio/pci: Lock external INTx masking
    ops Mask operations through config space changes to DisINTx may race INTx configuration changes via ioctl.
    Create wrappers that add locking for paths outside of the core interrupt code. In particular, irq_type is
    updated holding igate, therefore testing is_intx() requires holding igate. For example clearing DisINTx
    from config space can otherwise race changes of the interrupt configuration. This aligns interfaces which
    may trigger the INTx eventfd into two camps, one side serialized by igate and the other only enabled while
    INTx is configured. A subsequent patch introduces synchronization for the latter flows.(CVE-2024-26810)

    In the Linux kernel, the following vulnerability has been resolved: ceph: fix deadlock or deadcode of
    misusing dget() The lock order is incorrect between denty and its parent, we should always make sure that
    the parent get the lock first. But since this deadcode is never used and the parent dir will always be set
    from the callers, let's just remove it.(CVE-2023-52583)

    In the Linux kernel, the following vulnerability has been resolved: aio: fix mremap after fork null-deref
    Commit e4a0d3e720e7 ('aio: Make it possible to remap aio ring') introduced a null-deref if mremap is
    called on an old aio mapping after fork as mm-ioctx_table will be set to NULL.(CVE-2023-52646)

    In the Linux kernel, the following vulnerability has been resolved: scsi: qedf: Add pointer checks in
    qedf_update_link_speed() The following trace was observed: [ 14.042059] Call Trace: [ 14.042061] IRQ
    [ 14.042068] qedf_link_update+0x144/0x1f0 [qedf] [ 14.042117] qed_link_update+0x5c/0x80 [qed] [ 14.042135]
    qed_mcp_handle_link_change+0x2d2/0x410 [qed] [ 14.042155] ? qed_set_ptt+0x70/0x80 [qed] [ 14.042170] ?
    qed_set_ptt+0x70/0x80 [qed] [ 14.042186] ? qed_rd+0x13/0x40 [qed] [ 14.042205]
    qed_mcp_handle_events+0x437/0x690 [qed] [ 14.042221] ? qed_set_ptt+0x70/0x80 [qed] [ 14.042239]
    qed_int_sp_dpc+0x3a6/0x3e0 [qed] [ 14.042245] tasklet_action_common.isra.14+0x5a/0x100 [ 14.042250]
    __do_softirq+0xe4/0x2f8 [ 14.042253] irq_exit+0xf7/0x100 [ 14.042255] do_IRQ+0x7f/0xd0 [ 14.042257]
    common_interrupt+0xf/0xf [ 14.042259] /IRQ API qedf_link_update() is getting called from QED but by
    that time shost_data is not initialised. This results in a NULL pointer dereference when we try to
    dereference shost_data while updating supported_speeds. Add a NULL pointer check before dereferencing
    shost_dat(CVE-2021-47077)

    In the Linux kernel, the following vulnerability has been resolved: perf/core: Bail out early if the
    request AUX area is out of bound When perf-record with a large AUX area, e.g 4GB, it fails with: #perf
    record -C 0 -m ,4G -e arm_spe_0// -- sleep 1 failed to mmap with 12 (Cannot allocate memory) and it
    reveals a WARNING with __alloc_pages()(CVE-2023-52835)

    In the Linux kernel, the following vulnerability has been resolved: Bluetooth: af_bluetooth: Fix deadlock
    Attemting to do sock_lock on .recvmsg may cause a deadlock as shown bellow, so instead of using sock_sock
    this uses sk_receive_queue.lock on bt_sock_ioctl to avoid the UAF: INFO: task kworker/u9:1:121 blocked for
    more than 30 seconds. Not tainted 6.7.6-lemon #183 Workqueue: hci0 hci_rx_work(CVE-2024-26886)

    A vulnerability was reported in the Open vSwitch sub-component in the Linux Kernel. The flaw occurs when a
    recursive operation of code push recursively calls into the code block. The OVS module does not validate
    the stack depth, pushing too many frames and causing a stack overflow. As a result, this can lead to a
    crash or other related issues.(CVE-2024-1151)

    In the Linux kernel, the following vulnerability has been resolved:vfio/pci: Disable auto-enable of
    exclusive INTx IRQ.Currently for devices requiring masking at the irqchip for INTx, ie. devices without
    DisINTx support, the IRQ is enabled in request_irq() and subsequently disabled as necessary to align with
    the masked status flag.  This presents a window where the interrupt could fire between these events,
    resulting in the IRQ incrementing the disable depth twice.This would be unrecoverable for a user since the
    masked flag prevents nested enables through vfio.Instead, invert the logic using IRQF_NO_AUTOEN such that
    exclusive INTx is never auto-enabled, then unmask as required.(CVE-2024-27437)

    In the Linux kernel, the following vulnerability has been resolved: mlxsw: spectrum_acl_tcam: Fix stack
    corruption When tc filters are first added to a net device, the corresponding local port gets bound to an
    ACL group in the device. The group contains a list of ACLs. In turn, each ACL points to a different TCAM
    region where the filters are stored. During forwarding, the ACLs are sequentially evaluated until a match
    is found. One reason to place filters in different regions is when they are added with decreasing
    priorities and in an alternating order so that two consecutive filters can never fit in the same region
    because of their key usage. In Spectrum-2 and newer ASICs the firmware started to report that the maximum
    number of ACLs in a group is more than 16, but the layout of the register that configures ACL groups
    (PAGT) was not updated to account for that. It is therefore possible to hit stack corruption [1] in the
    rare case where more than 16 ACLs in a group are required. Fix by limiting the maximum ACL group size to
    the minimum between what the firmware reports and the maximum ACLs that fit in the PAGT register. Add a
    test case to make sure the machine does not crash when this condition is hit. [1] Kernel panic - not
    syncing: stack-protector: Kernel stack is corrupted in: mlxsw_sp_acl_tcam_group_update+0x116/0x120 [...]
    dump_stack_lvl+0x36/0x50 panic+0x305/0x330 __stack_chk_fail+0x15/0x20
    mlxsw_sp_acl_tcam_group_update+0x116/0x120 mlxsw_sp_acl_tcam_group_region_attach+0x69/0x110
    mlxsw_sp_acl_tcam_vchunk_get+0x492/0xa20 mlxsw_sp_acl_tcam_ventry_add+0x25/0xe0
    mlxsw_sp_acl_rule_add+0x47/0x240 mlxsw_sp_flower_replace+0x1a9/0x1d0 tc_setup_cb_add+0xdc/0x1c0
    fl_hw_replace_filter+0x146/0x1f0 fl_change+0xc17/0x1360 tc_new_tfilter+0x472/0xb90
    rtnetlink_rcv_msg+0x313/0x3b0 netlink_rcv_skb+0x58/0x100 netlink_unicast+0x244/0x390
    netlink_sendmsg+0x1e4/0x440 ____sys_sendmsg+0x164/0x260 ___sys_sendmsg+0x9a/0xe0 __sys_sendmsg+0x7a/0xc0
    do_syscall_64+0x40/0xe0 entry_SYSCALL_64_after_hwframe+0x63/0x6b(CVE-2024-26586)

    In the Linux kernel, the following vulnerability has been resolved: bpf: Reject variable offset alu on
    PTR_TO_FLOW_KEYS For PTR_TO_FLOW_KEYS, check_flow_keys_access() only uses fixed off for validation.
    However, variable offset ptr alu is not prohibited for this ptr kind. So the variable offset is not
    checked.(CVE-2024-26589)

    In the Linux kernel, the following vulnerability has been resolved: sched/membarrier: reduce the ability
    to hammer on sys_membarrier On some systems, sys_membarrier can be very expensive, causing overall
    slowdowns for everything. So put a lock on the path in order to serialize the accesses to prevent the
    ability for this to be called at too high of a frequency and saturate the machine.(CVE-2024-26602)

    In the Linux kernel, the following vulnerability has been resolved: ALSA: sh: aica: reorder cleanup
    operations to avoid UAF bugs The dreamcastcard-timer could schedule the spu_dma_work and the
    spu_dma_work could also arm the dreamcastcard-timer. When the snd_pcm_substream is closing, the
    aica_channel will be deallocated. But it could still be dereferenced in the worker thread. The reason is
    that del_timer() will return directly regardless of whether the timer handler is running or not and the
    worker could be rescheduled in the timer handler. As a result, the UAF bug will happen. The racy situation
    is shown below: (Thread 1) | (Thread 2) snd_aicapcm_pcm_close() | ... | run_spu_dma() //worker |
    mod_timer() flush_work() | del_timer() | aica_period_elapsed() //timer kfree(dreamcastcard-channel) |
    schedule_work() | run_spu_dma() //worker ... | dreamcastcard-channel- //USE In order to mitigate
    this bug and other possible corner cases, call mod_timer() conditionally in run_spu_dma(), then implement
    PCM sync_stop op to cancel both the timer and worker. The sync_stop op will be called from PCM core
    appropriately when needed.(CVE-2024-26654)

Tenable has extracted the preceding description block directly from the EulerOS kernel security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2024-1964
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e6f8145d");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-27395");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python3-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var _release = get_kb_item("Host/EulerOS/release");
if (isnull(_release) || _release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (_release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP9");

var sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(9)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP9");

if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP9", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "x86" >!< cpu) audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

var flag = 0;

var pkgs = [
  "kernel-4.18.0-147.5.1.6.h1305.eulerosv2r9",
  "kernel-tools-4.18.0-147.5.1.6.h1305.eulerosv2r9",
  "kernel-tools-libs-4.18.0-147.5.1.6.h1305.eulerosv2r9",
  "python3-perf-4.18.0-147.5.1.6.h1305.eulerosv2r9"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"9", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
