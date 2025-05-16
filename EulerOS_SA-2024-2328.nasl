#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(206524);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/02");

  script_cve_id(
    "CVE-2021-47094",
    "CVE-2021-47101",
    "CVE-2021-47105",
    "CVE-2021-47182",
    "CVE-2021-47212",
    "CVE-2023-6536",
    "CVE-2023-52467",
    "CVE-2023-52478",
    "CVE-2023-52492",
    "CVE-2023-52498",
    "CVE-2023-52515",
    "CVE-2023-52612",
    "CVE-2023-52619",
    "CVE-2023-52620",
    "CVE-2023-52621",
    "CVE-2023-52622",
    "CVE-2023-52623",
    "CVE-2023-52628",
    "CVE-2023-52646",
    "CVE-2024-23307",
    "CVE-2024-24861",
    "CVE-2024-25739",
    "CVE-2024-26633",
    "CVE-2024-26635",
    "CVE-2024-26636",
    "CVE-2024-26640",
    "CVE-2024-26641",
    "CVE-2024-26642",
    "CVE-2024-26643",
    "CVE-2024-26645",
    "CVE-2024-26659",
    "CVE-2024-26663",
    "CVE-2024-26665",
    "CVE-2024-26668",
    "CVE-2024-26669",
    "CVE-2024-26671",
    "CVE-2024-26673",
    "CVE-2024-26675",
    "CVE-2024-26679",
    "CVE-2024-26680",
    "CVE-2024-26686",
    "CVE-2024-26687",
    "CVE-2024-26688",
    "CVE-2024-26689",
    "CVE-2024-26695",
    "CVE-2024-26698",
    "CVE-2024-26704",
    "CVE-2024-26720",
    "CVE-2024-26733",
    "CVE-2024-26734",
    "CVE-2024-26735",
    "CVE-2024-26739",
    "CVE-2024-26740",
    "CVE-2024-26743",
    "CVE-2024-26744",
    "CVE-2024-26747",
    "CVE-2024-26752",
    "CVE-2024-26759",
    "CVE-2024-26763",
    "CVE-2024-26764",
    "CVE-2024-26766",
    "CVE-2024-26769",
    "CVE-2024-26772",
    "CVE-2024-26773",
    "CVE-2024-26774",
    "CVE-2024-26798",
    "CVE-2024-26804",
    "CVE-2024-26805",
    "CVE-2024-26808",
    "CVE-2024-26809",
    "CVE-2024-26810",
    "CVE-2024-26812",
    "CVE-2024-26813",
    "CVE-2024-26814",
    "CVE-2024-26833",
    "CVE-2024-26835",
    "CVE-2024-26839",
    "CVE-2024-26840",
    "CVE-2024-26851",
    "CVE-2024-26855",
    "CVE-2024-26859",
    "CVE-2024-26862",
    "CVE-2024-26870",
    "CVE-2024-26872",
    "CVE-2024-26875",
    "CVE-2024-26878",
    "CVE-2024-26882",
    "CVE-2024-26883",
    "CVE-2024-26884",
    "CVE-2024-26885",
    "CVE-2024-26894",
    "CVE-2024-26898",
    "CVE-2024-26900",
    "CVE-2024-26901",
    "CVE-2024-26920",
    "CVE-2024-27437"
  );

  script_name(english:"EulerOS Virtualization 2.12.0 : kernel (EulerOS-SA-2024-2328)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the EulerOS Virtualization installation on the remote host
is affected by the following vulnerabilities :

    A flaw was found in the Linux kernel's NVMe driver. This issue may allow an unauthenticated malicious
    actor to send a set of crafted TCP packages when using NVMe over TCP, leading the NVMe driver to a NULL
    pointer dereference in the NVMe driver, causing kernel panic and a denial of service.(CVE-2023-6536)

    A race condition was found in the Linux kernel's media/xc4000 device driver in xc4000
    xc4000_get_frequency() function. This can result in return value overflow issue, possibly leading to
    malfunction or denial of service issue.(CVE-2024-24861)

    create_empty_lvol in drivers/mtd/ubi/vtbl.c in the Linux kernel through 6.7.4 can attempt to allocate zero
    bytes, and crash, because of a missing check for ubi-leb_size.(CVE-2024-25739)

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

    In the Linux kernel, the following vulnerability has been resolved: aio: fix mremap after fork null-deref
    Commit e4a0d3e720e7 ('aio: Make it possible to remap aio ring') introduced a null-deref if mremap is
    called on an old aio mapping after fork as mm-ioctx_table will be set to NULL.(CVE-2023-52646)

    In the Linux kernel, the following vulnerability has been resolved: arp: Prevent overflow in
    arp_req_get(). syzkaller reported an overflown write in arp_req_get(). [0] When ioctl(SIOCGARP) is issued,
    arp_req_get() looks up an neighbour entry and copies neigh-ha to struct arpreq.arp_ha.sa_data. The
    arp_ha here is struct sockaddr, not struct sockaddr_storage, so the sa_data buffer is just 14 bytes. In
    the splat below, 2 bytes are overflown to the next int field, arp_flags. We initialise the field just
    after the memcpy(), so it's not a problem. However, when dev-addr_len is greater than 22 (e.g.
    MAX_ADDR_LEN), arp_netmask is overwritten, which could be set as htonl(0xFFFFFFFFUL) in arp_ioctl() before
    calling arp_req_get(). To avoid the overflow, let's limit the max length of memcpy().(CVE-2024-26733)

    In the Linux kernel, the following vulnerability has been resolved: asix: fix uninit-value in
    asix_mdio_read() asix_read_cmd() may read less than sizeof(smsr) bytes and in this case smsr will be
    uninitialized.(CVE-2021-47101)

    In the Linux kernel, the following vulnerability has been resolved: bpf: Fix hashtab overflow check on
    32-bit arches The hashtab code relies on roundup_pow_of_two() to compute the number of hash buckets, and
    contains an overflow check by checking if the resulting value is 0. However, on 32-bit arches, the roundup
    code itself can overflow by doing a 32-bit left-shift of an unsigned long value, which is undefined
    behaviour, so it is not guaranteed to truncate neatly. This was triggered by syzbot on the DEVMAP_HASH
    type, which contains the same check, copied from the hashtab code. So apply the same fix to hashtab, by
    moving the overflow check to before the roundup.(CVE-2024-26884)

    In the Linux kernel, the following vulnerability has been resolved: bpf: Fix stackmap overflow check on
    32-bit arches The stackmap code relies on roundup_pow_of_two() to compute the number of hash buckets, and
    contains an overflow check by checking if the resulting value is 0. However, on 32-bit arches, the roundup
    code itself can overflow by doing a 32-bit left-shift of an unsigned long value, which is undefined
    behaviour, so it is not guaranteed to truncate neatly. This was triggered by syzbot on the DEVMAP_HASH
    type, which contains the same check, copied from the hashtab code. The commit in the fixes tag actually
    attempted to fix this, but the fix did not account for the UB, so the fix only works on CPUs where an
    overflow does result in a neat truncation to zero, which is not guaranteed. Checking the value before
    rounding does not have this problem.(CVE-2024-26883)

    In the Linux kernel, the following vulnerability has been resolved: cachefiles: fix memory leak in
    cachefiles_add_cache()(CVE-2024-26840)

    In the Linux kernel, the following vulnerability has been resolved: dm-crypt: don't modify the data when
    using authenticated encryption It was said that authenticated encryption could produce invalid tag when
    the data that is being encrypted is modified [1]. So, fix this problem by copying the data into the clone
    bio first and then encrypt them inside the clone bio. This may reduce performance, but it is needed to
    prevent the user from corrupting the device by writing data with O_DIRECT and modifying them at the same
    time.(CVE-2024-26763)

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

    In the Linux kernel, the following vulnerability has been resolved: ext4: avoid allocating blocks from
    corrupted group in ext4_mb_find_by_goal() Places the logic for checking if the group's block bitmap is
    corrupt under the protection of the group lock to avoid allocating blocks from the group with a corrupted
    block bitmap.(CVE-2024-26772)

    In the Linux kernel, the following vulnerability has been resolved: ext4: avoid allocating blocks from
    corrupted group in ext4_mb_try_best_found() Determine if the group block bitmap is corrupted before using
    ac_b_ex in ext4_mb_try_best_found() to avoid allocating blocks from a group with a corrupted block bitmap
    in the following concurrency and making the situation worse. ext4_mb_regular_allocator ext4_lock_group(sb,
    group) ext4_mb_good_group // check if the group bbitmap is corrupted ext4_mb_complex_scan_group // Scan
    group gets ac_b_ex but doesn't use it ext4_unlock_group(sb, group) ext4_mark_group_bitmap_corrupted(group)
    // The block bitmap was corrupted during // the group unlock gap. ext4_mb_try_best_found
    ext4_lock_group(ac-ac_sb, group) ext4_mb_use_best_found mb_mark_used // Allocating blocks in block
    bitmap corrupted group(CVE-2024-26773)

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

    In the Linux kernel, the following vulnerability has been resolved: fs/aio: Restrict kiocb_set_cancel_fn()
    to I/O submitted via libaio If kiocb_set_cancel_fn() is called for I/O submitted via io_uring, the
    following kernel warning appears: WARNING: CPU: 3 PID: 368 at fs/aio.c:598 kiocb_set_cancel_fn+0x9c/0xa8
    Call trace: kiocb_set_cancel_fn+0x9c/0xa8 ffs_epfile_read_iter+0x144/0x1d0 io_read+0x19c/0x498
    io_issue_sqe+0x118/0x27c io_submit_sqes+0x25c/0x5fc __arm64_sys_io_uring_enter+0x104/0xab0
    invoke_syscall+0x58/0x11c el0_svc_common+0xb4/0xf4 do_el0_svc+0x2c/0xb0 el0_svc+0x2c/0xa4
    el0t_64_sync_handler+0x68/0xb4 el0t_64_sync+0x1a4/0x1a8 Fix this by setting the IOCB_AIO_RW flag for read
    and write I/O that is submitted by libaio.(CVE-2024-26764)

    In the Linux kernel, the following vulnerability has been resolved: fs/proc: do_task_stat: use sig-
    stats_lock to gather the threads/children stats lock_task_sighand() can trigger a hard lockup. If
    NR_CPUS threads call do_task_stat() at the same time and the process has NR_THREADS, it will spin with
    irqs disabled O(NR_CPUS * NR_THREADS) time. Change do_task_stat() to use sig-stats_lock to gather the
    statistics outside of -siglock protected section, in the likely case this code will run
    lockless.(CVE-2024-26686)

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

    In the Linux kernel, the following vulnerability has been resolved: IB/hfi1: Fix a memleak in
    init_credit_return When dma_alloc_coherent fails to allocate dd-cr_base[i].va, init_credit_return
    should deallocate dd-cr_base and dd-cr_base[i] that allocated before. Or those resources would be
    never freed and a memleak is triggered.(CVE-2024-26839)

    In the Linux kernel, the following vulnerability has been resolved: inet: read sk-sk_family once in
    inet_recv_error() inet_recv_error() is called without holding the socket lock. IPv6 socket could mutate to
    IPv4 with IPV6_ADDRFORM socket option and trigger a KCSAN warning.(CVE-2024-26679)

    In the Linux kernel, the following vulnerability has been resolved: ip6_tunnel: fix NEXTHDR_FRAGMENT
    handling in ip6_tnl_parse_tlv_enc_lim() syzbot pointed out [1] that NEXTHDR_FRAGMENT handling is broken.
    Reading frag_off can only be done if we pulled enough bytes to skb-head. Currently we might access
    garbage.(CVE-2024-26633)

    In the Linux kernel, the following vulnerability has been resolved: ip6_tunnel: make sure to pull inner
    header in __ip6_tnl_rcv() syzbot found __ip6_tnl_rcv() could access unitiliazed data [1]. Call
    pskb_inet_may_pull() to fix this, and initialize ipv6h variable after this call as it can change skb-
    head.(CVE-2024-26641)

    In the Linux kernel, the following vulnerability has been resolved: ipv6: sr: fix possible use-after-free
    and null-ptr-deref The pernet operations structure for the subsystem must be registered before registering
    the generic netlink family.(CVE-2024-26735)

    In the Linux kernel, the following vulnerability has been resolved: l2tp: pass correct message length to
    ip6_append_data l2tp_ip6_sendmsg needs to avoid accounting for the transport header twice when splicing
    more data into an already partially-occupied skbuff. To manage this, we check whether the skbuff contains
    data using skb_queue_empty when deciding how much data to append using ip6_append_data. However, the code
    which performed the calculation was incorrect: ulen = len + skb_queue_empty(sk-sk_write_queue) ?
    transhdrlen : 0; ...due to C operator precedence, this ends up setting ulen to transhdrlen for messages
    with a non-zero length, which results in corrupted packets on the wire. Add parentheses to correct the
    calculation in line with the original intent.(CVE-2024-26752)

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

    In the Linux kernel, the following vulnerability has been resolved: media: pvrusb2: fix uaf in
    pvr2_context_set_notify(CVE-2024-26875)

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

    In the Linux kernel, the following vulnerability has been resolved: net/bnx2x: Prevent access to a freed
    page in page_pool Fix race condition leading to system crash during EEH error handling During EEH error
    recovery, the bnx2x driver's transmit timeout logic could cause a race condition when handling reset
    tasks. The bnx2x_tx_timeout() schedules reset tasks via bnx2x_sp_rtnl_task(), which ultimately leads to
    bnx2x_nic_unload(). In bnx2x_nic_unload() SGEs are freed using bnx2x_free_rx_sge_range(). However, this
    could overlap with the EEH driver's attempt to reset the device using bnx2x_io_slot_reset(), which also
    tries to free SGEs.(CVE-2024-26859)

    In the Linux kernel, the following vulnerability has been resolved: net/sched: act_mirred: don't override
    retval if we already lost the skb If we're redirecting the skb, and haven't called tcf_mirred_forward(),
    yet, we need to tell the core to drop the skb by setting the retcode to SHOT. If we have called
    tcf_mirred_forward(), however, the skb is out of our hands and returning SHOT will lead to UaF. Move the
    retval override to the error path which actually need it.(CVE-2024-26739)

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

    In the Linux kernel, the following vulnerability has been resolved: net/sched: flower: Fix chain template
    offload When a qdisc is deleted from a net device the stack instructs the underlying driver to remove its
    flow offload callback from the associated filter block using the 'FLOW_BLOCK_UNBIND' command. The stack
    then continues to replay the removal of the filters in the block for this driver by iterating over the
    chains in the block and invoking the 'reoffload' operation of the classifier being used. In turn, the
    classifier in its 'reoffload' operation prepares and emits a 'FLOW_CLS_DESTROY' command for each filter.
    However, the stack does not do the same for chain templates and the underlying driver never receives a
    'FLOW_CLS_TMPLT_DESTROY' command when a qdisc is deleted.(CVE-2024-26669)

    In the Linux kernel, the following vulnerability has been resolved: net/sched: flower: Fix chain template
    offload When a qdisc is deleted from a net device the stack instructs the underlying driver to remove its
    flow offload callback from the associated filter block using the 'FLOW_BLOCK_UNBIND' command. The stack
    then continues to replay the removal of the filters in the block for this driver by iterating over the
    chains in the block and invoking the 'reoffload' operation of the classifier being used. In turn, the
    classifier in its 'reoffload' operation prepares and emits a 'FLOW_CLS_DESTROY' command for each filter.
    However, the stack does not do the same for chain templates and the underlying driver never receives a
    'FLOW_CLS_TMPLT_DESTROY' command when a qdisc is deleted.(CVE-2024-26671)

    In the Linux kernel, the following vulnerability has been resolved: net: ice: Fix potential NULL pointer
    dereference in ice_bridge_setlink() The function ice_bridge_setlink() may encounter a NULL pointer
    dereference if nlmsg_find_attr() returns NULL and br_spec is dereferenced subsequently in
    nla_for_each_nested(). To address this issue, add a check to ensure that br_spec is not NULL before
    proceeding with the nested attribute iteration.(CVE-2024-26855)

    In the Linux kernel, the following vulnerability has been resolved: net: ip_tunnel: make sure to pull
    inner header in ip_tunnel_rcv() Apply the same fix than ones found in : 8d975c15c0cd ('ip6_tunnel: make
    sure to pull inner header in __ip6_tnl_rcv()') 1ca1ba465e55 ('geneve: make sure to pull inner header in
    geneve_rx()') We have to save skb-network_header in a temporary variable in order to be able to
    recompute the network_header pointer after a pskb_inet_may_pull() call. pskb_inet_may_pull() makes sure
    the needed headers are in skb-head.(CVE-2024-26882)

    In the Linux kernel, the following vulnerability has been resolved: net: ip_tunnel: prevent perpetual
    headroom growth syzkaller triggered following kasan splat: BUG: KASAN: use-after-free in
    __skb_flow_dissect+0x19d1/0x7a50(CVE-2024-26804)

    In the Linux kernel, the following vulnerability has been resolved: netfilter: nf_conntrack_h323: Add
    protection for bmp length out of range UBSAN load reports an exception of BRK#5515 SHIFT_ISSUE:Bitwise
    shifts that are out of bounds for their data type.(CVE-2024-26851)

    In the Linux kernel, the following vulnerability has been resolved: netfilter: nf_tables: disallow
    anonymous set with timeout flag Anonymous sets are never used with timeout from userspace, reject this.
    Exception to this rule is NFT_SET_EVAL to ensure legacy meters still work.(CVE-2024-26642)

    In the Linux kernel, the following vulnerability has been resolved: netfilter: nf_tables: disallow timeout
    for anonymous sets Never used from userspace, disallow these parameters.(CVE-2023-52620)

    In the Linux kernel, the following vulnerability has been resolved: netfilter: nft_limit: reject
    configurations that cause integer overflow Reject bogus configs where internal token counter wraps around.
    This only occurs with very very large requests, such as 17gbyte/s. Its better to reject this rather than
    having incorrect ratelimit.(CVE-2024-26668)

    In the Linux kernel, the following vulnerability has been resolved: netlink: Fix kernel-infoleak-after-
    free in __skb_datagram_iter syzbot reported the following uninit-value access issue [1]:
    netlink_to_full_skb() creates a new `skb` and puts the `skb-data` passed as a 1st arg of
    netlink_to_full_skb() onto new `skb`. The data size is specified as `len` and passed to skb_put_data().
    This `len` is based on `skb-end` that is not data offset but buffer offset. The `skb-end` contains
    data and tailroom. Since the tailroom is not initialized when the new `skb` created, KMSAN detects
    uninitialized memory area when copying the data. This patch resolved this issue by correct the len from
    `skb-end` to `skb-len`, which is the actual data offset.(CVE-2024-26805)

    In the Linux kernel, the following vulnerability has been resolved: ppp_async: limit MRU to 64K syzbot
    triggered a warning [1] in __alloc_pages(): WARN_ON_ONCE_GFP(order  MAX_PAGE_ORDER, gfp) Willem fixed a
    similar issue in commit c0a2a1b0d631 ('ppp: limit MRU to 64K') Adopt the same sanity check for
    ppp_async_ioctl(PPPIOCSMRU)(CVE-2024-26675)

    In the Linux kernel, the following vulnerability has been resolved: pstore/ram: Fix crash when setting
    number of cpus to an odd number When the number of cpu cores is adjusted to 7 or other odd numbers, the
    zone size will become an odd number. The address of the zone will become: addr of zone0 = BASE addr of
    zone1 = BASE + zone_size addr of zone2 = BASE + zone_size*2 ... The address of zone1/3/5/7 will be mapped
    to non-alignment va. Eventually crashes will occur when accessing these va. So, use ALIGN_DOWN() to make
    sure the zone size is even to avoid this bug.(CVE-2023-52619)

    In the Linux kernel, the following vulnerability has been resolved: quota: Fix potential NULL pointer
    dereference Below race may cause NULL pointer dereference P1 P2 dquot_free_inode quota_off drop_dquot_ref
    remove_dquot_ref dquots = i_dquot(inode) dquots = i_dquot(inode) srcu_read_lock dquots[cnt]) != NULL (1)
    dquots[type] = NULL (2) spin_lock(dquots[cnt]-dq_dqb_lock) (3) .... If dquot_free_inode(or other
    routines) checks inode's quota pointers (1) before quota_off sets it to NULL(2) and use it (3) after that,
    NULL pointer dereference will be triggered. So let's fix it by using a temporary pointer to avoid this
    issue.(CVE-2024-26878)

    In the Linux kernel, the following vulnerability has been resolved: RDMA/qedr: Fix qedr_create_user_qp
    error flow Avoid the following warning by making sure to free the allocated resources in case that
    qedr_init_user_queue() fail.(CVE-2024-26743)

    In the Linux kernel, the following vulnerability has been resolved: RDMA/srp: Do not call scsi_done() from
    srp_abort() After scmd_eh_abort_handler() has called the SCSI LLD eh_abort_handler callback, it performs
    one of the following actions: * Call scsi_queue_insert(). * Call scsi_finish_command(). * Call
    scsi_eh_scmd_add(). Hence, SCSI abort handlers must not call scsi_done(). Otherwise all the above actions
    would trigger a use-after-free. Hence remove the scsi_done() call from srp_abort(). Keep the
    srp_free_req() call before returning SUCCESS because we may not see the command again if SUCCESS is
    returned.(CVE-2023-52515)

    In the Linux kernel, the following vulnerability has been resolved: RDMA/srpt: Do not register event
    handler until srpt device is fully setup Upon rare occasions, KASAN reports a use-after-free Write in
    srpt_refresh_port(). This seems to be because an event handler is registered before the srpt device is
    fully setup and a race condition upon error may leave a partially setup event handler in place. Instead,
    only register the event handler after srpt device initialization is complete.(CVE-2024-26872)

    In the Linux kernel, the following vulnerability has been resolved: RDMA/srpt: Support specifying the
    srpt_service_guid parameter Make loading ib_srpt with this parameter set work. The current behavior is
    that setting that parameter while loading the ib_srpt kernel module triggers the following kernel crash:
    BUG: kernel NULL pointer dereference, address: 0000000000000000(CVE-2024-26744)

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

    In the Linux kernel, the following vulnerability has been resolved: SUNRPC: Fix a suspicious RCU usage
    warning I received the following warning while running cthon against an ontap server running pNFS: [
    57.202521] ============================= [ 57.202522] WARNING: suspicious RCU usage [ 57.202523]
    6.7.0-rc3-g2cc14f52aeb7 #41492 Not tainted [ 57.202525] ----------------------------- [ 57.202525]
    net/sunrpc/xprtmultipath.c:349 RCU-list traversed in non-reader section!! [ 57.202527] other info that
    might help us debug this: [ 57.202528] rcu_scheduler_active = 2, debug_locks = 1 [ 57.202529] no locks
    held by test5/3567. [ 57.202530] stack backtrace: [ 57.202532] CPU: 0 PID: 3567 Comm: test5 Not tainted
    6.7.0-rc3-g2cc14f52aeb7 #41492 5b09971b4965c0aceba19f3eea324a4a806e227e [ 57.202534] Hardware name: QEMU
    Standard PC (Q35 + ICH9, 2009), BIOS unknown 2/2/2022 [ 57.202536](CVE-2023-52623)

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

    In the Linux kernel, the following vulnerability has been resolved: tipc: Check the bearer type before
    calling tipc_udp_nl_bearer_add() syzbot reported the following general protection fault [1]: general
    protection fault, probably for non-canonical address 0xdffffc0000000010: 0000 [#1] PREEMPT SMP KASAN
    KASAN: null-ptr-deref in range [0x0000000000000080-0x0000000000000087] ...The cause of this issue is
    that when tipc_nl_bearer_add() is called with the TIPC_NLA_BEARER_UDP_OPTS attribute,
    tipc_udp_nl_bearer_add() is called even if the bearer is not UDP. tipc_udp_is_known_peer() called by
    tipc_udp_nl_bearer_add() assumes that the media_ptr field of the tipc_bearer has an udp_bearer type
    object, so the function goes crazy for non-UDP bearers. This patch fixes the issue by checking the bearer
    type before calling tipc_udp_nl_bearer_add() in tipc_nl_bearer_add().(CVE-2024-26663)

    In the Linux kernel, the following vulnerability has been resolved: tracing: Ensure visibility when
    inserting an element into tracing_map Running the following two commands in parallel on a multi-processor
    AArch64 machine can sporadically produce an unexpected warning about duplicate histogram entries: $ while
    true; do echo hist:key=id.syscall:val=hitcount  \
    /sys/kernel/debug/tracing/events/raw_syscalls/sys_enter/trigger cat
    /sys/kernel/debug/tracing/events/raw_syscalls/sys_enter/hist sleep 0.001 done $ stress-ng --sysbadaddr
    $(nproc)(CVE-2024-26645)

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

    In the Linux kernel, the following vulnerability has been resolved: vfio/pci: Lock external INTx masking
    ops Mask operations through config space changes to DisINTx may race INTx configuration changes via ioctl.
    Create wrappers that add locking for paths outside of the core interrupt code. In particular, irq_type is
    updated holding igate, therefore testing is_intx() requires holding igate. For example clearing DisINTx
    from config space can otherwise race changes of the interrupt configuration. This aligns interfaces which
    may trigger the INTx eventfd into two camps, one side serialized by igate and the other only enabled while
    INTx is configured. A subsequent patch introduces synchronization for the latter flows.(CVE-2024-26810)

    In the Linux kernel, the following vulnerability has been resolved: vfio/platform: Create persistent IRQ
    handlers The vfio-platform SET_IRQS ioctl currently allows loopback triggering of an interrupt before a
    signaling eventfd has been configured by the user, which thereby allows a NULL pointer dereference. Rather
    than register the IRQ relative to a valid trigger, register all IRQs in a disabled state in the device
    open path. This allows mask operations on the IRQ to nest within the overall enable state governed by a
    valid eventfd signal. This decouples @masked, protected by the @locked spinlock from @trigger, protected
    via the @igate mutex. In doing so, it's guaranteed that changes to @trigger cannot race the IRQ handlers
    because the IRQ handler is synchronously disabled before modifying the trigger, and loopback triggering of
    the IRQ via ioctl is safe due to serialization with trigger changes via igate. For compatibility,
    request_irq() failures are maintained to be local to the SET_IRQS ioctl rather than a fatal error in the
    open device path. This allows, for example, a userspace driver with polling mode support to continue to
    work regardless of moving the request_irq() call site. This necessarily blocks all SET_IRQS access to the
    failed index.(CVE-2024-26813)

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

    In the Linux kernel, the following vulnerability has been resolved:crypto: scomp - fix req-dst buffer
    overflow.The req-dst buffer size should be checked before copying from the scomp_scratch-dst to
    avoid req-dst buffer overflow problem.(CVE-2023-52612)

    In the Linux kernel, the following vulnerability has been resolved:tracing/trigger: Fix to return error if
    failed to alloc snapshot.Fix register_snapshot_trigger() to return error code if it failed to allocate a
    snapshot instead of 0 (success). Unless that, it will register snapshot trigger without an
    error.(CVE-2024-26920)

    In the Linux kernel, the following vulnerability has been resolved:vfio/pci: Disable auto-enable of
    exclusive INTx IRQ.Currently for devices requiring masking at the irqchip for INTx, ie. devices without
    DisINTx support, the IRQ is enabled in request_irq() and subsequently disabled as necessary to align with
    the masked status flag.  This presents a window where the interrupt could fire between these events,
    resulting in the IRQ incrementing the disable depth twice.This would be unrecoverable for a user since the
    masked flag prevents nested enables through vfio.Instead, invert the logic using IRQF_NO_AUTOEN such that
    exclusive INTx is never auto-enabled, then unmask as required.(CVE-2024-27437)

    Integer Overflow or Wraparound vulnerability in Linux Linux kernel kernel on Linux, x86, ARM (md, raid,
    raid5 modules) allows Forced Integer Overflow.(CVE-2024-23307)

    In the Linux kernel, the following vulnerability has been resolved: aoe: fix the potential use-after-free
    problem in aoecmd_cfg_pkts This patch is against CVE-2023-6270. The description of cve is: A flaw was
    found in the ATA over Ethernet (AoE) driver in the Linux kernel. The aoecmd_cfg_pkts() function improperly
    updates the refcnt on `struct net_device`, and a use-after-free can be triggered by racing between the
    free on the struct and the access through the `skbtxq` global queue. This could lead to a denial of
    service condition or potential code execution. In aoecmd_cfg_pkts(), it always calls dev_put(ifp) when skb
    initial code is finished. But the net_device ifp will still be used in later tx()-dev_queue_xmit() in
    kthread. Which means that the dev_put(ifp) should NOT be called in the success path of skb initial code in
    aoecmd_cfg_pkts(). Otherwise tx() may run into use-after-free because the net_device is freed. This patch
    removed the dev_put(ifp) in the success path in aoecmd_cfg_pkts(), and added dev_put() after skb xmit in
    tx().(CVE-2024-26898)

    In the Linux kernel, the following vulnerability has been resolved: NFSv4.2: fix nfs4_listxattr kernel BUG
    at mm/usercopy.c:102 A call to listxattr() with a buffer size = 0 returns the actual size of the buffer
    needed for a subsequent call. When size  0, nfs4_listxattr() does not return an error because either
    generic_listxattr() or nfs4_listxattr_nfs4_label() consumes exactly all the bytes then size is 0 when
    calling nfs4_listxattr_nfs4_user() which then triggers the following kernel BUG: [ 99.403778] kernel BUG
    at mm/usercopy.c:102! [ 99.404063] Internal error: Oops - BUG: 00000000f2000800 [#1] SMP [ 99.408463] CPU:
    0 PID: 3310 Comm: python3 Not tainted 6.6.0-61.fc40.aarch64 #1 [ 99.415827] Call trace: [ 99.415985]
    usercopy_abort+0x70/0xa0 [ 99.416227] __check_heap_object+0x134/0x158 [ 99.416505]
    check_heap_object+0x150/0x188 [ 99.416696] __check_object_size.part.0+0x78/0x168 [ 99.416886]
    __check_object_size+0x28/0x40 [ 99.417078] listxattr+0x8c/0x120 [ 99.417252] path_listxattr+0x78/0xe0 [
    99.417476] __arm64_sys_listxattr+0x28/0x40 [ 99.417723] invoke_syscall+0x78/0x100 [ 99.417929]
    el0_svc_common.constprop.0+0x48/0xf0 [ 99.418186] do_el0_svc+0x24/0x38 [ 99.418376] el0_svc+0x3c/0x110 [
    99.418554] el0t_64_sync_handler+0x120/0x130 [ 99.418788] el0t_64_sync+0x194/0x198 [ 99.418994] Code:
    aa0003e3 d000a3e0 91310000 97f49bdb (d4210000) Issue is reproduced when generic_listxattr() returns
    'system.nfs4_acl', thus calling lisxattr() with size = 16 will trigger the bug. Add check on
    nfs4_listxattr() to return ERANGE error when it is called with size  0 and the return value is greater
    than size.(CVE-2024-26870)

    In the Linux kernel, the following vulnerability has been resolved: packet: annotate data-races around
    ignore_outgoing ignore_outgoing is read locklessly from dev_queue_xmit_nit() and packet_getsockopt() Add
    appropriate READ_ONCE()/WRITE_ONCE() annotations. syzbot reported: BUG: KCSAN: data-race in
    dev_queue_xmit_nit(CVE-2024-26862)

    In the Linux kernel, the following vulnerability has been resolved: netfilter: nf_tables: set dormant flag
    on hook register failure We need to set the dormant flag again if we fail to register the hooks. During
    memory pressure hook registration can fail and we end up with a table marked as active but no registered
    hooks. On table/base chain deletion, nf_tables will attempt to unregister the hook again which yields a
    warn splat from the nftables core.(CVE-2024-26835)

    In the Linux kernel, the following vulnerability has been resolved: crypto: ccp - Fix null pointer
    dereference in __sev_platform_shutdown_locked The SEV platform device can be shutdown with a null
    psp_master, e.g., using DEBUG_TEST_DRIVER_REMOVE.(CVE-2024-26695)

    In the Linux kernel, the following vulnerability has been resolved: drm/amd/display: Fix memory leak in
    dm_sw_fini() After destroying dmub_srv, the memory associated with it is not freed, causing a memory leak:
    unreferenced object 0xffff896302b45800 (size 1024): comm '(udev-worker)', pid 222, jiffies 4294894636 hex
    dump (first 32 bytes): 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ................ 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 ................ backtrace (crc 6265fd77): [ffffffff993495ed]
    kmalloc_trace+0x29d/0x340 [ffffffffc0ea4a94] dm_dmub_sw_init+0xb4/0x450 [amdgpu]
    [ffffffffc0ea4e55] dm_sw_init+0x15/0x2b0 [amdgpu] [ffffffffc0ba8557]
    amdgpu_device_init+0x1417/0x24e0 [amdgpu] [ffffffffc0bab285] amdgpu_driver_load_kms+0x15/0x190
    [amdgpu] [ffffffffc0ba09c7] amdgpu_pci_probe+0x187/0x4e0 [amdgpu] [ffffffff9968fd1e]
    local_pci_probe+0x3e/0x90 [ffffffff996918a3] pci_device_probe+0xc3/0x230 [ffffffff99805872]
    really_probe+0xe2/0x480 [ffffffff99805c98] __driver_probe_device+0x78/0x160 [ffffffff99805daf]
    driver_probe_device+0x1f/0x90 [ffffffff9980601e] __driver_attach+0xce/0x1c0 [ffffffff99803170]
    bus_for_each_dev+0x70/0xc0 [ffffffff99804822] bus_add_driver+0x112/0x210 [ffffffff99807245]
    driver_register+0x55/0x100 [ffffffff990012d1] do_one_initcall+0x41/0x300 Fix this by freeing
    dmub_srv after destroying it.(CVE-2024-26833)

    In the Linux kernel, the following vulnerability has been resolved: netfilter: nft_ct: sanitize layer 3
    and 4 protocol number in custom expectations - Disallow families other than NFPROTO_{IPV4,IPV6,INET}. -
    Disallow layer 4 protocol with no ports, since destination port is a mandatory attribute for this
    object.(CVE-2024-26673)

    In the Linux kernel, the following vulnerability has been resolved: devlink: fix possible use-after-free
    and memory leaks in devlink_init() The pernet operations structure for the subsystem must be registered
    before registering the generic netlink family. Make an unregister in case of unsuccessful
    registration.(CVE-2024-26734)

    In the Linux kernel, the following vulnerability has been resolved: bpf: Fix DEVMAP_HASH overflow check on
    32-bit arches The devmap code allocates a number hash buckets equal to the next power of two of the
    max_entries value provided when creating the map. When rounding up to the next power of two, the 32-bit
    variable storing the number of buckets can overflow, and the code checks for overflow by checking if the
    truncated 32-bit value is equal to 0. However, on 32-bit arches the rounding up itself can overflow mid-
    way through, because it ends up doing a left-shift of 32 bits on an unsigned long value. If the size of an
    unsigned long is four bytes, this is undefined behaviour, so there is no guarantee that we'll end up with
    a nice and tidy 0-value at the end. Syzbot managed to turn this into a crash on arm32 by creating a
    DEVMAP_HASH with max_entries  0x80000000 and then trying to update it. Fix this by moving the overflow
    check to before the rounding up operation.(CVE-2024-26885)

    In the Linux kernel, the following vulnerability has been resolved: net/mlx5: Update error handler for
    UCTX and UMEM In the fast unload flow, the device state is set to internal error, which indicates that the
    driver started the destroy process. In this case, when a destroy command is being executed, it should
    return MLX5_CMD_STAT_OK. Fix MLX5_CMD_OP_DESTROY_UCTX and MLX5_CMD_OP_DESTROY_UMEM to return OK instead of
    EIO.(CVE-2021-47212)

    In the Linux kernel, the following vulnerability has been resolved: ice: xsk: return xsk buffers back to
    pool when cleaning the ring Currently we only NULL the xdp_buff pointer in the internal SW ring but we
    never give it back to the xsk buffer pool. This means that buffers can be leaked out of the buff pool and
    never be used again. Add missing xsk_buff_free() call to the routine that is supposed to clean the entries
    that are left in the ring so that these buffers in the umem can be used by other sockets. Also, only go
    through the space that is actually left to be cleaned instead of a whole ring.(CVE-2021-47105)

    In the Linux kernel, the following vulnerability has been resolved: netfilter: nft_chain_filter: handle
    NETDEV_UNREGISTER for inet/ingress basechain Remove netdevice from inet/ingress basechain in case
    NETDEV_UNREGISTER event is reported, otherwise a stale reference to netdevice remains in the hook
    list.(CVE-2024-26808)

    In the Linux kernel, the following vulnerability has been resolved: dmaengine: fix NULL pointer in channel
    unregistration function __dma_async_device_channel_register() can fail. In case of failure, chan-local
    is freed (with free_percpu()), and chan-local is nullified. When dma_async_device_unregister() is
    called (because of managed API or intentionally by DMA controller driver), channels are unconditionally
    unregistered, leading to this NULL pointer: [ 1.318693] Unable to handle kernel NULL pointer dereference
    at virtual address 00000000000000d0 [...] [ 1.484499] Call trace: [ 1.486930] device_del+0x40/0x394 [
    1.490314] device_unregister+0x20/0x7c [ 1.494220] __dma_async_device_channel_unregister+0x68/0xc0 Look at
    dma_async_device_register() function error path, channel device unregistration is done only if chan-
    local is not NULL. Then add the same condition at the beginning of
    __dma_async_device_channel_unregister() function, to avoid NULL pointer issue whatever the API used to
    reach this function.(CVE-2023-52492)

    In the Linux kernel, the following vulnerability has been resolved: mfd: syscon: Fix null pointer
    dereference in of_syscon_register() kasprintf() returns a pointer to dynamically allocated memory which
    can be NULL upon failure.(CVE-2023-52467)

    In the Linux kernel, the following vulnerability has been resolved: nvmet-fc: avoid deadlock on delete
    association path When deleting an association the shutdown path is deadlocking because we try to flush the
    nvmet_wq nested. Avoid this by deadlock by deferring the put work into its own work item.(CVE-2024-26769)

    In the Linux kernel, the following vulnerability has been resolved: xhci: handle isoc Babble and Buffer
    Overrun events properly xHCI 4.9 explicitly forbids assuming that the xHC has released its ownership of a
    multi-TRB TD when it reports an error on one of the early TRBs. Yet the driver makes such assumption and
    releases the TD, allowing the remaining TRBs to be freed or overwritten by new TDs. The xHC should also
    report completion of the final TRB due to its IOC flag being set by us, regardless of prior errors. This
    event cannot be recognized if the TD has already been freed earlier, resulting in 'Transfer event TRB DMA
    ptr not part of current TD' error message. Fix this by reusing the logic for processing isoc Transaction
    Errors. This also handles hosts which fail to report the final completion. Fix transfer length reporting
    on Babble errors. They may be caused by device malfunction, no guarantee that the buffer has been
    filled.(CVE-2024-26659)

    In the Linux kernel, the following vulnerability has been resolved: vfio/fsl-mc: Block calling interrupt
    handler without trigger The eventfd_ctx trigger pointer of the vfio_fsl_mc_irq object is initially NULL
    and may become NULL if the user sets the trigger eventfd to -1. The interrupt handler itself is guaranteed
    that trigger is always valid between request_irq() and free_irq(), but the loopback testing mechanisms to
    invoke the handler function need to test the trigger. The triggering and setting ioctl paths both make use
    of igate and are therefore mutually exclusive. The vfio-fsl-mc driver does not make use of irqfds, nor
    does it support any sort of masking operations, therefore unlike vfio-pci and vfio-platform, the flow can
    remain essentially unchanged.(CVE-2024-26814)

    In the Linux kernel, the following vulnerability has been resolved: tunnels: fix out of bounds access when
    building IPv6 PMTU error If the ICMPv6 error is built from a non-linear skb we get the following splat,
    BUG: KASAN: slab-out-of-bounds in do_csum+0x220/0x240 Read of size 4 at addr ffff88811d402c80 by task
    netperf/820 CPU: 0 PID: 820 Comm: netperf Not tainted 6.8.0-rc1+ #543 ... kasan_report+0xd8/0x110
    do_csum+0x220/0x240 csum_partial+0xc/0x20 skb_tunnel_check_pmtu+0xeb9/0x3280 vxlan_xmit_one+0x14c2/0x4080
    vxlan_xmit+0xf61/0x5c00 dev_hard_start_xmit+0xfb/0x510 __dev_queue_xmit+0x7cd/0x32a0
    br_dev_queue_push_xmit+0x39d/0x6a0 Use skb_checksum instead of csum_partial who cannot deal with non-
    linear SKBs.(CVE-2024-26665)

    In the Linux kernel, the following vulnerability has been resolved: hv_netvsc: Fix race condition between
    netvsc_probe and netvsc_remove In commit ac5047671758 ('hv_netvsc: Disable NAPI before closing the VMBus
    channel'), napi_disable was getting called for all channels, including all subchannels without confirming
    if they are enabled or not. This caused hv_netvsc getting hung at napi_disable, when netvsc_probe() has
    finished running but nvdev-subchan_work has not started yet. netvsc_subchan_work() -
    rndis_set_subchannel() has not created the sub-channels and because of that netvsc_sc_open() is not
    running. netvsc_remove() calls cancel_work_sync(nvdev-subchan_work), for which netvsc_subchan_work
    did not run. netif_napi_add() sets the bit NAPI_STATE_SCHED because it ensures NAPI cannot be scheduled.
    Then netvsc_sc_open() - napi_enable will clear the NAPIF_STATE_SCHED bit, so it can be scheduled.
    napi_disable() does the opposite. Now during netvsc_device_remove(), when napi_disable is called for those
    subchannels, napi_disable gets stuck on infinite msleep. This fix addresses this problem by ensuring that
    napi_disable() is not getting called for non-enabled NAPI struct. But netif_napi_del() is still necessary
    for these non-enabled NAPI struct for cleanup purpose.(CVE-2024-26698)

    In the Linux kernel, the following vulnerability has been resolved: fbcon: always restore the old font
    data in fbcon_do_set_font() Commit a5a923038d70 (fbdev: fbcon: Properly revert changes when vc_resize()
    failed) started restoring old font data upon failure (of vc_resize()). But it performs so only for user
    fonts. It means that the 'system'/internal fonts are not restored at all. So in result, the very first
    call to fbcon_do_set_font() performs no restore at all upon failing vc_resize(). This can be reproduced by
    Syzkaller to crash the system on the next invocation of font_get(). It's rather hard to hit the allocation
    failure in vc_resize() on the first font_set(), but not impossible. Esp. if fault injection is used to aid
    the execution/failure.(CVE-2024-26798)

    In the Linux kernel, the following vulnerability has been resolved: ceph: prevent use-after-free in
    encode_cap_msg() In fs/ceph/caps.c, in encode_cap_msg(), 'use after free' error was caught by KASAN at
    this line - 'ceph_buffer_get(arg-xattr_buf);'. This implies before the refcount could be increment
    here, it was freed. In same file, in 'handle_cap_grant()' refcount is decremented by this line -
    'ceph_buffer_put(ci-i_xattrs.blob);'. It appears that a race occurred and resource was freed by the
    latter line before the former line could increment it. encode_cap_msg() is called by __send_cap() and
    __send_cap() is called by ceph_check_caps() after calling __prep_cap(). __prep_cap() is where arg-
    xattr_buf is assigned to ci-i_xattrs.blob. This is the spot where the refcount must be increased to
    prevent 'use after free' error.(CVE-2024-26689)

    In the Linux kernel, the following vulnerability has been resolved: IB/hfi1: Fix sdma.h tx-num_descs
    off-by-one error Unfortunately the commit `fd8958efe877` introduced another error causing the `descs`
    array to overflow.(CVE-2024-26766)

    In the Linux kernel, the following vulnerability has been resolved: usb: roles: fix NULL pointer issue
    when put module's reference In current design, usb role class driver will get usb_role_switch parent's
    module reference after the user get usb_role_switch device and put the reference after the user put the
    usb_role_switch device. However, the parent device of usb_role_switch may be removed before the user put
    the usb_role_switch. If so, then, NULL pointer issue will be met when the user put the parent module's
    reference. This will save the module pointer in structure of usb_role_switch. Then, we don't need to find
    module by iterating long relations.(CVE-2024-26747)

    In the Linux kernel, the following vulnerability has been resolved: netfilter: nft_set_pipapo: release
    elements in clone only from destroy path Clone already always provides a current view of the lookup table,
    use it to destroy the set, otherwise it is possible to destroy elements twice. This fix requires:
    212ed75dc5fb ('netfilter: nf_tables: integrate pipapo into commit protocol') which came after:
    9827a0e6e23b ('netfilter: nft_set_pipapo: release elements in clone from abort path').(CVE-2024-26809)

    In the Linux kernel, the following vulnerability has been resolved: fs,hugetlb: fix NULL pointer
    dereference in hugetlbs_fill_super When configuring a hugetlb filesystem via the fsconfig() syscall, there
    is a possible NULL dereference in hugetlbfs_fill_super() caused by assigning NULL to ctx-hstate in
    hugetlbfs_parse_param() when the requested pagesize is non valid. E.g: Taking the following steps: fd =
    fsopen('hugetlbfs', FSOPEN_CLOEXEC); fsconfig(fd, FSCONFIG_SET_STRING, 'pagesize', '1024', 0);
    fsconfig(fd, FSCONFIG_CMD_CREATE, NULL, NULL, 0); Given that the requested 'pagesize' is invalid, ctxt-
    hstate will be replaced with NULL, losing its previous value, and we will print an error: ... ... case
    Opt_pagesize: ps = memparse(param-string, rest); ctx-hstate = h; if (!ctx-hstate) {
    pr_err('Unsupported page size %lu MB\n', ps / SZ_1M); return -EINVAL; } return 0; ... ... This is a
    problem because later on, we will dereference ctxt-hstate in hugetlbfs_fill_super() ... ... sb-
    s_blocksize = huge_page_size(ctx-hstate); ... ... Causing below Oops. Fix this by replacing cxt-
    hstate value only when then pagesize is known to be valid.(CVE-2024-26688)

    In the Linux kernel, the following vulnerability has been resolved: ext4: avoid dividing by 0 in
    mb_update_avg_fragment_size() when block bitmap corrupt Determine if bb_fragments is 0 instead of
    determining bb_free to eliminate the risk of dividing by zero when the block bitmap is
    corrupted.(CVE-2024-26774)

    In the Linux kernel, the following vulnerability has been resolved: net: atlantic: Fix DMA mapping for PTP
    hwts ring Function aq_ring_hwts_rx_alloc() maps extra AQ_CFG_RXDS_DEF bytes for PTP HWTS ring but then
    generic aq_ring_free() does not take this into account. Create and use a specific function to free HWTS
    ring to fix this issue.(CVE-2024-26680)

    In the Linux kernel, the following vulnerability has been resolved: netfilter: nftables: exthdr: fix
    4-byte stack OOB write If priv-len is a multiple of 4, then dst[len / 4] can write past the destination
    array which leads to stack corruption. This construct is necessary to clean the remainder of the register
    in case -len is NOT a multiple of the register size, so make it conditional just like nft_payload.c
    does. The bug was added in 4.1 cycle and then copied/inherited when tcp/sctp and ip option support was
    added.(CVE-2023-52628)

    In the Linux kernel, the following vulnerability has been resolved: bpf: Check rcu_read_lock_trace_held()
    before calling bpf map helpers These three bpf_map_{lookup,update,delete}_elem() helpers are also
    available for sleepable bpf program, so add the corresponding lock assertion for sleepable bpf program,
    otherwise the following warning will be reported when a sleepable bpf program manipulates bpf map under
    interpreter mode (aka bpf_jit_enable=0): WARNING: CPU: 3 PID: 4985 at kernel/bpf/helpers.c:40 ...... CPU:
    3 PID: 4985 Comm: test_progs Not tainted 6.6.0+ #2 Hardware name: QEMU Standard PC (i440FX + PIIX, 1996)
    ...... RIP: 0010:bpf_map_lookup_elem+0x54/0x60 ......(CVE-2023-52621)

    In the Linux kernel, the following vulnerability has been resolved: netfilter: nf_tables: mark set as dead
    when unbinding anonymous set with timeout While the rhashtable set gc runs asynchronously, a race allows
    it to collect elements from anonymous sets with timeouts while it is being released from the commit path.
    Mingi Cho originally reported this issue in a different path in 6.1.x with a pipapo set with low timeouts
    which is not possible upstream since 7395dfacfff6 ('netfilter: nf_tables: use timestamp to check for set
    element timeout'). Fix this by setting on the dead flag for anonymous sets to skip async gc in this case.
    According to 08e4c8c5919f ('netfilter: nf_tables: mark newset as dead on transaction abort'), Florian
    plans to accelerate abort path by releasing objects via workqueue, therefore, this sets on the dead flag
    for abort path too.(CVE-2024-26643)

    In the Linux kernel, the following vulnerability has been resolved: KVM: x86/mmu: Don't advance iterator
    after restart due to yielding After dropping mmu_lock in the TDP MMU, restart the iterator during
    tdp_iter_next() and do not advance the iterator. Advancing the iterator results in skipping the top-level
    SPTE and all its children, which is fatal if any of the skipped SPTEs were not visited before yielding.
    When zapping all SPTEs, i.e. when min_level == root_level, restarting the iter and then invoking
    tdp_iter_next() is always fatal if the current gfn has as a valid SPTE, as advancing the iterator results
    in try_step_side() skipping the current gfn, which wasn't visited before yielding. Sprinkle WARNs on iter-
    yielded being true in various helpers that are often used in conjunction with yielding, and tag the
    helper with __must_check to reduce the probabily of improper usage. Failing to zap a top-level SPTE
    manifests in one of two ways. If a valid SPTE is skipped by both kvm_tdp_mmu_zap_all() and
    kvm_tdp_mmu_put_root(), the shadow page will be leaked and KVM will WARN accordingly.(CVE-2021-47094)

    In the Linux kernel, the following vulnerability has been resolved: PM: sleep: Fix possible deadlocks in
    core system-wide PM code It is reported that in low-memory situations the system-wide resume core code
    deadlocks, because async_schedule_dev() executes its argument function synchronously if it cannot allocate
    memory (and not only in that case) and that function attempts to acquire a mutex that is already held.
    Executing the argument function synchronously from within dpm_async_fn() may also be problematic for
    ordering reasons (it may cause a consumer device's resume callback to be invoked before a requisite
    supplier device's one, for example). Address this by changing the code in question to use
    async_schedule_dev_nocall() for scheduling the asynchronous execution of device suspend and resume
    functions and to directly run them synchronously if async_schedule_dev_nocall() returns
    false.(CVE-2023-52498)

    In the Linux kernel, the following vulnerability has been resolved: llc: make llc_ui_sendmsg() more robust
    against bonding changes syzbot was able to trick llc_ui_sendmsg(), allocating an skb with no headroom, but
    subsequently trying to push 14 bytes of Ethernet header [1] Like some others, llc_ui_sendmsg() releases
    the socket lock before calling sock_alloc_send_skb(). Then it acquires it again, but does not redo all the
    sanity checks that were performed. This fix: - Uses LL_RESERVED_SPACE() to reserve space. - Check all
    conditions again after socket lock is held again. - Do not account Ethernet header for mtu
    limitation.(CVE-2024-26636)

Tenable has extracted the preceding description block directly from the EulerOS Virtualization kernel security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2024-2328
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a2c642fa");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26898");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-abi-stablelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python3-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:2.12.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var _release = get_kb_item("Host/EulerOS/release");
if (isnull(_release) || _release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "2.12.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 2.12.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "x86" >!< cpu) audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

var flag = 0;

var pkgs = [
  "bpftool-5.10.0-136.12.0.86.h1837.eulerosv2r12",
  "kernel-5.10.0-136.12.0.86.h1837.eulerosv2r12",
  "kernel-abi-stablelists-5.10.0-136.12.0.86.h1837.eulerosv2r12",
  "kernel-tools-5.10.0-136.12.0.86.h1837.eulerosv2r12",
  "kernel-tools-libs-5.10.0-136.12.0.86.h1837.eulerosv2r12",
  "python3-perf-5.10.0-136.12.0.86.h1837.eulerosv2r12"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

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
