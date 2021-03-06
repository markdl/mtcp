#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

__visible struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0x9d35aeec, __VMLINUX_SYMBOL_STR(module_layout) },
	{ 0x6bc3fbc0, __VMLINUX_SYMBOL_STR(__unregister_chrdev) },
	{ 0x6a10d6c5, __VMLINUX_SYMBOL_STR(netdev_info) },
	{ 0x8a9809d6, __VMLINUX_SYMBOL_STR(kmalloc_caches) },
	{ 0x897f0ccc, __VMLINUX_SYMBOL_STR(pci_bus_read_config_byte) },
	{ 0x205e9bea, __VMLINUX_SYMBOL_STR(pci_bus_type) },
	{ 0xd2b09ce5, __VMLINUX_SYMBOL_STR(__kmalloc) },
	{ 0x351fa0e5, __VMLINUX_SYMBOL_STR(ethtool_op_get_ts_info) },
	{ 0xe4689576, __VMLINUX_SYMBOL_STR(ktime_get_with_offset) },
	{ 0xf9a482f9, __VMLINUX_SYMBOL_STR(msleep) },
	{ 0x773609fd, __VMLINUX_SYMBOL_STR(dcb_ieee_setapp) },
	{ 0x7429842b, __VMLINUX_SYMBOL_STR(pci_enable_sriov) },
	{ 0x9313d603, __VMLINUX_SYMBOL_STR(debugfs_create_dir) },
	{ 0x6bf1c17f, __VMLINUX_SYMBOL_STR(pv_lock_ops) },
	{ 0x349cba85, __VMLINUX_SYMBOL_STR(strchr) },
	{ 0x8323348f, __VMLINUX_SYMBOL_STR(pci_intx_mask_supported) },
	{ 0x91eb9b4, __VMLINUX_SYMBOL_STR(round_jiffies) },
	{ 0x6cbea01, __VMLINUX_SYMBOL_STR(dcb_ieee_delapp) },
	{ 0x5a7fce4a, __VMLINUX_SYMBOL_STR(napi_disable) },
	{ 0xcf76e29b, __VMLINUX_SYMBOL_STR(napi_consume_skb) },
	{ 0xbc1362eb, __VMLINUX_SYMBOL_STR(skb_pad) },
	{ 0x43a53735, __VMLINUX_SYMBOL_STR(__alloc_workqueue_key) },
	{ 0x19f462ab, __VMLINUX_SYMBOL_STR(kfree_call_rcu) },
	{ 0xc4f331c6, __VMLINUX_SYMBOL_STR(cpu_online_mask) },
	{ 0xa11b55b2, __VMLINUX_SYMBOL_STR(xen_start_info) },
	{ 0x79aa04a2, __VMLINUX_SYMBOL_STR(get_random_bytes) },
	{ 0x3d36fcc9, __VMLINUX_SYMBOL_STR(node_data) },
	{ 0xcc808b6d, __VMLINUX_SYMBOL_STR(dev_mc_add_excl) },
	{ 0xa50a80c2, __VMLINUX_SYMBOL_STR(boot_cpu_data) },
	{ 0xf9a4f491, __VMLINUX_SYMBOL_STR(pci_disable_device) },
	{ 0xf31a9678, __VMLINUX_SYMBOL_STR(dev_uc_add_excl) },
	{ 0xc7a4fbed, __VMLINUX_SYMBOL_STR(rtnl_lock) },
	{ 0xf272aa29, __VMLINUX_SYMBOL_STR(pci_disable_msix) },
	{ 0x4ea25709, __VMLINUX_SYMBOL_STR(dql_reset) },
	{ 0x7ad6ac18, __VMLINUX_SYMBOL_STR(netif_carrier_on) },
	{ 0xd9d3bcd3, __VMLINUX_SYMBOL_STR(_raw_spin_lock_bh) },
	{ 0x227d2f05, __VMLINUX_SYMBOL_STR(pci_disable_sriov) },
	{ 0x2ed05c78, __VMLINUX_SYMBOL_STR(__hw_addr_sync_dev) },
	{ 0xc0a3d105, __VMLINUX_SYMBOL_STR(find_next_bit) },
	{ 0xe92a8028, __VMLINUX_SYMBOL_STR(netif_carrier_off) },
	{ 0x88bfa7e, __VMLINUX_SYMBOL_STR(cancel_work_sync) },
	{ 0x206a59d2, __VMLINUX_SYMBOL_STR(uio_unregister_device) },
	{ 0x44b1d426, __VMLINUX_SYMBOL_STR(__dynamic_pr_debug) },
	{ 0x177758bc, __VMLINUX_SYMBOL_STR(__register_chrdev) },
	{ 0x7b40e206, __VMLINUX_SYMBOL_STR(__dev_kfree_skb_any) },
	{ 0xeae3dfd6, __VMLINUX_SYMBOL_STR(__const_udelay) },
	{ 0x9580deb, __VMLINUX_SYMBOL_STR(init_timer_key) },
	{ 0x347cd1b3, __VMLINUX_SYMBOL_STR(mutex_unlock) },
	{ 0xbc82831d, __VMLINUX_SYMBOL_STR(debugfs_create_file) },
	{ 0x4629334c, __VMLINUX_SYMBOL_STR(__preempt_count) },
	{ 0x7a2af7b4, __VMLINUX_SYMBOL_STR(cpu_number) },
	{ 0xdf6a4b91, __VMLINUX_SYMBOL_STR(ipv6_find_hdr) },
	{ 0x3c050e81, __VMLINUX_SYMBOL_STR(debugfs_remove_recursive) },
	{ 0xf4c91ed, __VMLINUX_SYMBOL_STR(ns_to_timespec) },
	{ 0x8448f098, __VMLINUX_SYMBOL_STR(sysfs_remove_group) },
	{ 0xf38b46d, __VMLINUX_SYMBOL_STR(__alloc_pages_nodemask) },
	{ 0xf8de2d88, __VMLINUX_SYMBOL_STR(netif_napi_del) },
	{ 0x7d11c268, __VMLINUX_SYMBOL_STR(jiffies) },
	{ 0x59055f2d, __VMLINUX_SYMBOL_STR(__dynamic_netdev_dbg) },
	{ 0xe2d5255a, __VMLINUX_SYMBOL_STR(strcmp) },
	{ 0xa2d9c767, __VMLINUX_SYMBOL_STR(netif_rx) },
	{ 0xe4ef9c5a, __VMLINUX_SYMBOL_STR(__pskb_pull_tail) },
	{ 0xee0b0414, __VMLINUX_SYMBOL_STR(ptp_clock_unregister) },
	{ 0x4f8b5ddb, __VMLINUX_SYMBOL_STR(_copy_to_user) },
	{ 0xb97a8d7, __VMLINUX_SYMBOL_STR(param_ops_charp) },
	{ 0xfb6d4da3, __VMLINUX_SYMBOL_STR(pci_set_master) },
	{ 0xf5a4c3fe, __VMLINUX_SYMBOL_STR(netif_schedule_queue) },
	{ 0x706d051c, __VMLINUX_SYMBOL_STR(del_timer_sync) },
	{ 0x3c80c06c, __VMLINUX_SYMBOL_STR(kstrtoull) },
	{ 0xfb578fc5, __VMLINUX_SYMBOL_STR(memset) },
	{ 0x4e0994c1, __VMLINUX_SYMBOL_STR(pci_enable_pcie_error_reporting) },
	{ 0xd58277, __VMLINUX_SYMBOL_STR(netif_tx_wake_queue) },
	{ 0x41d9cd2d, __VMLINUX_SYMBOL_STR(pci_enable_msix) },
	{ 0xaa8e404, __VMLINUX_SYMBOL_STR(pci_restore_state) },
	{ 0x14b9bd13, __VMLINUX_SYMBOL_STR(netif_tx_stop_all_queues) },
	{ 0x194651a6, __VMLINUX_SYMBOL_STR(dev_err) },
	{ 0x17d070c2, __VMLINUX_SYMBOL_STR(__mutex_init) },
	{ 0x15ca1334, __VMLINUX_SYMBOL_STR(netif_set_xps_queue) },
	{ 0x27e1a049, __VMLINUX_SYMBOL_STR(printk) },
	{ 0x19c18373, __VMLINUX_SYMBOL_STR(ethtool_op_get_link) },
	{ 0x20c55ae0, __VMLINUX_SYMBOL_STR(sscanf) },
	{ 0x3c3fce39, __VMLINUX_SYMBOL_STR(__local_bh_enable_ip) },
	{ 0x33ea1df0, __VMLINUX_SYMBOL_STR(sysfs_create_group) },
	{ 0x449ad0a7, __VMLINUX_SYMBOL_STR(memcmp) },
	{ 0xa00aca2a, __VMLINUX_SYMBOL_STR(dql_completed) },
	{ 0x4c9d28b0, __VMLINUX_SYMBOL_STR(phys_base) },
	{ 0xcd279169, __VMLINUX_SYMBOL_STR(nla_find) },
	{ 0xb6b37f56, __VMLINUX_SYMBOL_STR(free_netdev) },
	{ 0x9166fada, __VMLINUX_SYMBOL_STR(strncpy) },
	{ 0xc56e920c, __VMLINUX_SYMBOL_STR(register_netdev) },
	{ 0x963876ac, __VMLINUX_SYMBOL_STR(dcbnl_ieee_notify) },
	{ 0x5a921311, __VMLINUX_SYMBOL_STR(strncmp) },
	{ 0x5792f848, __VMLINUX_SYMBOL_STR(strlcpy) },
	{ 0x16305289, __VMLINUX_SYMBOL_STR(warn_slowpath_null) },
	{ 0x11761f56, __VMLINUX_SYMBOL_STR(mutex_lock) },
	{ 0x8c03d20c, __VMLINUX_SYMBOL_STR(destroy_workqueue) },
	{ 0xe008721d, __VMLINUX_SYMBOL_STR(netif_set_real_num_rx_queues) },
	{ 0xf4f14de6, __VMLINUX_SYMBOL_STR(rtnl_trylock) },
	{ 0x16e5c2a, __VMLINUX_SYMBOL_STR(mod_timer) },
	{ 0x6db62594, __VMLINUX_SYMBOL_STR(netif_set_real_num_tx_queues) },
	{ 0x23ff7f97, __VMLINUX_SYMBOL_STR(netif_napi_add) },
	{ 0x919412ef, __VMLINUX_SYMBOL_STR(ptp_clock_register) },
	{ 0x2072ee9b, __VMLINUX_SYMBOL_STR(request_threaded_irq) },
	{ 0x4d32f7f6, __VMLINUX_SYMBOL_STR(simple_open) },
	{ 0x1096cae7, __VMLINUX_SYMBOL_STR(__get_page_tail) },
	{ 0xe523ad75, __VMLINUX_SYMBOL_STR(synchronize_irq) },
	{ 0x41c2eb24, __VMLINUX_SYMBOL_STR(arch_dma_alloc_attrs) },
	{ 0xd1fbbfae, __VMLINUX_SYMBOL_STR(dev_notice) },
	{ 0xc911b9d5, __VMLINUX_SYMBOL_STR(eth_get_headlen) },
	{ 0x167c5967, __VMLINUX_SYMBOL_STR(print_hex_dump) },
	{ 0xe3c488cb, __VMLINUX_SYMBOL_STR(pci_select_bars) },
	{ 0xd1e2f093, __VMLINUX_SYMBOL_STR(napi_gro_receive) },
	{ 0xd9607266, __VMLINUX_SYMBOL_STR(_dev_info) },
	{ 0x878262e1, __VMLINUX_SYMBOL_STR(__hw_addr_unsync_dev) },
	{ 0x78764f4e, __VMLINUX_SYMBOL_STR(pv_irq_ops) },
	{ 0x31988f5, __VMLINUX_SYMBOL_STR(__free_pages) },
	{ 0x618911fc, __VMLINUX_SYMBOL_STR(numa_node) },
	{ 0x42c8de35, __VMLINUX_SYMBOL_STR(ioremap_nocache) },
	{ 0xaaa8830b, __VMLINUX_SYMBOL_STR(pci_enable_msix_range) },
	{ 0x12a38747, __VMLINUX_SYMBOL_STR(usleep_range) },
	{ 0x3fd62d24, __VMLINUX_SYMBOL_STR(ipv6_skip_exthdr) },
	{ 0x724bcf15, __VMLINUX_SYMBOL_STR(__napi_schedule) },
	{ 0x5944d015, __VMLINUX_SYMBOL_STR(__cachemode2pte_tbl) },
	{ 0xbba70a2d, __VMLINUX_SYMBOL_STR(_raw_spin_unlock_bh) },
	{ 0xb79b43c9, __VMLINUX_SYMBOL_STR(pci_cleanup_aer_uncorrect_error_status) },
	{ 0xdb7305a1, __VMLINUX_SYMBOL_STR(__stack_chk_fail) },
	{ 0xc92cc3eb, __VMLINUX_SYMBOL_STR(pci_intx) },
	{ 0xb495f33f, __VMLINUX_SYMBOL_STR(skb_checksum_help) },
	{ 0x31fd9e17, __VMLINUX_SYMBOL_STR(napi_complete_done) },
	{ 0xc4d760c7, __VMLINUX_SYMBOL_STR(irq_set_affinity_notifier) },
	{ 0x2d0643bd, __VMLINUX_SYMBOL_STR(eth_type_trans) },
	{ 0x2a924b1a, __VMLINUX_SYMBOL_STR(dev_driver_string) },
	{ 0xc9c99c99, __VMLINUX_SYMBOL_STR(pskb_expand_head) },
	{ 0xbdfb6dbb, __VMLINUX_SYMBOL_STR(__fentry__) },
	{ 0xba2decb4, __VMLINUX_SYMBOL_STR(pci_cfg_access_lock) },
	{ 0x79833894, __VMLINUX_SYMBOL_STR(netdev_err) },
	{ 0x467df16d, __VMLINUX_SYMBOL_STR(netdev_rss_key_fill) },
	{ 0x1c7a1fb9, __VMLINUX_SYMBOL_STR(pci_enable_msi_range) },
	{ 0x90f9a77e, __VMLINUX_SYMBOL_STR(pci_unregister_driver) },
	{ 0xcc5005fe, __VMLINUX_SYMBOL_STR(msleep_interruptible) },
	{ 0x2142697b, __VMLINUX_SYMBOL_STR(kmem_cache_alloc_trace) },
	{ 0xe259ae9e, __VMLINUX_SYMBOL_STR(_raw_spin_lock) },
	{ 0x51d204db, __VMLINUX_SYMBOL_STR(__dynamic_dev_dbg) },
	{ 0xe41ababd, __VMLINUX_SYMBOL_STR(pci_set_power_state) },
	{ 0xc6fdb25c, __VMLINUX_SYMBOL_STR(netdev_warn) },
	{ 0x7b037a46, __VMLINUX_SYMBOL_STR(eth_validate_addr) },
	{ 0x1e047854, __VMLINUX_SYMBOL_STR(warn_slowpath_fmt) },
	{ 0x264331ac, __VMLINUX_SYMBOL_STR(pci_disable_pcie_error_reporting) },
	{ 0x37a0cba, __VMLINUX_SYMBOL_STR(kfree) },
	{ 0xa02d7891, __VMLINUX_SYMBOL_STR(remap_pfn_range) },
	{ 0x69acdf38, __VMLINUX_SYMBOL_STR(memcpy) },
	{ 0x7d776068, __VMLINUX_SYMBOL_STR(ptp_clock_index) },
	{ 0xa3a3fe2, __VMLINUX_SYMBOL_STR(pci_disable_msi) },
	{ 0x731dba7a, __VMLINUX_SYMBOL_STR(xen_domain_type) },
	{ 0x33cdf8a, __VMLINUX_SYMBOL_STR(dma_supported) },
	{ 0x487429be, __VMLINUX_SYMBOL_STR(skb_add_rx_frag) },
	{ 0x696600a5, __VMLINUX_SYMBOL_STR(pci_num_vf) },
	{ 0xedc03953, __VMLINUX_SYMBOL_STR(iounmap) },
	{ 0xaceb4f8d, __VMLINUX_SYMBOL_STR(__pci_register_driver) },
	{ 0xa8721b97, __VMLINUX_SYMBOL_STR(system_state) },
	{ 0xb352177e, __VMLINUX_SYMBOL_STR(find_first_bit) },
	{ 0x63c4d61f, __VMLINUX_SYMBOL_STR(__bitmap_weight) },
	{ 0x1a20f56d, __VMLINUX_SYMBOL_STR(dev_warn) },
	{ 0x719df329, __VMLINUX_SYMBOL_STR(__uio_register_device) },
	{ 0xcd8259a, __VMLINUX_SYMBOL_STR(unregister_netdev) },
	{ 0xd255c6da, __VMLINUX_SYMBOL_STR(ndo_dflt_bridge_getlink) },
	{ 0xa7dc745e, __VMLINUX_SYMBOL_STR(netif_wake_subqueue) },
	{ 0x2e0d2f7f, __VMLINUX_SYMBOL_STR(queue_work_on) },
	{ 0x13be4a76, __VMLINUX_SYMBOL_STR(pci_vfs_assigned) },
	{ 0x28318305, __VMLINUX_SYMBOL_STR(snprintf) },
	{ 0x99a109bd, __VMLINUX_SYMBOL_STR(consume_skb) },
	{ 0xd4c104bd, __VMLINUX_SYMBOL_STR(pci_check_and_mask_intx) },
	{ 0x377b603f, __VMLINUX_SYMBOL_STR(pci_enable_device_mem) },
	{ 0x161cd97, __VMLINUX_SYMBOL_STR(__napi_alloc_skb) },
	{ 0x1877cb9c, __VMLINUX_SYMBOL_STR(skb_tstamp_tx) },
	{ 0x30c58d84, __VMLINUX_SYMBOL_STR(pci_enable_device) },
	{ 0x661f9e0d, __VMLINUX_SYMBOL_STR(pci_wake_from_d3) },
	{ 0x5a7730ea, __VMLINUX_SYMBOL_STR(pci_release_selected_regions) },
	{ 0x638bb1a, __VMLINUX_SYMBOL_STR(pci_request_selected_regions) },
	{ 0x4f6b400b, __VMLINUX_SYMBOL_STR(_copy_from_user) },
	{ 0xca7903a1, __VMLINUX_SYMBOL_STR(irq_set_affinity_hint) },
	{ 0x964b0a2f, __VMLINUX_SYMBOL_STR(skb_copy_bits) },
	{ 0x97764186, __VMLINUX_SYMBOL_STR(pci_cfg_access_unlock) },
	{ 0x6e720ff2, __VMLINUX_SYMBOL_STR(rtnl_unlock) },
	{ 0xeb87363c, __VMLINUX_SYMBOL_STR(dma_ops) },
	{ 0x634eb654, __VMLINUX_SYMBOL_STR(pcie_capability_read_word) },
	{ 0x939669e1, __VMLINUX_SYMBOL_STR(device_set_wakeup_enable) },
	{ 0xf20dabd8, __VMLINUX_SYMBOL_STR(free_irq) },
	{ 0xbb261582, __VMLINUX_SYMBOL_STR(pci_save_state) },
	{ 0xca37d94, __VMLINUX_SYMBOL_STR(alloc_etherdev_mqs) },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=uio,ptp";


MODULE_INFO(srcversion, "F9FB8FDE6428B17106BFB28");
