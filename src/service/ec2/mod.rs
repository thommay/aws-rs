use time::Tm;

#[derive(Debug,Clone)]
pub struct Reservation {
    reservation_id: String,
    owner_id: String,
    requester_id: String,
    groups: Vec<Group>,
    instances: Vec<Instance>
}

#[derive(Debug,Clone)]
pub struct Group {
    group_id: String,
    group_name: String
}

pub struct Instance {
    instance_id: String,
    image_id: String,
    state: InstanceState,
    private_dns_name: String,
    public_dns_name: String,
    state_transition_reason: String,
    key_name: String,
    ami_launch_index: usize,
    product_codes: Vec<ProductCode>,
    instance_type: InstanceType,
    launch_time: Tm,
    placement: Placement,
    kernel_id: String,
    ramdisk_id: String,
    platform: Platform,
    monitoring: Monitoring,
    subnet_id: String,
    vpc_id: String,
    private_ip_address: String,
    public_ip_address: String,
    state_reason: StateReason,
    architecture: Architecture,
    root_device_type: DeviceType,
    root_device_name: String,
    block_device_mappings: Vec<InstanceBlockDeviceMapping>,
    virtualization_type: VirtualizationType,
    instance_lifecycle: InstanceLifecycleType,
    spot_instance_request_id: String,
    client_token: String,
    tags: Vec<Tag>,
    security_groups: Vec<Group>,
    source_dest_check: bool,
    hypervisor: HypervisorType,
    network_interfaces: Vec<InstanceNetworkInterface>,
    iam_instance_profile: IamInstanceProfile,
    ebs_optimized: bool,
    sriov_net_support: String
}

pub struct DescribeInstancesRequest {
    dry_run: bool,
    // instance_ids: Vec<String>,
}

pub struct DescribeInstancesResult {
    reservations: Vec<Reservation>
}

pub struct DescribeInstances {
    input: DescribeInstancesRequest
}

impl DescribeInstances{
    pub fn send(req: DescribeInstancesRequest)-> DescribeInstancesResult {}
}
