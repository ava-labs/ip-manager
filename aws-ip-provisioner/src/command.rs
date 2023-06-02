use std::{
    collections::HashMap,
    env,
    io::{self, Error, ErrorKind},
    path::Path,
};

use aws_manager::{self, ec2};
use clap::{crate_version, value_parser, Arg, Command};
use tokio::time::{sleep, Duration};

pub const NAME: &str = "aws-ip-provisioner";

pub fn new() -> Command {
    Command::new(NAME)
        .version(crate_version!())
        .about("Provisions the Elastic IP to the local EC2 instance")
        .long_about(
            "


The EC2 instance is automatically fetched.

Commands may run multiple times with idempotency.

Requires IAM instance role of: ec2:AllocateAddress, ec2:AssociateAddress, and ec2:DescribeAddresses.

e.g.,

$ aws-ip-provisioner \
--log-level=info \
--initial-wait-random-seconds=70 \
--id-tag-key=Id \
--id-tag-value=TEST-ID \
--kind-tag-key=Kind \
--kind-tag-value=aws-ip-provisioner \
--ec2-tag-asg-name-key=ASG_NAME \
--asg-tag-key=autoscaling:groupName \
--mounted-eip-file-path=/data/eip.yaml

",
        )
        .arg(
            Arg::new("LOG_LEVEL")
                .long("log-level")
                .short('l')
                .help("Sets the log level")
                .required(false)
                .num_args(1)
                .value_parser(["debug", "info"])
                .default_value("info"),
        )
        .arg(
            Arg::new("REGION")
                .long("region")
                .help("Sets the AWS region")
                .required(true)
                .num_args(1)
                .default_value("us-west-2"),
        )
        .arg(
            Arg::new("INITIAL_WAIT_RANDOM_SECONDS")
                .long("initial-wait-random-seconds")
                .help("Sets the maximum number of seconds to wait (value chosen at random with the range, highly recommend setting value >60 because EC2 tags take awhile to pupulate)")
                .required(false)
                .num_args(1)
                .value_parser(value_parser!(u32))
                .default_value("20"),
        )
        .arg(
            Arg::new("ID_TAG_KEY")
                .long("id-tag-key")
                .help("Sets the key for the elastic IP 'Id' tag (must be set via EC2 tags, or used for EIP creation)")
                .required(true)
                .num_args(1)
                .default_value("Id"),
        )
        .arg(
            Arg::new("ID_TAG_VALUE")
                .long("id-tag-value")
                .help("Sets the value for the elastic IP 'Id' tag key (must be set via EC2 tags)")
                .required(true)
                .num_args(1),
        )
        .arg(
            Arg::new("KIND_TAG_KEY")
                .long("kind-tag-key")
                .help("Sets the key for the elastic IP 'Kind' tag (must be set via EC2 tags, or used for EIP creation)")
                .required(true)
                .num_args(1)
                .default_value("Kind"),
        )
        .arg(
            Arg::new("KIND_TAG_VALUE")
                .long("kind-tag-value")
                .help("Sets the value for the elastic IP 'Kind' tag key (must be set via EC2 tags)")
                .required(true)
                .num_args(1),
        )
        .arg(
            Arg::new("EC2_TAG_ASG_NAME_KEY")
                .long("ec2-tag-asg-name-key")
                .help("Sets the key of the ASG name tag")
                .required(true)
                .num_args(1),
        )
        .arg(
            Arg::new("ASG_TAG_KEY")
                .long("asg-tag-key")
                .help("Sets the key for the elastic IP asg name tag (must be set via EC2 tags, or used for elastic IP creation)")
                .required(true)
                .num_args(1)
                .default_value("autoscaling:groupName"),
        )
        .arg(
            Arg::new("FIND_REUSABLE_RETRIES")
                .long("find-reusable-retries")
                .help("Sets the number of describe call retries until it finds one before creating one")
                .required(false)
                .value_parser(value_parser!(usize))
                .num_args(1)
                .default_value("5"),
        )
        .arg(
            Arg::new("MOUNTED_EIP_FILE_PATH")
                .long("mounted-eip-file-path")
                .help("Sets the file path to store Elastic IP information mapped to this volume path")
                .required(true)
                .num_args(1)
                .default_value("/data/eip.yaml"),
        )
}

/// Defines flag options.
pub struct Flags {
    pub log_level: String,
    pub region: String,
    pub initial_wait_random_seconds: u32,

    pub id_tag_key: String,
    pub id_tag_value: String,
    pub kind_tag_key: String,
    pub kind_tag_value: String,
    pub ec2_tag_asg_name_key: String,
    pub asg_tag_key: String,

    pub find_reusable_retries: usize,

    pub mounted_eip_file_path: String,
}

pub async fn execute(opts: Flags) -> io::Result<()> {
    println!("{} version: {}", NAME, crate_version!());

    // ref. <https://github.com/env-logger-rs/env_logger/issues/47>
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, opts.log_level),
    );
    log::info!(
        "starting 'aws-ip-provisioner' on the region '{}' with initial wait random seconds '{}'",
        opts.region,
        opts.initial_wait_random_seconds
    );

    let sleep_sec = if opts.initial_wait_random_seconds > 0 {
        opts.initial_wait_random_seconds + (random_manager::u32() % 20)
    } else {
        10
    };
    log::info!("waiting for random seconds {sleep_sec}");
    sleep(Duration::from_secs(sleep_sec as u64)).await;

    let shared_config =
        aws_manager::load_config(Some(opts.region.clone()), Some(Duration::from_secs(30))).await;
    let ec2_manager = ec2::Manager::new(&shared_config);

    let ec2_instance_id = ec2::metadata::fetch_instance_id().await.map_err(|e| {
        Error::new(
            ErrorKind::Other,
            format!("failed fetch_instance_id '{}'", e),
        )
    })?;

    log::info!("fetching the tag value for {}", opts.ec2_tag_asg_name_key);
    let mut asg_tag_value = String::new();
    for i in 0..50 {
        log::info!(
            "[{i}] fetching tags until ec2_tag_asg_name_key '{}' is found",
            opts.ec2_tag_asg_name_key
        );
        let tags = ec2_manager
            .fetch_tags(&ec2_instance_id)
            .await
            .map_err(|e| Error::new(ErrorKind::Other, format!("failed fetch_tags {}", e)))?;
        for c in tags {
            let k = c.key().unwrap();
            let v = c.value().unwrap();

            log::info!("EC2 tag key='{}', value='{}'", k, v);
            if k == opts.ec2_tag_asg_name_key {
                asg_tag_value = v.to_string();
                break;
            }
        }
        if !asg_tag_value.is_empty() {
            break;
        }
        sleep(Duration::from_secs(10)).await;
    }
    if asg_tag_value.is_empty() {
        return Err(Error::new(
            ErrorKind::Other,
            format!("{} is empty", opts.ec2_tag_asg_name_key),
        ));
    }

    log::info!(
        "checking if the local instance {} has an already created elastic Ip (for reuse) via {}",
        ec2_instance_id,
        opts.mounted_eip_file_path
    );
    let eip = if Path::new(&opts.mounted_eip_file_path).exists() {
        log::info!(
            "mounted EIP file path exists -- loading existing {}",
            opts.mounted_eip_file_path
        );
        ec2::Eip::load(&opts.mounted_eip_file_path)
            .map_err(|e| Error::new(ErrorKind::Other, format!("failed ec2::Eip::load '{}'", e)))?
    } else {
        log::info!("mounted EIP file does not exist in the mounted volume path -- creating one!");
        ec2_manager
            .allocate_eip(HashMap::from([
                (opts.id_tag_key.to_string(), opts.id_tag_value.to_string()),
                (String::from("Name"), asg_tag_value.clone()),
                (opts.asg_tag_key.to_string(), asg_tag_value.clone()),
                (
                    opts.kind_tag_key.to_string(),
                    opts.kind_tag_value.to_string(),
                ),
            ]))
            .await
            .map_err(|e| {
                Error::new(
                    ErrorKind::Other,
                    format!(
                        "failed ec2_manager.allocate_eip {} (retryable {})",
                        e.message(),
                        e.retryable()
                    ),
                )
            })?
    };
    eip.sync(&opts.mounted_eip_file_path)?;

    log::info!(
        "checking the instance has already been associated with elastic IP {:?}",
        eip
    );
    let mut local_eips = Vec::new();
    for i in 0..opts.find_reusable_retries {
        log::info!("[{i}] trying describe_eips_by_instance_id");
        local_eips = ec2_manager
            .describe_eips_by_instance_id(&ec2_instance_id)
            .await
            .map_err(|e| {
                Error::new(
                    ErrorKind::Other,
                    format!(
                        "failed ec2_manager.describe_eips_by_instance_id {} (retryable {})",
                        e.message(),
                        e.retryable()
                    ),
                )
            })?;
        if !local_eips.is_empty() {
            break;
        }

        log::info!("no local EIP found... retrying in case of inconsistent/stale API response");
        sleep(Duration::from_secs(3)).await;
    }
    let need_associate_eip = if local_eips.is_empty() {
        log::info!(
            "no existing EIP found, now associating {:?} to {ec2_instance_id}",
            eip
        );
        true
    } else {
        log::info!("existing EIPs found {:?}", local_eips);
        let mut found = false;
        for ev in local_eips.iter() {
            log::info!("address {:?}", ev);
            let allocation_id = ev.allocation_id.to_owned().unwrap();
            if allocation_id == eip.allocation_id {
                log::info!("{ec2_instance_id} already has EIP allocation ID {allocation_id} -- no need to associate once more");
                found = true;
                break;
            }
        }
        !found // if already associated EIP not found, need associate existing one
    };
    if need_associate_eip {
        let _association_id = ec2_manager
            .associate_eip(&eip.allocation_id, &ec2_instance_id)
            .await
            .map_err(|e| {
                Error::new(
                    ErrorKind::Other,
                    format!(
                        "failed ec2_manager.associate_eip {} (retryable {})",
                        e.message(),
                        e.retryable()
                    ),
                )
            })?;
    }

    log::info!("successfully provisioned and associated EIP!");
    Ok(())
}
