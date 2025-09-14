// How long to wait for onionbalance to bootstrap before starting periodic
// events (in seconds)
pub const INITIAL_CALLBACK_DELAY: u64 = 45;

// Every how often we should be fetching instance descriptors (in seconds)
pub const FETCH_DESCRIPTOR_FREQUENCY: u64 = 10 * 60;

// Every how often we should be checking whether we should publish our frontend
// descriptor (in seconds). Triggering this callback doesn't mean we will
// actually upload a descriptor. We only upload a descriptor if it has expired,
// the intro points have changed, etc.
pub const PUBLISH_DESCRIPTOR_CHECK_FREQUENCY: u64 = 5 * 60;

pub const REFRESH_CONSENSUS_FREQUENCY: u64 = 6 * 60 * 60;

// How long should we keep a frontend descriptor before we expire it (in
// seconds)?
pub const FRONTEND_DESCRIPTOR_LIFETIME: i64 = 60 * 60;

// How many intros should we use from each instance in the final frontend
// descriptor?
// [TODO: This makes no attempt to hide the use of onionbalance. In the future we
// should be smarter and sneakier here.]
pub const N_INTROS_PER_INSTANCE: usize = 3;

// If we last received a descriptor for this instance more than
// INSTANCE_DESCRIPTOR_TOO_OLD seconds ago, consider the instance to be down.
pub const INSTANCE_DESCRIPTOR_TOO_OLD: i64 = 60 * 60;

// Number of replicas per descriptor
pub const HSDIR_N_REPLICAS: usize = 2;

// Max descriptor size (in bytes) (see hs_cache_get_max_descriptor_size() in
// little-t-tor)
pub const MAX_DESCRIPTOR_SIZE: usize = 50000;
