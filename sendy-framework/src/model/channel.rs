//! Channels are categories that post resources are associated with

use chrono::{DateTime, Utc};
use sendy_wireformat::{FromBytes, ToBytes};

use crate::ctx::res::{ResourceId, cert::PeerCertificateId};

/// A channel seed that is be randomly generated, contains data required to derive the symmetric
/// channel membership key
#[derive(Debug, FromBytes, ToBytes)]
pub struct ChannelMembershipSeed {
    /// The channel seed that is hashed to produce the channel ID
    pub seed: [u8 ; 32],
    /// Additional salt combined with the `seed` to generate the channel's symmetric key
    pub salt: [u8 ; 32],
}

/// A channel structure as is is recorded by peers, informing nodes of the existence of a channel
/// owned by the given peer with the given ID
#[derive(Debug, FromBytes, ToBytes)]
pub struct Channel {
    /// Fingerprint of the channel owner, used to verify modifications and invites to the channel
    pub owner: PeerCertificateId,
    /// Hash of the channel's seed
    pub id: ResourceId<Channel>,
    /// User-facing name of the channel
    pub name: String,
    pub last_update: DateTime<Utc>,
}
