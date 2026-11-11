// Copyright 2026 Bad Monkey, Inc.
// Author: Al Baker
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Starting a [`Peer`] from [`PeerSettings`]: the identity from the keystore (or a fresh one), the
//! default dialers, the system clock, the settings' timings, and the spaces to pull.
//!
//! [`Peer::join_from_env`] is the whole path from the configuration to a joined peer:
//! [`Config::from_env`] reads and checks the `ASPACE_*` variables over the fleet YAML they (or the
//! default `~/.config/agentspaces/fleet.yaml`) name, and [`Peer::join_config`] takes it from there:
//! the keystore ([`crate::keystore::load_or_create`]) supplies the identity,
//! [`Config::peer_config`] builds the configuration, [`Peer::start`] dials and joins, and each
//! space the configuration names is pulled.

use std::sync::Arc;

use agentspaces_wire::identity::Identity;

use super::{Peer, PeerConfig, PeerError};
use crate::clock::SystemClock;
use crate::config::{Config, ConfigError, Overrides, PeerSettings};
use crate::keystore;
use crate::transport::Dialer;
use crate::transport::tcp::TcpDialer;
use crate::transport::tls::TlsDialer;

/// The dialers a peer started from settings uses: [`TcpDialer`] for `tcp` seeds and
/// [`TlsDialer::new`] for `tls` seeds (it presents the dialing identity's channel certificate
/// and refuses a seed whose certificate attests nobody).
///
/// Which seeds may be dialed in the clear is decided before any dial, by
/// [`PeerSettings::validate`] (a plaintext seed outside loopback needs [`Profile::DevLocal`]).
///
/// [`Profile::DevLocal`]: crate::group::Profile::DevLocal
pub fn default_dialers() -> Vec<Arc<dyn Dialer>> {
    vec![Arc::new(TcpDialer::new()), Arc::new(TlsDialer::new())]
}

/// The identity `settings` name: the one in [`PeerSettings::keystore`] (loaded, or minted and
/// persisted there when the directory holds no key), or a fresh one that is gone when the
/// process ends.
pub fn settings_identity(settings: &PeerSettings) -> Result<Identity, PeerError> {
    match &settings.keystore {
        Some(dir) => Ok(keystore::load_or_create(dir)?),
        None => Identity::generate().map_err(|error| PeerError::Random(error.to_string())),
    }
}

impl PeerConfig {
    /// A configuration for `identity` from checked `settings`: their group, seeds, and timings
    /// ([`PeerSettings::reconnect_interval`], [`PeerSettings::reconnect_window`],
    /// [`PeerSettings::peer_ad_interval`]), the [`default_dialers`], and the system clock. The
    /// other fields keep the [`PeerConfig::new`] defaults.
    ///
    /// The settings are validated first ([`PeerSettings::validate`]), so a configuration built
    /// here never dials a plaintext seed outside loopback under the `mtls` profile.
    /// [`PeerSettings::keystore`] and [`PeerSettings::spaces`] are not part of a
    /// [`PeerConfig`]: [`Peer::join`] loads the one and pulls the other.
    pub fn from_settings(settings: &PeerSettings, identity: Identity) -> Result<Self, ConfigError> {
        settings.validate()?;
        Ok(Self::from_checked_settings(settings, identity))
    }

    /// [`PeerConfig::from_settings`] of settings the caller checked (a listening peer's, which
    /// may have no seed).
    pub(crate) fn from_checked_settings(settings: &PeerSettings, identity: Identity) -> Self {
        let mut config = Self::new(identity, settings.group.clone());
        config.seeds = settings.seeds.clone();
        config.dialers = default_dialers();
        config.clock = Arc::new(SystemClock);
        config.reconnect_interval = settings.reconnect_interval;
        config.reconnect_window = settings.reconnect_window;
        config.peer_ad_interval = settings.peer_ad_interval;
        config
    }
}

impl Peer {
    /// Starts a peer from `settings`: the identity from [`settings_identity`] (the keystore, or
    /// a fresh one), then [`Peer::join_as`].
    pub async fn join(settings: &PeerSettings) -> Result<Peer, PeerError> {
        let identity = settings_identity(settings)?;
        Self::join_as(settings, identity).await
    }

    /// Starts a peer as `identity` from `settings`: [`PeerConfig::from_settings`], then
    /// [`Peer::start`], then a pull of each of [`PeerSettings::spaces`] (pulled again after every
    /// reconnect). If a pull is refused the peer is closed and the refusal returned.
    pub async fn join_as(settings: &PeerSettings, identity: Identity) -> Result<Peer, PeerError> {
        let config = PeerConfig::from_settings(settings, identity)?;
        Self::start_and_pull(config, &settings.spaces).await
    }

    /// Starts a peer from a resolved [`Config`] (flags, variables, and the fleet YAML): the
    /// identity from [`Config::identity`], then [`Config::peer_config`] (with the configuration's
    /// join timeout), [`Peer::start`], and a pull of each of the configuration's spaces. If a pull
    /// is refused the peer is closed and the refusal returned.
    ///
    /// ```no_run
    /// # async fn run() -> Result<(), Box<dyn std::error::Error>> {
    /// use agentspaces::Config;
    /// use agentspaces::peer::Peer;
    ///
    /// let peer = Peer::join_config(&Config::load("fleet.yaml")?).await?;
    /// println!("{} joined {}", peer.peer_id(), peer.group_id());
    /// # Ok(())
    /// # }
    /// ```
    pub async fn join_config(config: &Config) -> Result<Peer, PeerError> {
        let identity = config.identity()?;
        let peer_config = config.peer_config(identity)?;
        Self::start_and_pull(peer_config, &config.settings.spaces).await
    }

    /// Starts a peer from the configuration of the process ([`crate::config`]): the `ASPACE_*`
    /// variables over the fleet YAML that `ASPACE_CONFIG` names, else the default
    /// `$XDG_CONFIG_HOME/agentspaces/fleet.yaml` (`~/.config/agentspaces/fleet.yaml`) when it
    /// exists, read and checked by [`Config::from_env`]; then [`Peer::join_config`].
    pub async fn join_from_env() -> Result<Peer, PeerError> {
        let config = Config::from_env(&Overrides::default())?;
        Self::join_config(&config).await
    }

    /// [`Peer::start`], then a pull of each of `spaces`; a refused pull closes the peer.
    async fn start_and_pull(config: PeerConfig, spaces: &[String]) -> Result<Peer, PeerError> {
        let peer = Self::start(config).await?;
        for space in spaces {
            if let Err(error) = peer.pull_space(space).await {
                let _ = peer.close().await;
                return Err(error);
            }
        }
        Ok(peer)
    }
}
