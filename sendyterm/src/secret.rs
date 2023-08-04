use async_trait::async_trait;
use sendy_framework::model::crypto::PrivateKeychain;

///! Module for fetching sendy secret keys from the host's secret store

/// Trait implemented per-platform specifying how to securely store secrets on the host
#[async_trait]
pub trait SecretStore {
    async fn store(&self, keys: &PrivateKeychain);

    async fn read(&self) -> Option<PrivateKeychain>;
}

#[cfg(target_os = "linux")]
pub const SECRET_STORE: &dyn SecretStore = &secserv::SecretServiceStore;

#[cfg(target_os = "linux")]
mod secserv {
    use std::collections::HashMap;

    use super::*;
    use futures::TryFutureExt;
    use secret_service::{EncryptionType, SecretService};
    use sendy_framework::{rsa::RsaPrivateKey, FromBytes, ToBytes};

    pub struct SecretServiceStore;

    #[async_trait]
    impl SecretStore for SecretServiceStore {
        async fn store(&self, keys: &PrivateKeychain) {
            let service = match SecretService::connect(EncryptionType::Dh).await {
                Ok(serv) => serv,
                Err(e) => {
                    log::error!("Failed to connect to secret service provider: {}", e);
                    return;
                }
            };

            let collection = match service.get_default_collection().await {
                Ok(c) => c,
                Err(secret_service::Error::NoResult) => match service
                    .create_collection("Default Keyring", "default")
                    .await
                {
                    Ok(c) => c,
                    Err(e) => {
                        log::error!("Failed to create default keyring: {}", e);
                        return;
                    }
                },
                Err(e) => {
                    log::error!("Failed to get collection for keychain: {}", e);
                    return;
                }
            };

            if let Err(_) = collection.ensure_unlocked().await {
                if let Err(e) = collection.unlock().await {
                    log::error!("Failed to unlock keychain collection: {}", e);
                    return;
                }
            }

            let auth_key = keys.auth.as_ref().write_to_vec();
            if let Err(e) = collection
                .create_item(
                    Self::AUTHENTICATION_KEY_LABEL,
                    HashMap::from([(Self::SENDY_ATTR, Self::AUTHENTICATION_KEY_LABEL)]),
                    &auth_key,
                    true,
                    Self::KEYS_CONTENT_TYPE,
                )
                .await
            {
                log::error!("Failed to create authentication key secret: {}", e);
                return;
            }

            let enc_key = keys.enc.write_to_vec();
            if let Err(e) = collection
                .create_item(
                    Self::ENCRYPTION_KEY_LABEL,
                    HashMap::from([(Self::SENDY_ATTR, Self::ENCRYPTION_KEY_LABEL)]),
                    &enc_key,
                    true,
                    Self::KEYS_CONTENT_TYPE,
                )
                .await
            {
                log::error!("Failed to create encryption key secret: {}", e);
                return;
            }
        }

        async fn read(&self) -> Option<PrivateKeychain> {
            let service = match SecretService::connect(EncryptionType::Dh).await {
                Ok(serv) => serv,
                Err(e) => {
                    log::error!("Failed to connect to secret service provider: {}", e);
                    return None;
                }
            };

            let collection = match service.get_default_collection().await {
                Ok(c) => c,
                Err(e) => {
                    log::error!("Failed to get collection for keychain: {}", e);
                    return None;
                }
            };

            if let Err(_) = collection.ensure_unlocked().await {
                if let Err(e) = collection.unlock().await {
                    log::error!("Failed to unlock keychain collection: {}", e);
                    return None;
                }
            }

            match collection
                .search_items(HashMap::from([(
                    Self::SENDY_ATTR,
                    Self::ENCRYPTION_KEY_LABEL,
                )]))
                .await
            {
                Ok(enc) => match collection
                    .search_items(HashMap::from([(
                        Self::SENDY_ATTR,
                        Self::AUTHENTICATION_KEY_LABEL,
                    )]))
                    .await
                {
                    Ok(auth) => {
                        let (auth, enc) = (auth.first()?, enc.first()?);

                        match auth
                            .get_secret()
                            .and_then(|auth| enc.get_secret().map_ok(|enc| (auth, enc)))
                            .await
                        {
                            Ok((auth, enc)) => {
                                match RsaPrivateKey::read_from_slice(&auth).and_then(|auth| {
                                    RsaPrivateKey::read_from_slice(&enc).map(|enc| (auth, enc))
                                }) {
                                    Ok((auth, enc)) => Some(PrivateKeychain::new(auth, enc)),
                                    Err(e) => {
                                        log::error!(
                                            "Failed to decode RSA keys from secrets: {}",
                                            e
                                        );
                                        None
                                    }
                                }
                            }
                            Err(e) => {
                                log::error!("Failed to get secret for keychain: {}", e);
                                None
                            }
                        }
                    }
                    Err(e) => {
                        log::error!("Failed to get authentication key from collection: {}", e);
                        return None;
                    }
                },
                Err(e) => {
                    log::error!("Failed to get encryption key from collection: {}", e);
                    return None;
                }
            }
        }
    }

    impl SecretServiceStore {
        const SENDY_ATTR: &str = "sendy-kind";

        const ENCRYPTION_KEY_LABEL: &str = "Encryption Key";
        const AUTHENTICATION_KEY_LABEL: &str = "Authentication Key";

        const KEYS_CONTENT_TYPE: &str = "application/pkcs8";
    }
}
