use hmac::{Hmac, Mac};
use md5::{Digest, Md5};
use sha1::Sha1;

pub enum AuthProtocol {
    None,
    Md5,
    Sha1,
}

trait HashToVec {
    fn hash(data: &[u8], hmac_key: Option<&[u8]>) -> Result<Vec<u8>, crate::Error> {
        match hmac_key {
            None => {
                let mut hasher = md5::Md5::new();
                hasher.update(data);
                Ok(hasher.finalize().to_vec())
            }
            Some(k) => {
                let mut hasher = Hmac::<Md5>::new_from_slice(k)
                    .map_err(|_| crate::Error::HashKeyInvalidLength)?;
                hasher.update(data);
                Ok(hasher.finalize().into_bytes().to_vec())
            }
        }
    }
}

impl HashToVec for Md5 {}
impl HashToVec for Sha1 {}

trait GetKey: HashToVec {
    const DIGEST_SIZE: usize;
    fn get_key(password: &[u8], engine_id: &[u8]) -> Result<Vec<u8>, crate::Error> {
        // see RFC 3414 A.2.2. Password to Key Sample Code for SHA
        let mut cp = [0_u8; 72];
        let mut password_index = 0_usize;
        let mut count = 0_u64;
        let mut hasher = Sha1::new();
        while count < 1024 * 1024 {
            for i in 0..64 {
                password_index += 1;
                cp[i] = password[password_index % password.len()];
            }
            hasher.update(cp);
            count += 64;
        }
        let slice = &hasher.finalize();
        cp[..Self::DIGEST_SIZE].copy_from_slice(&slice[..Self::DIGEST_SIZE]);
        cp[Self::DIGEST_SIZE..Self::DIGEST_SIZE + engine_id.len()].copy_from_slice(engine_id);
        cp[Self::DIGEST_SIZE + engine_id.len()..(Self::DIGEST_SIZE * 2) + engine_id.len()]
            .copy_from_slice(&slice[..Self::DIGEST_SIZE]);
        Ok(Self::hash(&cp, None)?)
    }
}

impl GetKey for Md5 {
    const DIGEST_SIZE: usize = 16;
}

impl GetKey for Sha1 {
    const DIGEST_SIZE: usize = 20;
}

impl AuthProtocol {
    fn hash(&self, data: &[u8], hmac_key: Option<&[u8]>) -> Result<Vec<u8>, crate::Error> {
        // TODO the below code paths can probably be coalesced and have less duplicate code
        match self {
            AuthProtocol::None => Ok(vec![]),
            AuthProtocol::Md5 => Md5::hash(data, hmac_key),
            AuthProtocol::Sha1 => Sha1::hash(data, hmac_key),
        }
    }
    fn get_key(&self, password: &[u8], engine_id: &[u8]) -> Result<Vec<u8>, crate::Error> {
        // TODO ensure engine length is <= 32 otherwise the engine hash mixin crap will throw its shit out the pram
        if password.len() < 8 {
            Err(crate::Error::SecretKeyIsTooShort(password.len()))
        } else {
            match self {
                AuthProtocol::None => Ok(vec![]),
                AuthProtocol::Md5 => Md5::get_key(password, engine_id),
                AuthProtocol::Sha1 => Sha1::get_key(password, engine_id),
            }
        }
    }
    pub fn authenticate(
        &self,
        password: &[u8],
        engine_id: &[u8],
        msg: &[u8],
    ) -> Result<Vec<u8>, crate::Error> {
        self.authenticate_with_key(&self.get_key(password, engine_id)?[..], msg)
    }
    pub fn authenticate_with_key(&self, key: &[u8], msg: &[u8]) -> Result<Vec<u8>, crate::Error> {
        let mut ret = self.hash(msg, Some(key))?;
        ret.drain(12..);
        Ok(ret)
    }
}
