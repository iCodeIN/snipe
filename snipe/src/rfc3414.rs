use std::mem::size_of;

use aes::{
    cipher::{
        block_padding::ZeroPadding, AsyncStreamCipher, BlockDecryptMut, BlockEncryptMut, KeyIvInit,
    },
    Aes128,
};
use des::Des;
use hmac::{Hmac, Mac};
use md5::{Digest, Md5};
use rasn::Encode;
use rasn_snmp::v3::{ScopedPdu, ScopedPduData, USMSecurityParameters};
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
            for x in &mut cp[..64] {
                password_index += 1;
                *x = password[password_index % password.len()];
            }
            hasher.update(cp);
            count += 64;
        }
        let slice = &hasher.finalize();
        cp[..Self::DIGEST_SIZE].copy_from_slice(&slice[..Self::DIGEST_SIZE]);
        cp[Self::DIGEST_SIZE..Self::DIGEST_SIZE + engine_id.len()].copy_from_slice(engine_id);
        cp[Self::DIGEST_SIZE + engine_id.len()..(Self::DIGEST_SIZE * 2) + engine_id.len()]
            .copy_from_slice(&slice[..Self::DIGEST_SIZE]);
        Self::hash(&cp, None)
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
    pub fn validate(
        &self,
        password: &[u8],
        engine_id: &[u8],
        auth_params: &[u8],
        msg: &[u8],
    ) -> Result<(), crate::Error> {
        self.validate_with_key(&self.get_key(password, engine_id)?[..], auth_params, msg)
    }
    pub fn validate_with_key(
        &self,
        key: &[u8],
        auth_params: &[u8],
        msg: &[u8],
    ) -> Result<(), crate::Error> {
        if &self.hash(msg, Some(key))?[..12] != auth_params {
            Err(crate::Error::IncomingAuthFail)
        } else {
            Ok(())
        }
    }
}

pub enum PrivProtocol {
    None,
    Aes,
    Des,
}

fn get_aes_iv(security_params: &USMSecurityParameters) -> Result<[u8; 16], crate::Error> {
    let mut iv = [0_u8; 16];

    let boots: u32 = security_params
        .authoritative_engine_boots
        .clone()
        .try_into()?;
    let time: u32 = security_params
        .authoritative_engine_time
        .clone()
        .try_into()?;
    iv[..size_of::<u32>()].copy_from_slice(&boots.to_be_bytes());
    iv[size_of::<u32>()..size_of::<u64>()].copy_from_slice(&time.to_be_bytes());
    iv[size_of::<u64>()..].copy_from_slice(&security_params.privacy_parameters[..]);
    Ok(iv)
}

trait PrivKey<D: GetKey> {
    type Salt;
    fn encrypt(
        pdu: ScopedPdu,
        security_params: &mut USMSecurityParameters,
        password: &[u8],
        salt: Self::Salt,
    ) -> Result<ScopedPduData, crate::Error>;
    fn decrypt(
        pdu: ScopedPduData,
        security_params: &USMSecurityParameters,
        password: &[u8],
    ) -> Result<ScopedPdu, crate::Error>;
}

impl<D: GetKey> PrivKey<D> for Aes128 {
    type Salt = u64;
    fn encrypt(
        pdu: ScopedPdu,
        security_params: &mut USMSecurityParameters,
        password: &[u8],
        salt: Self::Salt,
    ) -> Result<ScopedPduData, crate::Error> {
        let mut key = [0_u8; 16];
        key.copy_from_slice(
            &D::get_key(password, &security_params.authoritative_engine_id[..])?[..16],
        );
        security_params.privacy_parameters = salt.to_be_bytes().to_vec().into();
        let encryptor =
            cfb_mode::Encryptor::<Aes128>::new(&key.into(), &get_aes_iv(security_params)?.into());
        let mut data = rasn::ber::encode(&pdu).map_err(crate::Error::AsnEncode)?;
        encryptor.encrypt(&mut data[..]);
        Ok(ScopedPduData::EncryptedPdu(data.into()))
    }

    fn decrypt(
        pdu: ScopedPduData,
        security_params: &USMSecurityParameters,
        password: &[u8],
    ) -> Result<ScopedPdu, crate::Error> {
        match pdu {
            ScopedPduData::EncryptedPdu(data) => {
                let mut key = [0_u8; 16];
                key.copy_from_slice(
                    &D::get_key(password, &security_params.authoritative_engine_id[..])?[..16],
                );
                let decryptor = cfb_mode::Decryptor::<Aes128>::new(
                    &key.into(),
                    &get_aes_iv(security_params)?.into(),
                );
                let mut data_cp = data.to_vec();
                decryptor.decrypt(&mut data_cp[..]);
                Ok(rasn::ber::decode(&data_cp[..]).map_err(crate::Error::AsnDecode)?)
            }
            ScopedPduData::CleartextPdu(pdu) => Ok(pdu),
        }
    }
}

fn get_des_iv(key: &[u8], salt: &[u8]) -> Result<([u8; 8], [u8; 8]), crate::Error> {
    let (des_key, pre_iv) = key[..16].split_at(8);
    let mut key = [0_u8; 8];
    key.copy_from_slice(des_key);
    let mut iv = [0_u8; 8];
    iv.copy_from_slice(salt);
    iv.iter_mut()
        .zip(pre_iv.iter())
        .for_each(|(salt_byte, pre_iv)| *salt_byte ^= pre_iv);
    Ok((key, iv))
}

impl<D: GetKey> PrivKey<D> for Des {
    type Salt = u32;

    fn encrypt(
        pdu: ScopedPdu,
        security_params: &mut USMSecurityParameters,
        password: &[u8],
        salt: Self::Salt,
    ) -> Result<ScopedPduData, crate::Error> {
        let mut input_salt = [0_u8; size_of::<u64>()];
        input_salt[..size_of::<u32>()].copy_from_slice(
            &u32::try_from(security_params.authoritative_engine_boots.clone())?.to_be_bytes()[..],
        );
        input_salt[size_of::<u32>()..].copy_from_slice(&salt.to_be_bytes()[..]);
        security_params.privacy_parameters = input_salt.to_vec().into();
        let (key, iv) = get_des_iv(
            &D::get_key(password, &security_params.authoritative_engine_id[..])?[..16],
            &input_salt[..],
        )?;
        let encryptor = cfb_mode::Encryptor::<Des>::new(&key.into(), &iv.into());
        let mut data = rasn::ber::encode(&pdu).map_err(crate::Error::AsnEncode)?;
        encryptor.encrypt(&mut data[..]);
        Ok(ScopedPduData::EncryptedPdu(data.into()))
    }

    fn decrypt(
        pdu: ScopedPduData,
        security_params: &USMSecurityParameters,
        password: &[u8],
    ) -> Result<ScopedPdu, crate::Error> {
        match pdu {
            ScopedPduData::EncryptedPdu(data) => {
                let (key, iv) = get_des_iv(
                    &D::get_key(password, &security_params.authoritative_engine_id[..])?[..16],
                    &security_params.privacy_parameters[..],
                )?;
                let decryptor = cfb_mode::Decryptor::<Des>::new(&key.into(), &iv.into());
                let mut data_cp = data.to_vec();
                decryptor.decrypt(&mut data_cp[..]);
                Ok(rasn::ber::decode(&data_cp[..]).map_err(crate::Error::AsnDecode)?)
            }
            ScopedPduData::CleartextPdu(pdu) => Ok(pdu),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use hex_literal::hex;

    // Values used within these tests were captured from a real wireshark trace.

    #[test]
    fn des_decrypt() {
        let pdu = <Des as PrivKey<Md5>>::decrypt(
            ScopedPduData::EncryptedPdu(
                hex!("1a220c98ff3459d9f6648224c59553506d0c91bd9b5d13a40481840ec529c901040078bfecbd58417eb90815aff07292ce22cd3536d29c8fc081ea8b3d988859")[..].into()
            ),
            &USMSecurityParameters {
                authoritative_engine_id: hex!("80004fb8056e69676874726176656e02828500")[..].into(),
                authoritative_engine_boots: 2_u32.into(), authoritative_engine_time: 224_u32.into(),
                user_name: "simulator".into(),
                authentication_parameters: hex!("c23bda11ede262c244b5677b")[..].into(),
                privacy_parameters: hex!("00000001166bd28b")[..].into()
            },
            "privatus".as_bytes()
        ).expect("failed to decrypt!");
    }
}
