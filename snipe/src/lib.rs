pub mod client;
pub mod prelude;
pub mod rfc1212;
pub mod rfc3412;
pub mod rfc3414;

use std::{
    io::{Read, Write},
    num::{ParseIntError, TryFromIntError},
    str::Utf8Error,
    string::FromUtf8Error
};

use num_bigint::TryFromBigIntError;
pub use rasn as asn;
pub use rasn::prelude::*;
use rasn_smi::v1::{InvalidVariant, IpAddress};
pub use rasn_snmp as snmp;
use snmp::v2::{ObjectSyntax, VarBindList};

extern crate self as snipe;

pub use snipe_macros::{declare_mib, declare_oid};

// ------------------------------------- FIXED -------------------------------------

#[async_trait::async_trait]
pub trait SnmpInterface: Send + Sync {
    async fn read(&mut self, oid: ObjectIdentifier) -> Result<ObjectSyntax, Error>;
    async fn write(&mut self, oid: ObjectIdentifier, value: ObjectSyntax) -> Result<(), Error>;
    async fn bulk(&mut self, oid: ObjectIdentifier) -> Result<VarBindList, Error>;
}

pub trait GetSnmpInterface: Send + Sync {
    type Interface: SnmpInterface;
    fn snmp_interface(&mut self) -> &mut Self::Interface;
}

pub fn append_index<T, C: prelude::OidConverter<T>>(
    base_oid: ObjectIdentifier,
    value: T,
) -> Result<ObjectIdentifier, Error> {
    let mut vec = base_oid.iter().copied().collect::<Vec<_>>();
    vec.extend(C::try_to_oid(value)?.iter().copied());
    ObjectIdentifier::new(vec)
        .ok_or_else(|| Error::BaseOid(base_oid.iter().map(|x| format!("{x}.")).collect()))
}

impl<T: SnmpInterface + Send + Sync> GetSnmpInterface for T {
    type Interface = T;

    fn snmp_interface(&mut self) -> &mut Self::Interface {
        self
    }
}

// ----------------------------------- GENERATED ------------------------------------
// Per MIB

declare_mib!("EXAMPLE-MIB.mib");
declare_oid!("ipAddress", IpAddress);

// Per OID per MIB
impl<'a, I: SnmpInterface + Send + Sync> ReadIpAddress for ExampleMib<'a, I> {
    type Converter = prelude::DefaultConverter;
    const OID: ConstOid = ConstOid(&[1_u32, 3_u32, 6_u32, 1_u32, 4_u32, 1_u32]);
}

//     where ip_address is implemented by trait GetIpAddressOid generated from an OID called ipAddress
//     this trait is implemented on MyMibName
//     this method returns IpAddress

async fn x<T: SnmpInterface>(mut x: T) {
    let _ = x.example_mib().ip_address().await.unwrap();
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("failed to create a UTF8 string from the given octet string: {}", .0)]
    Utf8(#[from] Utf8Error),
    #[error("failed to create a UTF8 string from the byte array: {}", .0)]
    FromUtf8(#[from] FromUtf8Error),
    #[error("failed to convert from an int: {}", .0)]
    IntegerConvert(#[from] TryFromIntError),
    #[error("failed to convert from ASN int: {}", .0)]
    BigIntegerConvert(#[from] TryFromBigIntError<Integer>),
    #[error("this error is impossible")]
    Infalliable(#[from] std::convert::Infallible),
    #[error("message was valid SMI but was not the variant we expected")]
    InvalidVariant,
    #[error("octet string length does not match the fixed expected length: expected {}, got {}", .0, .1)]
    StringLength(usize, usize),
    #[error("{} is not a valid base OID", .0)]
    BaseOid(String),
    #[error("OID is not big enough to contain index (expected at least {} subidentifiers)", .0)]
    InsufficientLength(usize),
    #[error("the given network address type is invalid/not supported: {}", .0)]
    UnsupportedNetworkAddress(u32),
    #[error(
        "noAuthPriv (..10 - privacy flag set but not auth flag) is reserved and must not be used"
    )]
    PrivNoAuth,
    #[error("secret key is too short (expected 8, got {})", .0)]
    SecretKeyIsTooShort(usize),
    #[error("hash key is of an invalid length")]
    HashKeyInvalidLength,
    #[error("the incoming message did not match the expected hash")]
    IncomingAuthFail,
    #[error("failed to encode ASN: {}", .0)]
    AsnEncodeError(rasn::ber::enc::Error),
    #[error("failed to decode ASN: {}", .0)]
    AsnDecodeError(rasn::ber::de::Error),
}

impl From<InvalidVariant> for Error {
    fn from(_: InvalidVariant) -> Self {
        Error::InvalidVariant
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
