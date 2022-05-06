pub mod prelude;

use std::{
    num::{ParseIntError, TryFromIntError},
    str::Utf8Error,
};

pub use rasn as asn;
pub use rasn::prelude::*;
use rasn_smi::v1::{InvalidVariant, IpAddress};
pub use rasn_snmp as snmp;
use snmp::v2::{ObjectSyntax, VarBindList};

extern crate self as snipe;

pub use snipe_macros::*;

// ------------------------------------- FIXED -------------------------------------

pub trait SnmpInterface {
    fn read(&mut self, oid: ObjectIdentifier) -> Result<ObjectSyntax, Error>;
    fn write(&mut self, oid: ObjectIdentifier, value: ObjectSyntax) -> Result<(), Error>;
    fn bulk(&mut self, oid: ObjectIdentifier) -> Result<VarBindList, Error>;
}

pub trait GetSnmpInterface {
    type Interface: SnmpInterface;
    fn snmp_interface(&mut self) -> &mut Self::Interface;
}

pub fn append_index<T, C: prelude::OidConverter<T>>(
    base_oid: ObjectIdentifier,
    value: T,
) -> Result<ObjectIdentifier, Error> {
}

/// A noddy trait containing the type of declared OIDs, to avoid needing to specify the type again when implementing the
/// OID for a particular MIB.
pub trait OidType {
    type Type;
}

impl<T: SnmpInterface> GetSnmpInterface for T {
    type Interface = T;

    fn snmp_interface(&mut self) -> &mut Self::Interface {
        self
    }
}

// ----------------------------------- GENERATED ------------------------------------
// Per MIB

declare_oid!("ipAddress", IpAddress);
declare_mib!("EXAMPLE-MIB.mib");

// Per OID (overall)

// Per OID per MIB
impl<'a, I: SnmpInterface> ReadIpAddress for ExampleMib<'a, I> {
    type Converter = prelude::DefaultConverter;
    const OID: ConstOid = ConstOid(&[1_u32, 3_u32, 6_u32, 1_u32, 4_u32, 1_u32]);
}

//     where ip_address is implemented by trait GetIpAddressOid generated from an OID called ipAddress
//     this trait is implemented on MyMibName
//     this method returns IpAddress

fn x<T: SnmpInterface>(mut x: T) {
    x.example_mib().ip_address().unwrap();
}

trait AsOid {
    fn as_oid(&self) -> ObjectIdentifier;
}

#[derive(thiserror::Error, Debug)]
pub enum MessageError {}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("conversion to the given type is unsupported")]
    UnsupportedConversion,
    #[error("value of integer is outside the range of the target numeric type")]
    IntegerValueOutOfRange,
    #[error("failed to create a UTF8 string from the given octet string: {}", .0)]
    Utf8(#[from] Utf8Error),
    #[error("failed to parse the given integer: {}", .0)]
    IntegerParse(#[from] ParseIntError),
    #[error("failed to convert from an int: {}", .0)]
    IntegerConvert(#[from] TryFromIntError),
    #[error("this error is impossible")]
    Infalliable(#[from] std::convert::Infallible),
    #[error("message was valid SMI but was not the variant we expected")]
    InvalidVariant,
    #[error("failed to encode SNMP message/object: {}", .0)]
    EncodeError(String),
    #[error("octet string length does not match the fixed expected length: expected {}, got {}", .0, .1)]
    StringLengthError(usize, usize),
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
