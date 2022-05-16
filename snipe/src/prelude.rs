//! Contains implementations of common traits which augment usage of snipe when all contents are imported.

use num_bigint::BigInt;
use rasn::types::{ObjectIdentifier, OctetString};
use rasn_smi::{
    v1::{Counter, Gauge, IpAddress, NetworkAddress, Opaque, TimeTicks},
    v2::{ObjectSyntax, SimpleSyntax},
};

pub use crate::rfc1212::*;

pub struct FixedLengthOctetString<const N: usize>(pub [u8; N]);

/// Encapsulates an OID conversion result. That is, a type containing the given T and the number of identifiers
/// consumed when reading that T from an OID.
pub struct OidConversionResult<T> {
    /// The number of bytes or identifiers read
    pub num_consumed: usize,

    /// The T read from the OID.
    pub converted: T,
}

/// Defines methods for converting the given T to/from a SNMP [`ObjectSyntax`].
pub trait SnmpConverter<T: Sized> {
    fn try_from_snmp(syntax: ObjectSyntax) -> Result<T, crate::Error>;
    fn try_to_snmp(value: T) -> Result<ObjectSyntax, crate::Error>;
}

pub trait OidConverter<T: Sized> {
    fn try_from_oid(identifier: &[u32]) -> Result<OidConversionResult<T>, crate::Error>;
    fn try_to_oid(value: T) -> Result<ObjectIdentifier, crate::Error>;
}

/// Defines a new type
#[macro_export]
macro_rules! try_into_snmp_converter {
    ($(#[$outer:meta])* $visibility:vis struct $name:ident($($type:ty),+)) => {
        $(
            #[$outer]
        )*
        ///
        /// This type implements SNMP conversions for the following types:
        $(
            #[doc = ::std::concat!(" - [`", ::std::stringify!($type), "`]")]
        )+
        $visibility struct $name;
        $(
            impl SnmpConverter<$type> for $name {
                fn try_from_snmp(syntax: ObjectSyntax) -> Result<$type, $crate::Error> {
                    Ok(syntax.try_into()?)
                }

                fn try_to_snmp(value: $type) -> Result<ObjectSyntax, $crate::Error> {
                    Ok(value.try_into()?)
                }
            }
        )+
    }
}

impl<const N: usize> TryFrom<ObjectSyntax> for FixedLengthOctetString<N> {
    type Error = crate::Error;

    fn try_from(value: ObjectSyntax) -> Result<Self, Self::Error> {
        let str: OctetString = value.try_into()?;
        if str.len() == N {
            Err(crate::Error::StringLength(N, str.len()))
        } else {
            let mut ret = [0_u8; N];
            for (i, byte) in str.into_iter().enumerate() {
                ret[i] = byte;
            }

            Ok(FixedLengthOctetString(ret))
        }
    }
}

impl<const N: usize> From<FixedLengthOctetString<N>> for ObjectSyntax {
    fn from(val: FixedLengthOctetString<N>) -> Self {
        ObjectSyntax::Simple(SimpleSyntax::String(OctetString::from_iter(val.0)))
    }
}

impl<const N: usize> SnmpConverter<FixedLengthOctetString<N>> for DefaultConverter {
    fn try_from_snmp(syntax: ObjectSyntax) -> Result<FixedLengthOctetString<N>, crate::Error> {
        syntax.try_into()
    }

    fn try_to_snmp(value: FixedLengthOctetString<N>) -> Result<ObjectSyntax, crate::Error> {
        Ok(value.try_into()?)
    }
}

impl<const N: usize> From<FixedLengthOctetString<N>> for OctetString {
    fn from(val: FixedLengthOctetString<N>) -> Self {
        val.0.to_vec().into()
    }
}

impl<const N: usize> TryFrom<FixedLengthOctetString<N>> for String {
    type Error = std::string::FromUtf8Error;
    fn try_from(value: FixedLengthOctetString<N>) -> Result<Self, Self::Error> {
        String::from_utf8(value.0.into_iter().collect())
    }
}

impl<const N: usize> FixedLengthOctetString<N> {
    pub fn try_as_str(&self) -> Result<&str, crate::Error> {
        Ok(std::str::from_utf8(&self.0[..])?)
    }
}

try_into_snmp_converter! {
    /// Implements basic built-in SNMP conversions to/from common types.
    pub struct DefaultConverter(
        OctetString,
        BigInt,
        u8,
        u16,
        u32,
        u64,
        u128,
        i8,
        i16,
        i32,
        i64,
        i128,
        ObjectIdentifier,
        NetworkAddress,
        Counter,
        Gauge,
        TimeTicks,
        Opaque,
        IpAddress
    )
}

// 11 is the max length for index tuples. currently matches Rust's max length to get common implementations for traits
// like Eq, Debug, etc..
snipe_macros::__private_api_tuple_oid_converter_impl! { 11 }
