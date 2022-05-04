//! Contains implementations of common traits which augment usage of snipe when all contents are imported.

use num_bigint::BigInt;
use rasn::types::{ObjectIdentifier, OctetString};
use rasn_smi::{
    v1::{Counter, Gauge, IpAddress, NetworkAddress, Opaque, TimeTicks},
    v2::ObjectSyntax,
};

/// Defines methods for converting the given T to/from a SNMP [`ObjectSyntax`].
pub trait SnmpConverter<T: Sized> {
    fn try_from_snmp(syntax: ObjectSyntax) -> Result<T, crate::Error>;
    fn try_to_snmp(value: T) -> Result<ObjectSyntax, crate::Error>;
}

/// Defines a new type
#[macro_export]
macro_rules! try_into_converter {
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
                fn try_from_snmp(syntax: ObjectSyntax) -> Result<$type, crate::Error> {
                    Ok(syntax.try_into()?)
                }

                fn try_to_snmp(value: $type) -> Result<ObjectSyntax, crate::Error> {
                    Ok(value.try_into()?)
                }
            }
        )+
    }
}

try_into_converter! {
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

struct FixedLengthOctetString<const Length: usize>();