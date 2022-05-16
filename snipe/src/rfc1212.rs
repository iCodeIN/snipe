//! An implementation of parts of RFC 1212 that aren't already catered for by [`rasn`] (mainly OID index construction).
//! This module is included by [`crate::prelude`].

// 4.1.6.  Mapping of the INDEX clause
//
//    To define the instance identification information, determine which
//    object value(s) will unambiguously distinguish a conceptual row.  The
//    syntax of those objects indicate how to form the instance-identifier:
//
//           (1)  integer-valued: a single sub-identifier taking the
//                integer value (this works only for non-negative
//                integers);
//
//           (2)  string-valued, fixed-length strings: `n' sub-identifiers,
//                where `n' is the length of the string (each octet of the
//                string is encoded in a separate sub-identifier);
//
//           (3)  string-valued, variable-length strings: `n+1' sub-
//                identifiers, where `n' is the length of the string (the
//                first sub-identifier is `n' itself, following this, each
//                octet of the string is encoded in a separate sub-
//                identifier);
//
//           (4)  object identifier-valued: `n+1' sub-identifiers, where
//                `n' is the number of sub-identifiers in the value (the
//                first sub-identifier is `n' itself, following this, each
//                sub-identifier in the value is copied);
//
//           (5)  NetworkAddress-valued: `n+1' sub-identifiers, where `n'
//                depends on the kind of address being encoded (the first
//                sub-identifier indicates the kind of address, value 1
//                indicates an IpAddress); or,
//
//           (6)  IpAddress-valued: 4 sub-identifiers, in the familiar
//                a.b.c.d notation.

use rasn::types::{ObjectIdentifier, OctetString};
use rasn_smi::v1::{IpAddress, NetworkAddress};

use crate::prelude::*;

macro_rules! integral_oid_conversion {
    ($($type:ty),+) => {
        $(
            impl OidConverter<$type> for DefaultConverter {
                fn try_from_oid(
                    identifier: &[u32],
                ) -> Result<OidConversionResult<$type>, crate::Error> {
                    if identifier.is_empty() {
                        Err(crate::Error::InsufficientLength(1))
                    } else {
                        Ok(OidConversionResult {
                            num_consumed: 1,
                            converted: identifier[0].try_into()?,
                        })
                    }
                }

                fn try_to_oid(value: $type) -> Result<rasn::types::ObjectIdentifier, crate::Error> {
                    Ok(ObjectIdentifier::new_unchecked(vec![value.try_into()?].into()))
                }
            }
        )+
    };
}

integral_oid_conversion! {
    u8, u16, u32, u64, u128
}

impl<const N: usize> OidConverter<FixedLengthOctetString<N>> for DefaultConverter {
    fn try_from_oid(
        identifier: &[u32],
    ) -> Result<OidConversionResult<FixedLengthOctetString<N>>, crate::Error> {
        if identifier.len() != N {
            Err(crate::Error::InsufficientLength(N))
        } else {
            let mut ret = [0_u8; N];
            for (i, v) in ret.iter_mut().enumerate() {
                *v = identifier[i].try_into()?;
            }

            Ok(OidConversionResult {
                num_consumed: N,
                converted: FixedLengthOctetString(ret),
            })
        }
    }

    fn try_to_oid(value: FixedLengthOctetString<N>) -> Result<ObjectIdentifier, crate::Error> {
        Ok(ObjectIdentifier::new_unchecked(
            value
                .0
                .into_iter()
                .map(|x| x as u32)
                .collect::<Vec<_>>()
                .into(),
        ))
    }
}

impl OidConverter<String> for DefaultConverter {
    fn try_from_oid(identifier: &[u32]) -> Result<OidConversionResult<String>, crate::Error> {
        if identifier.is_empty() {
            Err(crate::Error::InsufficientLength(1))
        } else {
            let end_idx = (identifier[0] + 1) as usize;
            if identifier.len() < end_idx {
                Err(crate::Error::InsufficientLength(end_idx))
            } else {
                let mut ret = Vec::with_capacity(end_idx - 1);
                for (i, v) in ret.iter_mut().enumerate() {
                    *v = identifier[i + 1].try_into()?;
                }

                Ok(OidConversionResult {
                    num_consumed: end_idx,
                    converted: String::from_utf8(ret)?,
                })
            }
        }
    }

    fn try_to_oid(value: String) -> Result<ObjectIdentifier, crate::Error> {
        Ok(ObjectIdentifier::new_unchecked(
            value
                .as_bytes()
                .iter()
                .copied()
                .map(|x| x as u32)
                .collect::<Vec<_>>()
                .into(),
        ))
    }
}

impl OidConverter<OctetString> for DefaultConverter {
    fn try_from_oid(identifier: &[u32]) -> Result<OidConversionResult<OctetString>, crate::Error> {
        if identifier.is_empty() {
            Err(crate::Error::InsufficientLength(1))
        } else {
            let end_idx = (identifier[0] + 1) as usize;
            if identifier.len() < end_idx {
                Err(crate::Error::InsufficientLength(end_idx))
            } else {
                let mut ret = Vec::with_capacity(end_idx - 1);
                for (i, v) in ret.iter_mut().enumerate() {
                    *v = identifier[i + 1].try_into()?;
                }

                Ok(OidConversionResult {
                    num_consumed: end_idx,
                    converted: OctetString::copy_from_slice(&ret[..]),
                })
            }
        }
    }

    fn try_to_oid(value: OctetString) -> Result<ObjectIdentifier, crate::Error> {
        Ok(ObjectIdentifier::new_unchecked(
            value
                .iter()
                .copied()
                .map(|x| x as u32)
                .collect::<Vec<_>>()
                .into(),
        ))
    }
}

impl OidConverter<ObjectIdentifier> for DefaultConverter {
    fn try_from_oid(
        identifier: &[u32],
    ) -> Result<OidConversionResult<ObjectIdentifier>, crate::Error> {
        if identifier.is_empty() {
            Err(crate::Error::InsufficientLength(1))
        } else {
            let end_idx = (identifier[0] + 1) as usize;
            if identifier.len() < end_idx {
                Err(crate::Error::InsufficientLength(end_idx))
            } else {
                Ok(OidConversionResult {
                    num_consumed: end_idx,
                    converted: ObjectIdentifier::new_unchecked(
                        identifier[1..end_idx].to_owned().into(),
                    ),
                })
            }
        }
    }

    fn try_to_oid(value: ObjectIdentifier) -> Result<ObjectIdentifier, crate::Error> {
        Ok(ObjectIdentifier::new_unchecked(
            std::iter::once(value.len().try_into()?)
                .chain(value.iter().copied())
                .collect::<Vec<_>>()
                .into(),
        ))
    }
}

impl OidConverter<NetworkAddress> for DefaultConverter {
    fn try_from_oid(
        identifier: &[u32],
    ) -> Result<OidConversionResult<NetworkAddress>, crate::Error> {
        if identifier.is_empty() {
            Err(crate::Error::InsufficientLength(1))
        } else {
            match identifier[0] {
                1 => {
                    if identifier.len() < 5 {
                        Err(crate::Error::InsufficientLength(5))
                    } else {
                        Ok(OidConversionResult {
                            num_consumed: 5,
                            converted: NetworkAddress::Internet(
                                Self::try_from_oid(&identifier[1..])?.converted,
                            ),
                        })
                    }
                }
                x => Err(crate::Error::UnsupportedNetworkAddress(x)),
            }
        }
    }

    fn try_to_oid(value: NetworkAddress) -> Result<ObjectIdentifier, crate::Error> {
        match value {
            NetworkAddress::Internet(ip) => Ok(ObjectIdentifier::new_unchecked(
                std::iter::once(1_u32)
                    .chain(Self::try_to_oid(ip)?.iter().copied())
                    .collect::<Vec<_>>()
                    .into(),
            )),
        }
    }
}

impl OidConverter<IpAddress> for DefaultConverter {
    fn try_from_oid(identifier: &[u32]) -> Result<OidConversionResult<IpAddress>, crate::Error> {
        if identifier.len() < 4 {
            Err(crate::Error::InsufficientLength(4))
        } else {
            let mut ret = [0_u8; 4];
            for (i, v) in ret.iter_mut().enumerate() {
                *v = identifier[i].try_into()?;
            }

            Ok(OidConversionResult {
                num_consumed: 4,
                converted: IpAddress(OctetString::copy_from_slice(&ret[..4])),
            })
        }
    }

    fn try_to_oid(value: IpAddress) -> Result<ObjectIdentifier, crate::Error> {
        Ok(ObjectIdentifier::new_unchecked(
            value
                .0
                .iter()
                .copied()
                .map(|x| x as u32)
                .collect::<Vec<_>>()
                .into(),
        ))
    }
}
