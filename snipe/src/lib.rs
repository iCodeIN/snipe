use std::ops::Deref;

pub use rasn::prelude::*;
pub use rasn as asn;
pub use rasn_snmp as snmp;

trait AsOid {
    fn as_oid(&self) -> ObjectIdentifier;
}

enum Error {

}

trait Mib {
    const OID: ObjectIdentifier;
}

trait ScalarMib: Mib {
    type Value: TryFrom<snmp::v2::ObjectSyntax, Error = Error> + TryInto<snmp::v2::ObjectSyntax, Error = Error>; 
}

trait ReadableMib: ScalarMib {
    fn get(&self) -> Self::Value;
}

trait WriteableMib: ScalarMib {
    fn set(&mut self, value: &Self::Value) -> Result<(), Error>;
}

trait IndexedScalarMib: ScalarMib {
    type Index: TryFrom<ObjectIdentifier, Error = Error> + TryInto<ObjectIdentifier, Error = Error>;
}

trait ReadableAtMib: IndexedScalarMib {
    fn get(&self, index: &Self::Index) -> Result<Self::Value, Error>;
}

trait WriteableAtMib: IndexedScalarMib {
    fn set(&self, index: &Self::Index, value: &Self::Value) -> Result<(), Error>;
}

/* ------------------------------------------------------------------------ */

struct IpAddress;
impl ScalarMib for IpAddress {
    type Value;
}

impl WriteableMib for IpAddress {
    fn set(&mut self, value: &Self::Value) -> Result<(), Error> {
        todo!()
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
