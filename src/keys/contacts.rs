use serde::{Deserialize, Serialize};
use crate::error::Result;
use crate::keys::Key;
use crate::keys::key_gen::{ed25519_pk_to_x25519, ed25519_sk_to_x25519};
use crate::util::get_airoi_dir;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Contact {
    pub name: String,
    pub public_key: Key,
    pub address: String,
    pub added_at: String,
}


pub fn get_contacts() -> Result<Vec<Contact>> {
    let mut path = get_airoi_dir();
    path.push("contacts.json");
    if !path.exists() {
        return Ok(vec![]);
    }
    let contacts = serde_json::from_str::<Vec<Contact>>(
        &std::fs::read_to_string(&path)?
    )?;
    Ok(contacts)
}

pub fn store_contacts(contacts: Vec<Contact>) -> Result<()> {
    let mut path = get_airoi_dir();
    path.push("contacts.json");
    let json = serde_json::to_string_pretty(&contacts)?;
    std::fs::write(&path, json)?;
    Ok(())
}

pub fn add_contact(contact: Contact) -> Result<()> {
    let mut contacts = get_contacts()?;
    contacts.push(contact);
    store_contacts(contacts)?;
    Ok(())
}

pub fn remove_contact(name: &str) -> Result<()> {
    let mut contacts = get_contacts()?;
    let mut index = 0;
    for contact in contacts.iter() {
        if contact.name == name {
            contacts.remove(index);
            break;
        }
        index += 1;
    }
    store_contacts(contacts)?;
    Ok(())
}

impl Contact {
    pub fn new(name: String, raw_ed_public_key: Vec<u8>, address: &str) -> Contact {
        let raw_x_public_key = ed25519_pk_to_x25519(&raw_ed_public_key).to_vec();
        let public_key = Key::new(raw_ed_public_key, raw_x_public_key);
        Contact {
            name,
            public_key,
            address: address.to_string(),
            added_at: chrono::Utc::now().to_rfc3339(),
        }
    }
    pub fn public_key(&self) -> &Key {
        &self.public_key
    }
    pub fn address(&self) -> &str {
        &self.address
    }
    pub fn added_at(&self) -> &str {
        &self.added_at
    }
    pub fn fingerprint_ed(&self) -> &str {
        self.public_key.fingerprint_ed()
    }
    pub fn fingerprint_x(&self) -> &str {
        self.public_key.fingerprint_x()
    }
}