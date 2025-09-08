use std::path::PathBuf;
use serde::{Deserialize, Serialize};
use crate::error::Result;
use crate::keys::key_gen::get_fingerprint;
use crate::util::get_airoi_dir;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Contact {
    pub name: String,
    pub public_key: String,
    pub finger_print: String,
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
    pub fn finger_print(&self) -> &str {
        &self.finger_print
    }
}