use crate::{managers::status_provider::StatusProvider, status_list::StatusList};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Issuer {
    pub status_lists: HashMap<String, StatusList>,
}

impl Default for Issuer {
    fn default() -> Self {
        Self::new()
    }
}

impl Issuer {
    pub fn new() -> Self {
        Self {
            status_lists: HashMap::new(),
        }
    }

    pub fn add_status_list(&mut self, key: String, status_list: StatusList) {
        self.status_lists.insert(key, status_list);
    }

    pub fn get_status_list(&self, key: &str) -> Option<&StatusList> {
        self.status_lists.get(key)
    }

    pub fn remove_status_list(&mut self, key: &str) -> Option<StatusList> {
        self.status_lists.remove(key)
    }

    pub fn create_status_provider() -> StatusProvider {
        todo!()
    }
}
